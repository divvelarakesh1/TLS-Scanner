import ssl
import socket
import shutil
import subprocess
import re
from typing import List, Optional, Dict, Any
from contextlib import contextmanager
from datetime import datetime, timezone
from OpenSSL import SSL, crypto
from .models import ScanTarget, ScannerConfig, Certificate,DelegatedCredential

class ConnectionContext:
    def __init__(self, target: ScanTarget, config: 'ScannerConfig'):
        self.target = target
        self.config = config
    def create_socket(self, timeout: Optional[float] = None) -> socket.socket:
        timeout = timeout or self.config.connection_timeout
        sock = socket.create_connection((self.target.hostname, self.target.port), timeout=timeout)
        return sock
    def create_ssl_context(self, **kwargs) -> ssl.SSLContext:
        ctx = ssl.SSLContext(kwargs.get("protocol", ssl.PROTOCOL_TLS_CLIENT))
        ctx.check_hostname = kwargs.get("check_hostname", False)
        ctx.verify_mode = kwargs.get("verify_mode", ssl.CERT_NONE if not self.config.verify_certificates else ssl.CERT_REQUIRED)
        
        if self.config.verify_certificates:
            ctx.load_default_certs()

        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION
        
        if kwargs.get("allow_old_tls", False):
            pass
        else:
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        ctx.set_ciphers(kwargs.get("ciphers", "ALL:@SECLEVEL=0"))

        if 'minimum_version' in kwargs:
            ctx.minimum_version = kwargs['minimum_version']
        if 'maximum_version' in kwargs:
            ctx.maximum_version = kwargs['maximum_version']
        return ctx

    def connect_tls(self, ssl_context: Optional[ssl.SSLContext] = None, timeout: Optional[float] = None) -> ssl.SSLSocket:
        timeout = timeout or self.config.connection_timeout
        sock = self.create_socket(timeout)
        ssl_context = ssl_context or self.create_ssl_context()
        try:
            ssl_sock = ssl_context.wrap_socket(sock, server_hostname=self.target.effective_sni)
            return ssl_sock
        except Exception:
            try:
                sock.close()
            except:
                pass
            raise

    @contextmanager
    def tls_connection(self, ssl_context: Optional[ssl.SSLContext] = None):
        """Context manager for TLS connections"""
        ssl_sock = None
        try:
            ssl_sock = self.connect_tls(ssl_context)
            yield ssl_sock
        finally:
            if ssl_sock:
                try:
                    ssl_sock.close()
                except:
                    pass

    def get_certificate_chain(self) -> List[Certificate]:
        chain: List[Certificate] = []
        try:
            ctx = self.create_ssl_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with self.tls_connection(ctx) as ssl_sock:
                der_cert = ssl_sock.getpeercert(binary_form=True)
                
                if der_cert:
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
                    parsed = self._parse_x509(x509)
                    if parsed:
                        chain.append(parsed)
                        
        except Exception as e:
            pass
            
        return chain

    def _parse_x509(self, x509: crypto.X509) -> Optional[Certificate]:
        try:
            def decode_comp(comp):
                return comp.decode('utf-8') if isinstance(comp, bytes) else str(comp)

            subject = {decode_comp(entry[0]): decode_comp(entry[1]) for entry in x509.get_subject().get_components()}
            issuer = {decode_comp(entry[0]): decode_comp(entry[1]) for entry in x509.get_issuer().get_components()}
            serial_number = hex(x509.get_serial_number())
            
            not_before_str = x509.get_notBefore().decode('utf-8')
            not_after_str = x509.get_notAfter().decode('utf-8')
            
            not_before = datetime.strptime(not_before_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(not_after_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)

            
            pub_key = x509.get_pubkey()
            key_size = pub_key.bits()
            
            pk_type = pub_key.type()
            if pk_type == crypto.TYPE_RSA:
                public_key_algorithm = "RSA"
            elif pk_type == crypto.TYPE_DSA:
                public_key_algorithm = "DSA"
            else:
                public_key_algorithm = "EC/Unknown"

            signature_algorithm = x509.get_signature_algorithm().decode('utf-8')
            fingerprint_sha256 = x509.digest("sha256").decode('utf-8')

            san = []
            ext_count = x509.get_extension_count()
            for i in range(ext_count):
                ext = x509.get_extension(i)
                if b"subjectAltName" in ext.get_short_name():
                    san_str = str(ext)
                    san = [x.strip().replace("DNS:", "") for x in san_str.split(",")]
            
            pem = crypto.dump_certificate(crypto.FILETYPE_PEM, x509).decode('utf-8')
            
            return Certificate(
                pem=pem,
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                san=san,
                fingerprint_sha256=fingerprint_sha256,
                public_key_algorithm=public_key_algorithm,
                signature_algorithm=signature_algorithm,
                key_size=key_size
            )
        except Exception:
            return None

    def test_cipher_suite(self, cipher: str, protocol: Optional[ssl.TLSVersion] = None) -> bool:
        try:
            ctx = self.create_ssl_context(ciphers=cipher, allow_old_tls=True)
            if protocol:
                ctx.minimum_version = protocol
                ctx.maximum_version = protocol
            ctx.options &= ~ssl.OP_NO_SSLv3
            ctx.options &= ~ssl.OP_NO_TLSv1
            ctx.options &= ~ssl.OP_NO_TLSv1_1
            with self.tls_connection(ctx) as ssl_sock:
                negotiated = ssl_sock.cipher()[0]
                if cipher in ["NULL", "aNULL"]:
                    if "NULL" not in negotiated:
                        return False
                elif cipher != "kRSA" and cipher not in negotiated:
                    return False 
                return True
        except Exception:
            return False
    def test_protocol_version(self, protocol: ssl.TLSVersion) -> bool:
        try:
            ctx = self.create_ssl_context(minimum_version=protocol, maximum_version=protocol, allow_old_tls=True)
            with self.tls_connection(ctx):
                return True
        except Exception:
            return False

    def get_negotiated_cipher(self) -> Optional[str]:
        """Get the cipher suite negotiated in a connection"""
        try:
            with self.tls_connection() as ssl_sock:
                return ssl_sock.cipher()[0]
        except Exception:
            return None

    def get_negotiated_protocol(self) -> Optional[str]:
        """Get the TLS protocol version negotiated"""
        try:
            with self.tls_connection() as ssl_sock:
                return ssl_sock.version()
        except Exception:
            return None

    def starttls_upgrade(self) -> socket.socket:
        if not self.target.starttls_protocol:
            raise ValueError("No STARTTLS protocol specified")
        
        sock = self.create_socket()
        protocol = self.target.starttls_protocol.lower()
        
        try:
            if protocol == "smtp":
                sock.recv(1024)
                sock.sendall(b"EHLO scanner.local\r\n")
                sock.recv(4096)
                sock.sendall(b"STARTTLS\r\n")
                response = sock.recv(4096)
                if not response.startswith(b"220"):
                    raise RuntimeError(f"STARTTLS failed: {response}")
            elif protocol == "imap":
                sock.recv(1024)
                sock.sendall(b"A001 STARTTLS\r\n")
                response = sock.recv(4096)
                if b"OK" not in response:
                    raise RuntimeError(f"STARTTLS failed: {response}")
            elif protocol == "ftp":
                sock.recv(1024)
                sock.sendall(b"AUTH TLS\r\n")
                response = sock.recv(4096)
                if not response.startswith(b"234"):
                    raise RuntimeError(f"AUTH TLS failed: {response}")
            else:
                raise ValueError(f"Unsupported STARTTLS protocol: {protocol}")
            
            return sock
        except Exception:
            try:
                sock.close()
            except:
                pass
            raise

    def get_delegated_credential(self) -> Optional[DelegatedCredential]:
        try:
            if not shutil.which("openssl"):
                return None
                
            cmd = [
                "openssl", "s_client",
                "-connect", f"{self.target.hostname}:{self.target.port}",
                "-tls1_3", 
                "-servername", self.target.effective_sni,
                "-delegated_credential", "1",
                "-msg",
                "-brief"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                input="Q\n"
            )
            
            output = result.stdout + result.stderr
            
            dc_info = self._parse_dc_from_openssl_output(output)
            if not dc_info or not dc_info.get("found", False):
                return None
                
            return DelegatedCredential(
                pem=dc_info.get("pem", ""),
                algorithm=dc_info.get("algorithm", "unknown"),
                not_before=dc_info.get("not_before", datetime.now()),
                not_after=dc_info.get("not_after", datetime.now()),
                public_key_algorithm=dc_info.get("public_key_algorithm", "unknown"),
                key_size=dc_info.get("key_size", 0),
                signature_algorithm=dc_info.get("signature_algorithm", "unknown")
            )
            
        except Exception:
            return None

    def _parse_dc_from_openssl_output(self, output: str) -> Optional[Dict[str, Any]]:
        
        if "delegated credential" not in output.lower():
            return {"found": False}
        
        dc_info = {"found": True}
        
        validity_match = re.search(r'Valid from:\s*(\w+\s+\d+\s+\d+:\d+:\d+\s+\d+\s+\w+)\s+until:\s*(\w+\s+\d+\s+\d+:\d+:\d+\s+\d+\s+\w+)', output)
        if validity_match:
            try:
                date_formats = [
                    "%b %d %H:%M:%S %Y %Z",
                    "%Y-%m-%d %H:%M:%S",
                ]
                
                not_before_str = validity_match.group(1).strip()
                not_after_str = validity_match.group(2).strip()
                
                not_before = None
                not_after = None
                
                for fmt in date_formats:
                    try:
                        not_before = datetime.strptime(not_before_str, fmt)
                        not_after = datetime.strptime(not_after_str, fmt)
                        break
                    except ValueError:
                        continue
                
                if not_before and not_after:
                    dc_info["not_before"] = not_before
                    dc_info["not_after"] = not_after
            except Exception:
                pass
        
        algo_match = re.search(r'signature algorithm:\s*([^\n,]+)', output, re.IGNORECASE)
        if algo_match:
            dc_info["signature_algorithm"] = algo_match.group(1).strip()
        
        key_match = re.search(r'Public Key Algorithm:\s*([^\n,]+)', output, re.IGNORECASE)
        if key_match:
            dc_info["public_key_algorithm"] = key_match.group(1).strip()
        
        size_match = re.search(r'(\d+)\s*bit', output)
        if size_match:
            dc_info["key_size"] = int(size_match.group(1))
        
        return dc_info

    def supports_delegated_credentials(self) -> bool:

        try:
            if not shutil.which("openssl"):
                return False
                
            cmd = [
                "openssl", "s_client",
                "-connect", f"{self.target.hostname}:{self.target.port}",
                "-tls1_3", 
                "-servername", self.target.effective_sni,
                "-delegated_credential", "1",
                "-brief" 
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                input="Q\n"
            )
            
            output = result.stdout + result.stderr
            
            dc_indicators = [
                "delegated credential",
                "dc=",
                "using delegated credential"
            ]
            
            return any(indicator in output.lower() for indicator in dc_indicators)
            
        except Exception:
            return False

    def test_dc_with_openssl(self) -> Optional[Dict[str, Any]]:
        try:
            if not shutil.which("openssl"):
                return None
            
            cmd = [
                "openssl", "s_client",
                "-connect", f"{self.target.hostname}:{self.target.port}",
                "-tls1_3", 
                "-servername", self.target.effective_sni,
                "-delegated_credential", "1",
                "-msg"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                input="Q\n"
            )
            
            output = result.stdout + result.stderr
            return self._parse_comprehensive_dc_info(output)
            
        except Exception:
            return None

    def _parse_comprehensive_dc_info(self, output: str) -> Dict[str, Any]:
        dc_info = {
            "supported": False,
            "validity_parsed": False,
            "algorithm_parsed": False,
            "signature_algorithm": "unknown"
        }
        
        if "delegated credential" in output.lower() or "dc=" in output.lower():
            dc_info["supported"] = True
        
        if not dc_info["supported"]:
            return dc_info

        date_patterns = [
            r'not before:\s*([^\n]+)\n\s*not after:\s*([^\n]+)',
            r'valid from:\s*([^\n]+)\s+until:\s*([^\n]+)',
        ]

        found_dates = []
        for pattern in date_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for m in matches:
                nb, na = self._parse_dc_dates(m[0], m[1])
                if nb and na:
                    found_dates.append((nb, na))

        if found_dates:
            best_pair = min(found_dates, key=lambda p: (p[1] - p[0]).total_seconds())
            
            dc_info["not_before"] = best_pair[0]
            dc_info["not_after"] = best_pair[1]
            dc_info["validity_parsed"] = True
            
            dc_info["lifetime_hours"] = (best_pair[1] - best_pair[0]).total_seconds() / 3600
            now = datetime.now()
            dc_info["is_expired"] = now > best_pair[1]
            dc_info["is_not_yet_valid"] = now < best_pair[0]

        algo_matches = re.findall(r'signature algorithm:\s*([^\n,]+)', output, re.IGNORECASE)
        if algo_matches:
            dc_info["signature_algorithm"] = algo_matches[-1].strip()
            dc_info["algorithm_parsed"] = True

        return dc_info

    def _parse_dc_dates(self, not_before_str: str, not_after_str: str) -> tuple:
        date_formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%Y-%m-%d %H:%M:%S", 
            "%d-%b-%Y %H:%M:%S", 
            "%b %d %Y %H:%M:%S", 
        ]
        for fmt in date_formats:
            try:
                nb = datetime.strptime(not_before_str.strip(), fmt)
                na = datetime.strptime(not_after_str.strip(), fmt)
                return nb, na
            except ValueError:
                continue
        return None, None

