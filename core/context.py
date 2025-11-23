import ssl
import socket
import shutil
import subprocess
import re
from typing import List, Optional, Dict, Any
from contextlib import contextmanager
from datetime import datetime, timezone
from OpenSSL import SSL, crypto
from .models import ScanTarget, ScannerConfig, Certificate

class ConnectionContext:
    def __init__(self, target: ScanTarget, config: ScannerConfig):
        self.target = target
        self.config = config

    def create_socket(self, timeout: Optional[float] = None) -> socket.socket:
        timeout = timeout or self.config.connection_timeout
        return socket.create_connection((self.target.hostname, self.target.port), timeout=timeout)

    def create_ssl_context(self, **kwargs) -> ssl.SSLContext:
        ctx = ssl.SSLContext(kwargs.get("protocol", ssl.PROTOCOL_TLS_CLIENT))
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= ssl.OP_NO_COMPRESSION
        
        if not kwargs.get("allow_old_tls", False):
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        if "ciphers" in kwargs:
            try:
                ctx.set_ciphers(kwargs["ciphers"])
            except ssl.SSLError:
                raise
        else:
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                ctx.set_ciphers("ALL")

        if 'minimum_version' in kwargs:
            ctx.minimum_version = kwargs['minimum_version']
        if 'maximum_version' in kwargs:
            ctx.maximum_version = kwargs['maximum_version']
        return ctx

    def connect_tls(self, ssl_context: Optional[ssl.SSLContext] = None) -> ssl.SSLSocket:
        sock = self.create_socket()
        ssl_context = ssl_context or self.create_ssl_context()
        try:
            return ssl_context.wrap_socket(sock, server_hostname=self.target.effective_sni)
        except Exception:
            sock.close()
            raise

    @contextmanager
    def tls_connection(self, ssl_context: Optional[ssl.SSLContext] = None):
        ssl_sock = None
        try:
            ssl_sock = self.connect_tls(ssl_context)
            yield ssl_sock
        finally:
            if ssl_sock:
                ssl_sock.close()

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
        except Exception:
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
            public_key_algorithm = "RSA" if pk_type == crypto.TYPE_RSA else "DSA" if pk_type == crypto.TYPE_DSA else "EC/Unknown"

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
            return Certificate(pem, subject, issuer, serial_number, not_before, not_after, san, fingerprint_sha256, public_key_algorithm, signature_algorithm, key_size)
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
                    if "NULL" not in negotiated: return False
                elif cipher != "kRSA" and cipher not in negotiated:
                    return False
                return True
        except Exception:
            return False

    def test_protocol_version(self, protocol: ssl.TLSVersion) -> bool:
        try:
            ctx = self.create_ssl_context(minimum_version=protocol, maximum_version=protocol, allow_old_tls=True)
            with self.tls_connection(ctx) as ssl_sock:
                ver = ssl_sock.version()
                if protocol == ssl.TLSVersion.TLSv1 and ver != "TLSv1": return False
                if protocol == ssl.TLSVersion.TLSv1_1 and ver != "TLSv1.1": return False
                if protocol == ssl.TLSVersion.SSLv3 and ver != "SSLv3": return False
                return True
        except Exception:
            return False

    def supports_delegated_credentials(self) -> bool:
        try:
            if not shutil.which("openssl"): return False
            cmd = ["openssl", "s_client", "-connect", f"{self.target.hostname}:{self.target.port}", "-tls1_3", "-servername", self.target.effective_sni, "-delegated_credential", "1", "-brief"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, input="Q\n")
            output = result.stdout + result.stderr
            return any(x in output.lower() for x in ["delegated credential", "dc=", "using delegated credential"])
        except Exception:
            return False

    def test_dc_with_openssl(self) -> Optional[Dict[str, Any]]:
        try:
            if not shutil.which("openssl"): return None
            cmd = ["openssl", "s_client", "-connect", f"{self.target.hostname}:{self.target.port}", "-tls1_3", "-servername", self.target.effective_sni, "-delegated_credential", "1", "-msg"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, input="Q\n")
            output = result.stdout + result.stderr
            
            # Simplified parsing for the modular code
            info = {"supported": "delegated credential" in output.lower()}
            if info["supported"]:
                # Basic expiry checks if found
                import re
                date_match = re.search(r'not after:\s*([^\n]+)', output, re.IGNORECASE)
                if date_match:
                    # Basic indicator that we found logic
                    info["validity_parsed"] = True 
            return info
        except Exception:
            return None