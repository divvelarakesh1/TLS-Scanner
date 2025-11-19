import ssl
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime, timedelta
from contextlib import contextmanager
import traceback
from OpenSSL import SSL, crypto


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    check_name: str
    severity: Severity
    title: str
    description: str
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class ScanTarget:
    hostname: str
    port: int = 443
    sni_hostname: Optional[str] = None
    starttls_protocol: Optional[str] = None

    @property
    def effective_sni(self) -> str:
        return self.sni_hostname or self.hostname

@dataclass
class Certificate:
    pem: str
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: str
    not_before: datetime
    not_after: datetime
    san: List[str]
    fingerprint_sha256: str
    public_key_algorithm: str
    signature_algorithm: str
    key_size: int

    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.not_after

    @property
    def is_not_yet_valid(self) -> bool:
        return datetime.now() < self.not_before

    @property
    def days_until_expiry(self) -> int:
        delta = self.not_after - datetime.now()
        return delta.days

class ConnectionContext:
    def __init__(self, target: ScanTarget, config: 'ScannerConfig'):
        self.target = target
        self.config = config

    # -----------------------
    # Socket creation
    # -----------------------
    def create_socket(self, timeout: Optional[float] = None) -> socket.socket:
        timeout = timeout or self.config.connection_timeout
        sock = socket.create_connection((self.target.hostname, self.target.port), timeout=timeout)
        return sock

    # -----------------------
    # SSL Context with strong defaults
    # -----------------------
    def create_ssl_context(self, **kwargs) -> ssl.SSLContext:
        ctx = ssl.SSLContext(kwargs.get("protocol", ssl.PROTOCOL_TLS_CLIENT))
        ctx.check_hostname = kwargs.get("check_hostname", False)
        ctx.verify_mode = kwargs.get("verify_mode", ssl.CERT_NONE if not self.config.verify_certificates else ssl.CERT_REQUIRED)
        
        if self.config.verify_certificates:
            ctx.load_default_certs()

        # Strong defaults
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION
        
        # Allow setting specific options
        if kwargs.get("allow_old_tls", False):
            pass  # Don't disable old TLS for testing
        else:
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        ctx.set_ciphers(kwargs.get("ciphers", "ALL:@SECLEVEL=0"))

        if 'minimum_version' in kwargs:
            ctx.minimum_version = kwargs['minimum_version']
        if 'maximum_version' in kwargs:
            ctx.maximum_version = kwargs['maximum_version']
        return ctx

    # -----------------------
    # TLS handshake
    # -----------------------
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
            # Use the robust create_ssl_context method we already wrote
            # We MUST enable verification or at least basic fetching to get the cert
            ctx = self.create_ssl_context()
            
            # We deliberately disable verification here to allow fetching 
            # expired/self-signed certs for analysis
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with self.tls_connection(ctx) as ssl_sock:
                # Get the raw binary certificate (DER format)
                # This works even if the cert is expired/bad
                der_cert = ssl_sock.getpeercert(binary_form=True)
                
                if der_cert:
                    # Load into pyOpenSSL to reuse your existing parsing logic
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
                    parsed = self._parse_x509(x509)
                    if parsed:
                        chain.append(parsed)
                        
        except Exception as e:
            # print(f"Debug: Cert fetch failed: {e}") # Uncomment to debug
            pass
            
        return chain

    # -----------------------
    # Parse OpenSSL X509 to Certificate
    # -----------------------
    def _parse_x509(self, x509: crypto.X509) -> Optional[Certificate]:
        try:
            # Helper to decode bytes or strings safely
            def decode_comp(comp):
                return comp.decode('utf-8') if isinstance(comp, bytes) else str(comp)

            subject = {decode_comp(entry[0]): decode_comp(entry[1]) for entry in x509.get_subject().get_components()}
            issuer = {decode_comp(entry[0]): decode_comp(entry[1]) for entry in x509.get_issuer().get_components()}
            serial_number = hex(x509.get_serial_number())
            
            # Parse dates properly (OpenSSL returns bytes like b'20251027083351Z')
            not_before_str = x509.get_notBefore().decode('utf-8')
            not_after_str = x509.get_notAfter().decode('utf-8')
            
            not_before = datetime.strptime(not_before_str, "%Y%m%d%H%M%SZ")
            not_after = datetime.strptime(not_after_str, "%Y%m%d%H%M%SZ")
            
            pub_key = x509.get_pubkey()
            key_size = pub_key.bits()
            
            # Determine Public Key Algorithm
            pk_type = pub_key.type()
            if pk_type == crypto.TYPE_RSA:
                public_key_algorithm = "RSA"
            elif pk_type == crypto.TYPE_DSA:
                public_key_algorithm = "DSA"
            else:
                # Fallback or EC check might differ based on pyOpenSSL version
                public_key_algorithm = "EC/Unknown"

            signature_algorithm = x509.get_signature_algorithm().decode('utf-8')
            fingerprint_sha256 = x509.digest("sha256").decode('utf-8')

            # Parse SANs
            san = []
            ext_count = x509.get_extension_count()
            for i in range(ext_count):
                ext = x509.get_extension(i)
                if b"subjectAltName" in ext.get_short_name():
                    san_str = str(ext)
                    # Clean up the SAN string (e.g., "DNS:example.com, DNS:www.example.com")
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

    # -----------------------
    # Test cipher suite
    # -----------------------
    def test_cipher_suite(self, cipher: str, protocol: Optional[ssl.TLSVersion] = None) -> bool:
        try:
            ctx = self.create_ssl_context(ciphers=cipher, allow_old_tls=True)
            if protocol:
                ctx.minimum_version = protocol
                ctx.maximum_version = protocol
            # Explicitly allow old protocols
            ctx.options &= ~ssl.OP_NO_SSLv3
            ctx.options &= ~ssl.OP_NO_TLSv1
            ctx.options &= ~ssl.OP_NO_TLSv1_1
            # CHANGE: Capture the socket as 'ssl_sock'
            with self.tls_connection(ctx) as ssl_sock:
                # Ask: "What cipher are we ACTUALLY using?"
                negotiated = ssl_sock.cipher()[0]
                # If we asked for NULL/aNULL, verify we got it
                if cipher in ["NULL", "aNULL"]:
                    if "NULL" not in negotiated:
                        return False # OS upgraded us to strong encryption            
                # If we asked for a specific string (e.g. "RC4"), verify it's in the name
                # Exception: "kRSA" is a mechanism, not a name, so we skip name check for it
                elif cipher != "kRSA" and cipher not in negotiated:
                    return False # OS upgraded us to AES/Chacha
                
                return True
        except Exception:
            return False

    # -----------------------
    # Test protocol version
    # -----------------------
    def test_protocol_version(self, protocol: ssl.TLSVersion) -> bool:
        try:
            ctx = self.create_ssl_context(minimum_version=protocol, maximum_version=protocol, allow_old_tls=True)
            with self.tls_connection(ctx):
                return True
        except Exception:
            return False

    # -----------------------
    # Get negotiated cipher
    # -----------------------
    def get_negotiated_cipher(self) -> Optional[str]:
        """Get the cipher suite negotiated in a connection"""
        try:
            with self.tls_connection() as ssl_sock:
                return ssl_sock.cipher()[0]
        except Exception:
            return None

    # -----------------------
    # Get negotiated protocol
    # -----------------------
    def get_negotiated_protocol(self) -> Optional[str]:
        """Get the TLS protocol version negotiated"""
        try:
            with self.tls_connection() as ssl_sock:
                return ssl_sock.version()
        except Exception:
            return None

    # -----------------------
    # STARTTLS support
    # -----------------------
    def starttls_upgrade(self) -> socket.socket:
        if not self.target.starttls_protocol:
            raise ValueError("No STARTTLS protocol specified")
        
        sock = self.create_socket()
        protocol = self.target.starttls_protocol.lower()
        
        try:
            if protocol == "smtp":
                sock.recv(1024)  # Read banner
                sock.sendall(b"EHLO scanner.local\r\n")
                sock.recv(4096)
                sock.sendall(b"STARTTLS\r\n")
                response = sock.recv(4096)
                if not response.startswith(b"220"):
                    raise RuntimeError(f"STARTTLS failed: {response}")
            elif protocol == "imap":
                sock.recv(1024)  # Read banner
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


# ---------------------------
# Scanner Config
# ---------------------------
@dataclass
class ScannerConfig:
    connection_timeout: float = 10.0
    handshake_timeout: float = 10.0
    stop_on_error: bool = False
    enabled_checks: Optional[List[str]] = None
    disabled_checks: List[str] = field(default_factory=list)
    max_retries: int = 0
    retry_delay: float = 1.0
    verify_certificates: bool = False  # False for scanning


# ---------------------------
# Base Check
# ---------------------------
class BaseCheck(ABC):
    def __init__(self):
        self.name = self.__class__.__name__
        self.description = self.__doc__ or "No description provided"

    @abstractmethod
    def run(self, context: ConnectionContext) -> List[Finding]:
        pass

    @property
    def check_id(self) -> str:
        return self.name.lower().replace(" ", "_")

    def create_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        remediation: Optional[str] = None,
        **metadata
    ) -> Finding:
        """Helper to create a finding with this check's name"""
        return Finding(
            check_name=self.name,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            metadata=metadata
        )


# ---------------------------
# Check Registry
# ---------------------------
class CheckRegistry:
    def __init__(self):
        self._checks: Dict[str, BaseCheck] = {}

    def register(self, check: BaseCheck):
        self._checks[check.check_id] = check

    def get_enabled_checks(self, config: ScannerConfig) -> List[BaseCheck]:
        all_checks = list(self._checks.values())
        if config.enabled_checks:
            all_checks = [c for c in all_checks if c.check_id in config.enabled_checks]
        all_checks = [c for c in all_checks if c.check_id not in config.disabled_checks]
        return all_checks


# ---------------------------
# Scan Result
# ---------------------------
@dataclass
class ScanResult:
    target: ScanTarget
    findings: List[Finding]
    start_time: datetime
    end_time: datetime
    total_checks: int
    successful_checks: int
    failed_checks: int
    errors: List[Dict[str, str]] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def has_critical_findings(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)


# ---------------------------
# TLS Scanner Core (Sequential)
# ---------------------------
class TLSScannerCore:
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()
        self.registry = CheckRegistry()

    def register_check(self, check: BaseCheck):
        self.registry.register(check)

    def _run_single_check(self, check: BaseCheck, context: ConnectionContext) -> tuple:
        try:
            findings = check.run(context)
            return (check.check_id, findings, None)
        except Exception as e:
            return (check.check_id, [], {
                "check_id": check.check_id,
                "error": str(e),
                "traceback": traceback.format_exc()
            })

    def scan(self, target: ScanTarget) -> ScanResult:
        start_time = datetime.now()
        all_findings = []
        errors = []
        checks = self.registry.get_enabled_checks(self.config)
        context = ConnectionContext(target, self.config)

        for check in checks:
            check_id, findings, error = self._run_single_check(check, context)
            if error:
                errors.append(error)
                if self.config.stop_on_error:
                    break
            else:
                all_findings.extend(findings)

        end_time = datetime.now()
        return ScanResult(
            target=target,
            findings=all_findings,
            start_time=start_time,
            end_time=end_time,
            total_checks=len(checks),
            successful_checks=len(checks) - len(errors),
            failed_checks=len(errors),
            errors=errors
        )


# ============================================
# CHECKS IMPLEMENTATION
# ============================================

class CipherConfigurationCheck(BaseCheck):
    """
    Checks for weak or misconfigured cipher suites, including:
    - Legacy Ciphers (RC4, 3DES, NULL)
    - Forward Secrecy support (Static RSA detection)
    - Anonymous authentication (Man-in-the-Middle risk)
    """  
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        weak_targets = [
            # --- CRITICAL (No Encryption / No Auth) ---
            ("NULL", "NULL", Severity.CRITICAL),      # No encryption
            ("ADH", "ADH", Severity.CRITICAL),        # Anonymous DH (No Authentication)
            ("AECDH", "AECDH", Severity.CRITICAL),    # Anonymous ECDH (No Authentication)
            ("EXPORT", "EXP", Severity.CRITICAL),     # Export-grade (40-bit keys, trivially breakable)
            # --- HIGH (Broken / Obsolete) ---
            ("RC4", "RC4", Severity.HIGH),            # Biased stream cipher (broken)
            ("RC2", "RC2", Severity.HIGH),            # Ancient block cipher
            ("DES", "DES", Severity.HIGH),            # Single DES (56-bit, broken)
            # --- MEDIUM (Weak / Deprecated) ---
            ("3DES", "3DES", Severity.MEDIUM),        # Triple-DES (Sweet32 vulnerability, slow)
            ("SEED", "SEED", Severity.MEDIUM),        # Old Korean cipher (deprecated)
            ("IDEA", "IDEA", Severity.MEDIUM),        # Old cipher (deprecated)
            ("CAMELLIA", "CAMELLIA", Severity.MEDIUM),# Not strictly broken, but rare/non-standard now
        ]
        for name, cipher_str, severity in weak_targets:
            if context.test_cipher_suite(cipher_str):
                 findings.append(self.create_finding(
                    severity=severity,
                    title=f"Weak Cipher Supported: {name}",
                    description=f"The server supports the obsolete {name} cipher suite.",
                    remediation=f"Disable {name} in the server configuration.",
                    metadata={"cipher_string": cipher_str}
                ))
        # 2. Static RSA (No Forward Secrecy)
        # "kRSA" in OpenSSL selects cipher suites using Static RSA Key Exchange
        if context.test_cipher_suite("kRSA"):
             findings.append(self.create_finding(
                severity=Severity.MEDIUM,
                title="No Forward Secrecy (Static RSA)",
                description="The server supports Static RSA key exchange. If the private key is stolen, past traffic can be decrypted.",
                remediation="Prioritize ECDHE or DHE cipher suites.",
                metadata={"cipher_string": "kRSA"}
            ))
        # 3. Anonymous Ciphers (aNULL)
        # Encryption without authentication
        if context.test_cipher_suite("aNULL"):
             findings.append(self.create_finding(
                severity=Severity.CRITICAL,
                title="Anonymous Cipher Suites Supported",
                description="The server supports cipher suites with no authentication (aNULL).",
                remediation="Disable anonymous cipher suites immediately.",
                metadata={"cipher_string": "aNULL"}
            ))
        return findings

class DeepCertificateAnalysisCheck(BaseCheck):
    """
    Checks for various certificate issues, including:
    - Expired or Not Yet Valid Certificates
    - Hostname Mismatches (CN and SAN)
    - Self-Signed Certificates
    - Weak Signature Algorithms (MD5, SHA1)
    - Weak Key Strength (RSA < 2048 bits, weak EC curves)
    """
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []

        # ----------------------------------------
        # Fetch certificate chain
        # ----------------------------------------
        chain = context.get_certificate_chain()
        if not chain:
            return findings
        
        # Leaf Certificate on the chain
        cert = chain[0]
        # Check 1: Certificate Status
        if cert.is_expired:
            findings.append(
                self.create_finding(
                    severity=Severity.CRITICAL,
                    title="Certificate Expired",
                    description=f"The certificate expired on {cert.not_after}.",
                    remediation="Renew/Reissue the certificate immediately.",
                )
            )

        if cert.is_not_yet_valid:
            findings.append(
                self.create_finding(
                    severity=Severity.HIGH,
                    title="Certificate is Not Yet Valid",
                    description=f"The certificate is not valid until {cert.not_before}.",
                    remediation="Fix system clock or certificate issue",
                )
            )

        if cert.days_until_expiry < 30 and not cert.is_expired:
            findings.append(
                self.create_finding(
                    severity=Severity.MEDIUM,
                    title="Certificate is Expiring Soon",
                    description=f"The certificate will expire in {cert.days_until_expiry} days.",
                    remediation="Renew/Reissue the certificate soon.",
                )
            )

        # Check 2: Hostname Validation
        hostname = context.target.effective_sni
        sanList = cert.san
        cn = cert.subject.get("CN", "")
        
        isSanMatch = hostname in sanList
        isCnMatch = (cn == hostname)

        if not sanList:
            findings.append(
                self.create_finding(
                    severity=Severity.HIGH,
                    title="Missing SAN Extension",
                    description="The certificate does not include Subject Alternative Names (SAN).",
                    remediation="Always include SAN in certificates.",
                    metadata={"cn": cn},
                )
            )

        if not isSanMatch and not isCnMatch:
            findings.append(
                self.create_finding(
                    severity=Severity.HIGH,
                    title="Hostname Mismatch",
                    description=f"Hostname {hostname} does not match CN={cn} or SAN={sanList}.",
                    remediation="Issue a certificate with correct SAN entries.",
                    metadata={"cn": cn, "san": sanList},
                )
            )

        # Check 3: Trust Chain / Self-signed Detection
        if cert.subject == cert.issuer:
            findings.append(
                self.create_finding(
                    severity=Severity.MEDIUM,
                    title="Self-Signed Certificate",
                    description="The certificate is self-signed, not issued by a trusted CA.",
                    remediation="Use a CA-issued certificate for public use.",
                )
            )

        # Check 4: Weak Signature Algorithm
        algo = cert.signature_algorithm.lower()
        
        if "md5" in algo or "md2" in algo:
            findings.append(
                self.create_finding(
                    severity=Severity.CRITICAL,
                    title="MD5 Hashing Algorithm Detected",
                    description=f"The certificate uses broken hashing: {cert.signature_algorithm}",
                    remediation="Use SHA256 or stronger Hashing",
                )
            )
        elif "sha1" in algo:
            findings.append(
                self.create_finding(
                    severity=Severity.HIGH,
                    title="SHA1 Hashing Algorithm Detected",
                    description=f"The certificate uses deprecated hashing: {cert.signature_algorithm}",
                    remediation="Use SHA256 or stronger Hashing",
                )
            )

        # Check 5: Weak Key Strength
        if cert.public_key_algorithm == "RSA":
            if cert.key_size < 1024:
                findings.append(
                    self.create_finding(
                        severity=Severity.CRITICAL,
                        title="Weak RSA Key (<=1024 bits)",
                        description=f"The RSA key size is only {cert.key_size} bits.",
                        remediation="Use RSA 2048 bits or stronger.",
                    )
                )
            elif cert.key_size < 2048:
                findings.append(
                    self.create_finding(
                        severity=Severity.HIGH,
                        title="Weak RSA Key (<2048 bits)",
                        description=f"The RSA key size is only {cert.key_size} bits.",
                        remediation="Use RSA 2048 bits or stronger.",
                    )
                )
        elif cert.public_key_algorithm.startswith("EC"):
            if cert.key_size < 256:
                findings.append(
                    self.create_finding(
                        severity=Severity.HIGH,
                        title="Weak EC Key",
                        description=f"EC key size {cert.key_size} bits indicates a weak curve.",
                        remediation="Use at least P-256 or stronger elliptic curves.",
                    )
                )

        return findings


class ProtocolSupportCheck(BaseCheck):
    """
    Checks for protocol version support, including:
    - Legacy Protocols (SSLv3, TLS 1.0, TLS 1.1)
    - Fallback SCSV (TLS_FALLBACK_SCSV) detection
    """

    OPENSSL_TIMEOUT = 20

    def __init__(self):
        super().__init__()
        self._protocols = []
        self._protocols.append(("SSLv3", None, "-ssl3"))

        if hasattr(ssl, "TLSVersion"):
            TLS = ssl.TLSVersion
            self._protocols.extend(
                [
                    ("TLSv1", getattr(TLS, "TLSv1", None), "-tls1"),
                    ("TLSv1.1", getattr(TLS, "TLSv1_1", None), "-tls1_1"),
                    ("TLSv1.2", getattr(TLS, "TLSv1_2", None), "-tls1_2"),
                    ("TLSv1.3", getattr(TLS, "TLSv1_3", None), "-tls1_3"),
                ]
            )
        else:
            self._protocols.extend(
                [
                    ("TLSv1", None, "-tls1"),
                    ("TLSv1.1", None, "-tls1_1"),
                    ("TLSv1.2", None, "-tls1_2"),
                    ("TLSv1.3", None, "-tls1_3"),
                ]
            )

    def run(self, context: ConnectionContext) -> List[Finding]:
        findings: List[Finding] = []

        supported_legacy: List[str] = []

        # Check 1: Probe protocol support
        for name, tls_const, openssl_flag in self._protocols:
            supported = False

            if tls_const is not None:
                try:
                    supported = context.test_protocol_version(tls_const)
                except Exception:
                    supported = False

            if not supported and openssl_flag and shutil.which("openssl"):
                try:
                    ok, _ = self._check_with_openssl(
                        context.target.hostname, context.target.port, openssl_flag
                    )
                    supported = ok
                except subprocess.TimeoutExpired:
                    supported = False
                except FileNotFoundError:
                    supported = False
                except Exception:
                    supported = False

            if supported:
                if name == "SSLv3":
                    sev = Severity.CRITICAL
                elif name in ("TLSv1",):
                    sev = Severity.HIGH
                elif name in ("TLSv1.1",):
                    sev = Severity.MEDIUM
                else:
                    sev = Severity.INFO

                if sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                    supported_legacy.append(name)

                findings.append(
                    self.create_finding(
                        severity=sev,
                        title=f"Protocol Supported: {name}",
                        description=f"Server accepted connections using {name}.",
                        remediation=f"Disable {name} on the server; prefer TLS 1.2+ (TLS 1.3 preferred).",
                        protocol=name,
                    )
                )

        # Check 2: Fallback SCSV detection
        scsv_result = self._detect_fallback_scsv(
            context.target.hostname, context.target.port, supported_legacy
        )

        if scsv_result is True:
            findings.append(
                self.create_finding(
                    severity=Severity.INFO,
                    title="Fallback SCSV: Server prevents downgrade",
                    description="Server rejected a downgraded ClientHello when TLS_FALLBACK_SCSV was present, indicating protection against downgrade attacks.",
                    remediation="No action required.",
                )
            )
        elif scsv_result is False:
            findings.append(
                self.create_finding(
                    severity=Severity.HIGH,
                    title="Fallback SCSV: Server may allow protocol downgrade",
                    description="Server accepted a downgraded ClientHello even when TLS_FALLBACK_SCSV was present, indicating it may allow protocol downgrade attacks.",
                    remediation="Enable TLS_FALLBACK_SCSV handling or upgrade server TLS stack.",
                )
            )
        elif scsv_result == "not_applicable":
            findings.append(
                self.create_finding(
                    severity=Severity.INFO,
                    title="Fallback SCSV: Not applicable",
                    description="Server does not support legacy protocols below TLS 1.2; fallback protection not required.",
                    remediation="No action required.",
                )
            )
        else:
            findings.append(
                self.create_finding(
                    severity=Severity.INFO,
                    title="Fallback SCSV: Indeterminate",
                    description="Could not conclusively determine server's handling of TLS_FALLBACK_SCSV (openssl missing, timed out, or legacy protocol not accepted).",
                    remediation="Re-run with OpenSSL available or use dedicated TLS testing tooling.",
                )
            )

        return findings

    
    def _check_with_openssl(self, host: str, port: int, openssl_flag: str, timeout: int = OPENSSL_TIMEOUT):
        """
        Returns (ok, output). ok is True when we heuristically believe the TLS handshake succeeded.
        May raise FileNotFoundError if openssl not installed or subprocess.TimeoutExpired on timeout.
        """
        cmd = ["openssl", "s_client", f"-connect", f"{host}:{port}", openssl_flag, "-servername", host, "-cipher", "DEFAULT@SECLEVEL=0"]
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        lower = out.lower()

        failure_indicators = [
            "inappropriate fallback", 
            "handshake failure",
            "no protocols available",
            "no cipher suites in common",
            "connection refused",
            "wrong version number",
            "sslv3 alert handshake failure",
        ]
        for indicator in failure_indicators:
            if indicator in lower:
                return False, out

        if proc.returncode == 0:
            success_indicators = [
                "verify return code: 0 (ok)",
                "cipher is",
                "connected(",
                "ssl handshake has read",
                "certificate chain",
                "server certificate"
            ]
            for indicator in success_indicators:
                if indicator in lower:
                    return True, out
            return True, out

        return False, out

    
    def _detect_fallback_scsv(self, host: str, port: int, supported_legacy: List[str]) -> Optional[Union[bool, str]]:
        """
        Return:
          True  -> server REJECTED the connection when -fallback_scsv was present (good)
          False -> server accepted even with -fallback_scsv (bad)
          "not_applicable" -> No legacy protocols to test
          None  -> indeterminate (openssl missing / both fail / timeout)
        """
        if not supported_legacy:
            return "not_applicable"

        if not shutil.which("openssl"):
            return None

        candidates = []
        if "TLSv1.1" in supported_legacy or "TLS 1.1" in supported_legacy:
            candidates.append("-tls1_1")
        if "TLSv1" in supported_legacy or "TLS 1.0" in supported_legacy:
            candidates.append("-tls1")
        if "SSLv3" in supported_legacy:
            candidates.append("-ssl3")
        if not candidates:
            candidates = ["-tls1_1", "-tls1", "-ssl3"]

        for flag in candidates:
            can_connect = self._test_openssl_connection_for_detection(host, port, flag, use_scsv=False)
            if can_connect is None:
                continue
            if not can_connect:
                continue

            connects_with_scsv = self._test_openssl_connection_for_detection(host, port, flag, use_scsv=True)
            if connects_with_scsv is None:
                return None

            if can_connect and not connects_with_scsv:
                return True

            if can_connect and connects_with_scsv:
                return False

            return None

        return None


    def _test_openssl_connection_for_detection(self, host: str, port: int, protocol_flag: str, use_scsv: bool = False) -> Optional[bool]:
        """
        Test if we can establish a connection using OpenSSL CLI.

        Returns:
            True  -> connection succeeded
            False -> connection failed
            None  -> indeterminate (timeout / unexpected error / openssl missing)
        """
        if not shutil.which("openssl"):
            return None

        cmd_parts = [
            "openssl",
            "s_client",
            "-connect",
            f"{host}:{port}",
            protocol_flag,
            "-servername",
            host,
            "-cipher", "DEFAULT@SECLEVEL=0"
        ]
        if use_scsv:
            cmd_parts.append("-fallback_scsv")

        try:
            proc = subprocess.run(
                cmd_parts,
                input="Q\n",
                capture_output=True,
                timeout=self.OPENSSL_TIMEOUT,
                text=True,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            out_lower = output.lower()

            failure_indicators = [
                "inappropriate fallback", 
                "handshake failure",
                "no protocols available",
                "no cipher suites in common",
                "connection refused",
                "wrong version number",
            ]
            for indicator in failure_indicators:
                if indicator in out_lower:
                    return False

            success_indicators = [
                "verify return code: 0 (ok)",
                "cipher is",
                "ssl handshake has read",
                "new, ",
                "verification: ok",           # New OpenSSL 3.0 success indicator
                "cipher:",                    # New OpenSSL 3.0 format
                "certificate chain",
            ]
            for indicator in success_indicators:
                if indicator in out_lower:
                    return True

            if proc.returncode == 0:
                return True

            return None

        except subprocess.TimeoutExpired:
            return None
        except FileNotFoundError:
            return None
        except Exception:
            return None
