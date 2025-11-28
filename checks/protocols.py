import ssl
import shutil
import subprocess
from typing import List, Union, Optional
from core.base_check import BaseCheck
from core.models import Finding, Severity
from core.context import ConnectionContext

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

        # Probe protocol support
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

        #  Fallback SCSV detection
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
          True  -> server REJECTED the connection when -fallback_scsv was present 
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
                "verification: ok",           
                "cipher:",                    
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
      
