import ssl
import shutil
import subprocess
from typing import List, Union, Optional
from core.base_check import BaseCheck
from core.models import Finding, Severity
from core.context import ConnectionContext

class ProtocolSupportCheck(BaseCheck):
    OPENSSL_TIMEOUT = 20

    def __init__(self):
        super().__init__()
        self._protocols = []
        self._protocols.append(("SSLv3", None, "-ssl3"))
        if hasattr(ssl, "TLSVersion"):
            TLS = ssl.TLSVersion
            self._protocols.extend([
                ("TLSv1", getattr(TLS, "TLSv1", None), "-tls1"),
                ("TLSv1.1", getattr(TLS, "TLSv1_1", None), "-tls1_1"),
                ("TLSv1.2", getattr(TLS, "TLSv1_2", None), "-tls1_2"),
                ("TLSv1.3", getattr(TLS, "TLSv1_3", None), "-tls1_3"),
            ])
        else:
            self._protocols.extend([
                ("TLSv1", None, "-tls1"), ("TLSv1.1", None, "-tls1_1"),
                ("TLSv1.2", None, "-tls1_2"), ("TLSv1.3", None, "-tls1_3"),
            ])

    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        supported_legacy = []

        for name, tls_const, openssl_flag in self._protocols:
            supported = False
            if tls_const is not None:
                supported = context.test_protocol_version(tls_const)
            
            if not supported and openssl_flag and shutil.which("openssl"):
                try:
                    ok, _ = self._check_with_openssl(context.target.hostname, context.target.port, openssl_flag)
                    supported = ok
                except: pass

            if supported:
                sev = Severity.INFO
                if name == "SSLv3": sev = Severity.CRITICAL
                elif name == "TLSv1": sev = Severity.HIGH
                elif name == "TLSv1.1": sev = Severity.MEDIUM
                
                if sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                    supported_legacy.append(name)
                
                findings.append(self.create_finding(sev, f"Protocol Supported: {name}", f"Server accepted connections using {name}."))

        scsv_result = self._detect_fallback_scsv(context.target.hostname, context.target.port, supported_legacy)
        if scsv_result is False:
            findings.append(self.create_finding(Severity.HIGH, "Fallback SCSV Missing", "Server allows protocol downgrade attacks."))
        
        return findings

    def _check_with_openssl(self, host: str, port: int, openssl_flag: str):
        cmd = ["openssl", "s_client", f"-connect", f"{host}:{port}", openssl_flag, "-servername", host, "-cipher", "DEFAULT@SECLEVEL=0"]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=self.OPENSSL_TIMEOUT, text=True, input="Q\n")
            out = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode == 0 and "cipher is" in out.lower(): return True, out
        except: pass
        return False, ""

    def _detect_fallback_scsv(self, host: str, port: int, supported_legacy: List[str]) -> Optional[Union[bool, str]]:
        if not supported_legacy or not shutil.which("openssl"): return "not_applicable"
        flag = "-tls1" if "TLSv1" in supported_legacy else "-ssl3"
        
        can_connect = self._test_openssl(host, port, flag, False)
        if not can_connect: return None
        connects_with_scsv = self._test_openssl(host, port, flag, True)
        
        if can_connect and not connects_with_scsv: return True
        if can_connect and connects_with_scsv: return False
        return None

    def _test_openssl(self, host: str, port: int, protocol_flag: str, use_scsv: bool):
        cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", protocol_flag, "-servername", host, "-cipher", "DEFAULT@SECLEVEL=0"]
        if use_scsv: cmd.append("-fallback_scsv")
        try:
            proc = subprocess.run(cmd, input="Q\n", capture_output=True, timeout=20, text=True)
            return proc.returncode == 0 and "cipher is" in (proc.stdout + proc.stderr).lower()
        except: return None