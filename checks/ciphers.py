import shutil
import subprocess
import re
from typing import List, Dict, Any
from core.base_check import BaseCheck
from core.models import Finding, Severity
from core.context import ConnectionContext

class CipherConfigurationCheck(BaseCheck):
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        weak_targets = [
            ("NULL", "NULL", Severity.CRITICAL),
            ("ADH", "ADH", Severity.CRITICAL),
            ("AECDH", "AECDH", Severity.CRITICAL),
            ("EXPORT", "EXP", Severity.CRITICAL),
            ("RC4", "RC4", Severity.HIGH),
            ("RC2", "RC2", Severity.HIGH),
            ("DES", "DES", Severity.HIGH),
            ("3DES", "3DES", Severity.MEDIUM),
            ("SEED", "SEED", Severity.MEDIUM),
            ("IDEA", "IDEA", Severity.MEDIUM),
            ("CAMELLIA", "CAMELLIA", Severity.MEDIUM),
        ]
        for name, cipher_str, severity in weak_targets:
            if context.test_cipher_suite(cipher_str):
                 findings.append(self.create_finding(severity, f"Weak Cipher Supported: {name}", f"The server supports the obsolete {name} cipher suite.", remediation=f"Disable {name} in the server configuration.", metadata={"cipher_string": cipher_str}))
        
        if context.test_cipher_suite("kRSA"):
             findings.append(self.create_finding(Severity.MEDIUM, "No Forward Secrecy (Static RSA)", "The server supports Static RSA key exchange.", remediation="Prioritize ECDHE or DHE cipher suites.", metadata={"cipher_string": "kRSA"}))
        
        if context.test_cipher_suite("aNULL"):
             findings.append(self.create_finding(Severity.CRITICAL, "Anonymous Cipher Suites Supported", "The server supports cipher suites with no authentication (aNULL).", remediation="Disable anonymous cipher suites immediately.", metadata={"cipher_string": "aNULL"}))
        return findings

class SessionTicketCheck(BaseCheck):
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        if not shutil.which("openssl"):
            findings.append(self.create_finding(Severity.INFO, "Skipping Session Ticket Check", "OpenSSL binary not found."))
            return findings

        ticket_info_1 = self._analyze_ticket(context)
        if not ticket_info_1.get("supported", False):
            findings.append(self.create_finding(Severity.INFO, "Session Tickets Not Supported", "Server does not issue stateless session tickets."))
            return findings

        lifetime = ticket_info_1.get("lifetime_hint", 0)
        if lifetime > 604800:
            findings.append(self.create_finding(Severity.HIGH, "Excessive Session Ticket Lifetime", f"Server suggests a ticket lifetime of {lifetime} seconds.", remediation="Configure STEK rotation."))
        
        ticket_info_2 = self._analyze_ticket(context)
        blob1 = ticket_info_1.get("ticket_hex", "")
        blob2 = ticket_info_2.get("ticket_hex", "")
        
        if blob1 and blob2 and blob1 == blob2:
            findings.append(self.create_finding(Severity.HIGH, "Static Session Tickets Detected", "Server issued exact same session ticket binary for two connections.", remediation="Ensure TLS software generates unique tickets."))
        
        return findings

    def _analyze_ticket(self, context: ConnectionContext) -> Dict[str, Any]:
        result_info = {"supported": False, "lifetime_hint": 0, "ticket_hex": ""}
        try:
            cmd = ["openssl", "s_client", "-connect", f"{context.target.hostname}:{context.target.port}", "-servername", context.target.effective_sni, "-sess_out", "-", "-no_ssl3", "-no_tls1"]
            proc = subprocess.run(cmd, input="Q\n", capture_output=True, text=True, timeout=10)
            output = proc.stdout + proc.stderr
            
            if "Post-Handshake New Session Ticket arrived" in output or "TLS session ticket:" in output:
                result_info["supported"] = True
            
            hint_match = re.search(r'lifetime hint[:\s]*(\d+)', output, re.IGNORECASE)
            if hint_match:
                result_info["lifetime_hint"] = int(hint_match.group(1))
                result_info["supported"] = True

            if "TLS session ticket:" in output:
                start_idx = output.find("TLS session ticket:")
                chunk = output[start_idx:start_idx+1000]
                hex_lines = re.findall(r'^\s*[0-9a-f]{4}\s-\s([0-9a-f\s]+)', chunk, re.MULTILINE)
                if hex_lines:
                    result_info["ticket_hex"] = "".join(hex_lines).replace(" ", "")
        except Exception:
            pass
        return result_info