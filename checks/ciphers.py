import shutil
import subprocess
import re
from typing import List, Dict, Any
from core.base_check import BaseCheck
from core.models import Finding, Severity
from core.context import ConnectionContext

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

class SessionTicketCheck(BaseCheck):
    """
    Checks for Session Ticket Encryption Key (STEK) misuse:
    1. Excessive Ticket Lifetimes (Keys not rotated frequently).
    2. Static Tickets (Lack of entropy/IV reuse).
    3. Support verification (RFC 5077/8446).
    """
    
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        
        # This check requires the 'openssl' binary to parse raw ticket fields
        if not shutil.which("openssl"):
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Skipping Session Ticket Check",
                description="OpenSSL binary not found on scanner host. Cannot analyze raw ticket data.",
            ))
            return findings

        # --- Step 1: Analyze First Connection ---
        ticket_info_1 = self._analyze_ticket(context)
        
        if not ticket_info_1.get("supported", False):
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Session Tickets Not Supported",
                description="Server does not issue stateless session tickets.",
            ))
            # If not supported, we can't test for misuse
            return findings

        # --- Step 2: Check Key Rotation (Lifetime Hint) ---
        # The server sends a 'hint' for how long the ticket is valid.
        # If this is too long (e.g., months), it implies the STEK is not rotated often.
        lifetime = ticket_info_1.get("lifetime_hint", 0)
        
        # Thresholds: > 7 days (High Risk), > 1 day (Medium Risk)
        if lifetime > 604800: 
            findings.append(self.create_finding(
                severity=Severity.HIGH,
                title="Excessive Session Ticket Lifetime",
                description=f"Server suggests a ticket lifetime of {lifetime} seconds ({lifetime/86400:.1f} days).",
                remediation="Configure STEK rotation to occur at least daily. Long lifetimes increase the risk to Forward Secrecy.",
                metadata={"lifetime_seconds": lifetime}
            ))
        elif lifetime > 86400: 
            findings.append(self.create_finding(
                severity=Severity.MEDIUM,
                title="Long Session Ticket Lifetime",
                description=f"Server suggests a ticket lifetime of {lifetime/3600:.1f} hours.",
                remediation="Consider rotating session keys daily (recommended < 24 hours).",
                metadata={"lifetime_seconds": lifetime}
            ))
        else:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Session Ticket Lifetime OK",
                description=f"Ticket lifetime hint is {lifetime} seconds ({lifetime/3600:.1f} hours).",
            ))

        # --- Step 3: Check Entropy (Static Ticket Detection) ---
        # 
        # We connect a SECOND time. 
        # A secure server MUST issue a different ticket (new IV, new HMAC) for every connection.
        # If the binary blob is identical, the server has broken randomness.
        
        ticket_info_2 = self._analyze_ticket(context)
        
        blob1 = ticket_info_1.get("ticket_hex", "")
        blob2 = ticket_info_2.get("ticket_hex", "")
        
        if blob1 and blob2 and blob1 == blob2:
            findings.append(self.create_finding(
                severity=Severity.HIGH,
                title="Static Session Tickets Detected (Lack of Entropy)",
                description="Server issued the exact same session ticket binary for two separate connections. This indicates a static IV or broken STEK implementation.",
                remediation="Ensure TLS software generates unique tickets per connection using random IVs.",
            ))
        elif blob1 and blob2:
             findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Session Tickets are Randomized",
                description="Server issued unique tickets for separate connections (Good entropy).",
            ))

        return findings

    def _analyze_ticket(self, context: ConnectionContext) -> Dict[str, Any]:
        """
        Connects via OpenSSL CLI and parses the session ticket output.
        """
        result_info = {"supported": False, "lifetime_hint": 0, "ticket_hex": ""}
        
        try:
            # Command: openssl s_client -connect host:port ...
            # We disable SSLv3/TLS1 to ensure we get modern ticket structures if possible
            cmd = [
                "openssl", "s_client",
                "-connect", f"{context.target.hostname}:{context.target.port}",
                "-servername", context.target.effective_sni,
                "-no_ssl3", "-no_tls1", 
            ]
            
            # Run with timeout
            proc = subprocess.run(
                cmd, 
                input="Q\n", # Send 'Q' to quit immediately after handshake
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            output = proc.stdout + proc.stderr
            
            # 1. Check if a ticket was actually received
            # OpenSSL output varies: "Post-Handshake New Session Ticket arrived" (TLS 1.3) or "TLS session ticket:" (TLS 1.2)
            if "Post-Handshake New Session Ticket arrived" in output or "TLS session ticket:" in output:
                result_info["supported"] = True
                
            # 2. Extract Lifetime Hint
            # Example output: "TLS session ticket lifetime hint: 7200 (seconds)"
            hint_match = re.search(r'lifetime hint[:\s]*(\d+)', output, re.IGNORECASE)
            if hint_match:
                result_info["lifetime_hint"] = int(hint_match.group(1))
                # If we see a hint, it definitely supports tickets
                result_info["supported"] = True

            # 3. Extract Raw Ticket Hex (For Entropy Check)
            # OpenSSL dumps the ticket in a hex block like:
            # 0000 - fc 23 11 ...
            # 0010 - ab cd ef ...
            if "TLS session ticket:" in output:
                # Find where the ticket dump starts
                start_idx = output.find("TLS session ticket:")
                # Grab a chunk of text after that
                chunk = output[start_idx:start_idx+2000]
                
                # Regex to match the hex dump lines (e.g., " 0010 - AE 4F ...")
                hex_lines = re.findall(r'^\s*[0-9a-f]{4}\s-\s([0-9a-f\s]+)', chunk, re.MULTILINE)
                
                if hex_lines:
                    # Combine lines and remove spaces to get a pure hex string
                    raw_hex = "".join(hex_lines).replace(" ", "")
                    result_info["ticket_hex"] = raw_hex

        except Exception:
            pass
            
        return result_info