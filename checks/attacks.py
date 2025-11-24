import ssl
from typing import List
from core.base_check import BaseCheck
from core.models import Finding, Severity
from core.context import ConnectionContext

class ZombiePoodleCheck(BaseCheck):
    """
    Checks for vulnerability to the ZOMBIE/POODLE attack on TLS connections.
    This involves testing if the server is vulnerable to CBC padding oracle attacks.
    """

    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []

        TLSVersionVulnerability = False

        if (
            context.test_protocol_version(ssl.TLSVersion.TLSv1_2)
            or context.test_protocol_version(ssl.TLSVersion.TLSv1_1)
            or context.test_protocol_version(ssl.TLSVersion.TLSv1)
        ):
            TLSVersionVulnerability = True

        cipherVulnerability = False
        CBCCiphers = [
            "AES128-SHA",
            "AES256-SHA",
            "DES-CBC3-SHA",
            "AES128-SHA256" ,
            "AES256-SHA256",
            "CAMELLIA128-SHA",
            "CAMELLIA256-SHA",
        ]

        for cipher in CBCCiphers:
            if context.test_cipher_support(cipher):
                cipherVulnerability = True
                break

        if TLSVersionVulnerability and cipherVulnerability:
            if TLSVersionVulnerability:
                findings.append(
                    self.create_finding(
                        severity=Severity.CRITICAL,
                        title="ZOMBIE/POODLE Vulnerability Detected",
                        description="The server is vulnerable to the ZOMBIE/POODLE attack due to support for vulnerable TLS versions and cipher suites.",
                        remediation="Disable support for TLS 1.0, TLS 1.1 and CBC cipher suites. Use TLS 1.2+ with AEAD ciphers (e.g., AES-GCM, ChaCha20).",
                        metadata={"negotiated_cipher": cipher},
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        severity=Severity.CRITICAL,
                        title="ZOMBIE/POODLE Vulnerability Detected",
                        description="The server is vulnerable to the ZOMBIE/POODLE attack due to support for vulnerable cipher suites.",
                        remediation="Disable CBC cipher suites. Use TLS 1.2+ with AEAD ciphers (e.g., AES-GCM, ChaCha20).",
                        metadata={"negotiated_cipher": cipher},
                    )
                )
        else:
            findings.append(
                self.create_finding(
                    severity=Severity.INFO,
                    title="No ZOMBIE/POODLE Vulnerability Detected",
                    description="The server is not vulnerable to the ZOMBIE/POODLE attack based on the tested TLS versions and cipher suites.",
                    remediation="No action required.",
                    metadata={"negotiated_cipher": cipher},
                )
            )

        return findings


class TicketBleedCheck(BaseCheck):
    """
    Detects the TicketBleed vulnerability (CVE-2016-9244).
    Vulnerable servers leak up to 31 bytes of memory when session tickets
    are incorrectly processed.
    """

    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        
        # check if session tickets are supported
        try:
            baseContext = context.create_ssl_context()
            baseContext.options &= ~ssl.OP_NO_TICKET
        except Exception:
            findings.append(
                self.create_finding(
                    severity=Severity.INFO,
                    title="TicketBleed: Not Applicable",
                    description="Session tickets could not be enabled; skipping TicketBleed check.",
                )
            )
            return findings
        
        # get baseline ticket length
        try:
            with context.tls_connection(baseContext) as s:
                baseLength = self.getTicketLength(s)
        except Exception:
            findings.append(
                self.create_finding(
                    severity=Severity.INFO,
                    title="TicketBleed: Cannot Determine",
                    description="Failed to perform handshake with session tickets enabled.",
                )
            )
            return findings
        
        if baseLength is None:
            findings.append(
                self.create_finding(
                    severity=Severity.INFO,
                    title="TicketBleed: Not Applicable",
                    description="Server did not return a session ticket (likely disabled).",
                )
            )
            return findings
        
        flag = False
        lengths = [baseLength]

        for _ in range(5):
            try:
                ctx = context.create_ssl_context()
                ctx.options &= ~ssl.OP_NO_TICKET

                with context.tls_connection(ctx) as s:
                    length = self.get_ticket_length(s)
                
                if length is not None:
                    lengths.append(length)
                    if length != baseLength:
                        flag = True
            
            except Exception:
                continue
        
        if flag:
            findings.append(
                self.create_finding(
                    severity=Severity.HIGH,
                    title="TicketBleed Vulnerability Detected",
                    description=(
                        "The server returned inconsistent session ticket lengths "
                        f"across resumptions: {lengths}. This matches behavior seen in TicketBleed (CVE-2016-9244)."
                    ),
                    remediation="Update OpenSSL or F5 BIG-IP, disable session tickets, or rotate ticket keys.",
                    metadata={"ticket_lengths": lengths},
                )
            )
        else:
            findings.append(
                self.create_finding(
                    severity=Severity.INFO,
                    title="TicketBleed: No Vulnerability Detected",
                    description="Session ticket lengths were consistent across connections.",
                    metadata={"ticket_lengths": lengths},
                )
            )

        return findings

    def getTicketLength(self, ssl_socket: ssl.SSLSocket) -> int:
        """
        Safely extracts the length of the session ticket.
        Returns None if unavailable.
        """
        try:
            session = ssl_socket.session
            ticket = getattr(session, "ticket", None)
            if ticket:
                return len(ticket)
        except Exception:
            return None
        return None
