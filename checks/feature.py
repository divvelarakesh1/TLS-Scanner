import ssl
from typing import List
from core.base_check import BaseCheck
from core.models import Finding, Severity
from core.context import ConnectionContext

class AlpnCheck(BaseCheck):
    """
    Checks if the server supports Application Layer Protocol Negotiation (ALPN),
    specifically identifying HTTP/2 support.
    """
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        try:
            # We need a fresh context to set ALPN protocols
            ctx = context.create_ssl_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])

            with context.tls_connection(ctx) as ssl_sock:
                selected = ssl_sock.selected_alpn_protocol()

                if selected == 'h2':
                    findings.append(self.create_finding(
                        severity=Severity.INFO,
                        title="HTTP/2 Supported (ALPN)",
                        description="Server supports modern HTTP/2 protocol via ALPN.",
                        metadata={"protocol": "h2"}
                    ))
                elif selected == 'http/1.1':
                    findings.append(self.create_finding(
                        severity=Severity.LOW,
                        title="No HTTP/2 Support (ALPN)",
                        description="Server negotiated HTTP/1.1. It does not support HTTP/2.",
                        metadata={"protocol": "http/1.1"}
                    ))
                else:
                    findings.append(self.create_finding(
                        severity=Severity.LOW,
                        title="ALPN Not Supported",
                        description="Server did not negotiate an application protocol.",
                    ))
        except Exception:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="ALPN Check Failed",
                description="Could not determine ALPN support due to connection error."
            ))
        return findings


class TlsCompressionCheck(BaseCheck):
    """
    Checks if TLS Compression is enabled.
    Enabled compression facilitates the CRIME attack (CVE-2012-4929).
    """
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        try:
            ctx = context.create_ssl_context()
            # Manually clear OP_NO_COMPRESSION to see if server accepts it
            ctx.options &= ~ssl.OP_NO_COMPRESSION

            with context.tls_connection(ctx) as ssl_sock:
                comp_alg = ssl_sock.compression()

                if comp_alg:
                    findings.append(self.create_finding(
                        severity=Severity.HIGH,
                        title="TLS Compression Enabled (CRIME Risk)",
                        description=f"Server supports TLS compression ({comp_alg}). This enables the CRIME attack.",
                        remediation="Disable TLS compression on the server (usually 'SSLCompression Off')."
                    ))
                else:
                    findings.append(self.create_finding(
                        severity=Severity.INFO,
                        title="TLS Compression Disabled",
                        description="Server correctly disables TLS compression."
                    ))
        except Exception:
            pass
        return findings


class OcspStaplingCheck(BaseCheck):
    """
    Checks if the server supports OCSP Stapling.
    Stapling improves privacy and performance by bundling the revocation status.
    """
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        try:
            ctx = context.create_ssl_context()
            
            # Try to request status (OCSP)
            if hasattr(ssl, 'VERIFY_OCSP_STAPLED'):
                 ctx.verify_flags |= ssl.VERIFY_OCSP_STAPLED

            with context.tls_connection(ctx) as ssl_sock:
                ocsp_data = None
                if hasattr(ssl_sock, "ocsp_response"):
                     ocsp_data = ssl_sock.ocsp_response

                if ocsp_data:
                    findings.append(self.create_finding(
                        severity=Severity.INFO,
                        title="OCSP Stapling Supported",
                        description="Server provided an OCSP response during handshake (Optimization/Privacy Good).",
                    ))
                else:
                    findings.append(self.create_finding(
                        severity=Severity.LOW,
                        title="OCSP Stapling Not Detected",
                        description="Server did not provide a stapled OCSP response.",
                    ))
        except Exception:
            pass
        return findings