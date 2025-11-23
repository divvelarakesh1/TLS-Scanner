from typing import List
from core.base_check import BaseCheck
from core.models import Finding, Severity
from core.context import ConnectionContext

class DeepCertificateAnalysisCheck(BaseCheck):
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        chain = context.get_certificate_chain()
        if not chain:
            findings.append(self.create_finding(Severity.CRITICAL, "Certificate missing", "Could not retrieve certificate chain"))
            return findings
        
        cert = chain[0]
        if cert.is_expired:
            findings.append(self.create_finding(Severity.CRITICAL, "Certificate Expired", f"Expired on {cert.not_after}"))
        elif cert.is_not_yet_valid:
            findings.append(self.create_finding(Severity.HIGH, "Certificate Not Yet Valid", f"Valid from {cert.not_before}"))
        
        if any(alg in cert.signature_algorithm.lower() for alg in ['md5', 'sha1']):
            findings.append(self.create_finding(Severity.CRITICAL, "Weak Signature Algorithm", f"Uses {cert.signature_algorithm}"))

        target_host = context.target.effective_sni
        san_match = target_host in cert.san
        if not san_match:
            for san in cert.san:
                if san.startswith("*."):
                    suffix = san[2:]
                    if target_host.endswith(suffix) and target_host.count(".") == suffix.count(".") + 1:
                        san_match = True
                        break
        if not san_match:
            cn = cert.subject.get("CN", "")
            if cn == target_host: san_match = True

        if not san_match:
            findings.append(self.create_finding(Severity.HIGH, "Hostname Mismatch", f"Certificate not valid for {target_host}"))

        if cert.subject == cert.issuer:
            findings.append(self.create_finding(Severity.MEDIUM, "Self-Signed Certificate", "Certificate is self-signed"))

        return findings

class DelegatedCredentialsCheck(BaseCheck):
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        if not context.supports_delegated_credentials():
            findings.append(self.create_finding(Severity.INFO, "Delegated Credentials Not Supported", "Server does not support DC."))
            return findings
        
        dc_info = context.test_dc_with_openssl()
        if not dc_info or not dc_info.get("supported", False):
            findings.append(self.create_finding(Severity.INFO, "Delegated Credentials Not Offered", "Server supports DC but did not offer one."))
            return findings
        
        if dc_info.get("is_expired", False):
            findings.append(self.create_finding(Severity.CRITICAL, "Expired Delegated Credential", "DC has expired."))
        
        return findings