from typing import List,Dict,Any
from core.base_check import BaseCheck
from core.models import Finding, Severity
from core.context import ConnectionContext


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

class DelegatedCredentialsCheck(BaseCheck):
    """
    Delegated credentials checks including:
    - Expired delegated credentials
    - Excessive DC lifetime (beyond recommended limits) 
    - Weak DC signature algorithms
    """
    
    MAX_RECOMMENDED_LIFETIME_HOURS = 7 * 24
    
    def run(self, context: ConnectionContext) -> List[Finding]:
        findings = []
        
        # Check 1: Basic DC support
        if not context.supports_delegated_credentials():
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Delegated Credentials Not Supported",
                description="The server does not support TLS 1.3 Delegated Credentials.",
                remediation="Consider implementing DC for improved certificate management.",
            ))
            return findings
        
        # Check 2: Get detailed DC information
        dc_info = context.test_dc_with_openssl()
        if not dc_info or not dc_info.get("supported", False):
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Delegated Credentials Not Offered",
                description="Server supports DC extension but did not serve one during handshake.",
            ))
            return findings
        
        # Check 3: DC Validity Period Analysis
        self._check_dc_validity(findings, dc_info)
        
        # Check 4: Weak Signature Algorithms
        self._check_dc_algorithms(findings, dc_info)
        
        
        if not any(f.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM] for f in findings):
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Properly Configured Delegated Credential",
                description=f"Delegated credential is valid (Lifetime: {dc_info.get('lifetime_hours', 0):.1f}h).",
            ))
        
        return findings
    
    def _check_dc_validity(self, findings: List[Finding], dc_info: Dict[str, Any]):
        if not dc_info.get("validity_parsed", False):
            findings.append(self.create_finding(
                severity=Severity.LOW,
                title="Delegated Credential Validity Unclear",
                description="Could not parse the delegated credential's validity period (Regex mismatch).",
                remediation="Verify OpenSSL output format.",
            ))
            return
        
        if dc_info.get("is_expired", False):
            findings.append(self.create_finding(
                severity=Severity.CRITICAL,
                title="Expired Delegated Credential",
                description=f"Delegated credential expired on {dc_info['not_after']}.",
                remediation="Rotate delegated credential immediately.",
                metadata={"expiry": str(dc_info['not_after'])}
            ))
        
        elif dc_info.get("lifetime_hours", 0) > self.MAX_RECOMMENDED_LIFETIME_HOURS:
            findings.append(self.create_finding(
                severity=Severity.MEDIUM,
                title="Excessive Delegated Credential Lifetime",
                description=f"DC lifetime is {dc_info['lifetime_hours']:.1f} hours (Max recommended: {self.MAX_RECOMMENDED_LIFETIME_HOURS}h).",
                remediation="Reduce DC lifetime (RFC 9345 recommends < 7 days).",
            ))

    def _check_dc_algorithms(self, findings: List[Finding], dc_info: Dict[str, Any]):
        if not dc_info.get("algorithm_parsed", False):
            return
        
        signature_algo = dc_info.get("signature_algorithm", "").lower()
        weak_algos = ["sha1", "md5", "rsa-pkcs1-sha1"]
        
        for weak_algo in weak_algos:
            if weak_algo in signature_algo:
                findings.append(self.create_finding(
                    severity=Severity.HIGH,
                    title="Weak Delegated Credential Signature Algorithm",
                    description=f"Delegated credential uses weak signature algorithm: {signature_algo}",
                    remediation="Use ECDSA (P-256) or RSA-PSS.",
                    metadata={"algorithm": signature_algo}
                ))
                break
