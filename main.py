from core.models import ScanTarget, ScannerConfig, Severity
from core.scanner import TLSScannerCore

# Import checks
from checks.certificates import DeepCertificateAnalysisCheck, DelegatedCredentialsCheck
from checks.protocols import ProtocolSupportCheck
from checks.ciphers import CipherConfigurationCheck, SessionTicketCheck
from checks.attacks import ZombiePoodleCheck, TicketBleedCheck
from checks.vulnerability import VulnerabilityCheck
from checks.feature import AlpnCheck,TlsCompressionCheck,OcspStaplingCheck

if __name__ == "__main__":
    config = ScannerConfig(connection_timeout=10.0, verify_certificates=False)
    scanner = TLSScannerCore(config)
    
    # The protocol checks
    scanner.register_check(ProtocolSupportCheck())
    
    #Ciphers.py
    scanner.register_check(CipherConfigurationCheck())
    scanner.register_check(SessionTicketCheck())

    #cerificates.py
    scanner.register_check(DeepCertificateAnalysisCheck())
    scanner.register_check(DelegatedCredentialsCheck())
    
    #attacks.py
    scanner.register_check(ZombiePoodleCheck())
    scanner.register_check(TicketBleedCheck())

    #feature.py
    scanner.register_check(AlpnCheck())
    scanner.register_check(TlsCompressionCheck())
    scanner.register_check(OcspStaplingCheck())

    
    target = ScanTarget(hostname="www.google.com", port=443)
 
    
    print(f"[*] Scanning {target.hostname}:{target.port}...")
    result = scanner.scan(target)
    
    print(f"\n{'='*60}")
    print(f"Scan completed in {result.duration_seconds:.2f} seconds")
    print(f"Total checks: {result.total_checks}")
    print(f"Successful: {result.successful_checks}")
    print(f"{'='*60}\n")
    
    found_issues = False
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        findings = result.get_findings_by_severity(severity)
        if findings:
            found_issues = True
            print(f"\n[{severity.value.upper()}] Findings:")
            for f in findings:
                print(f" - [{f.check_name}] {f.title}")
                print(f"   {f.description}")
                if f.remediation:
                    print(f"   Fix: {f.remediation}")

    if not found_issues:
        print("\n[+] No issues found.")