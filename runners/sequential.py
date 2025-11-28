import time
from core.scanner import TLSScannerCore
from core.models import ScannerConfig, ScanTarget
from checks.certificates import DeepCertificateAnalysisCheck, DelegatedCredentialsCheck
from checks.protocols import ProtocolSupportCheck
from checks.ciphers import CipherConfigurationCheck, SessionTicketCheck
from checks.attacks import  ZombiePoodleCheck,TicketBleedCheck
from checks.feature import AlpnCheck, TlsCompressionCheck, OcspStaplingCheck

def run_scan(targets: list[ScanTarget]):
    
    #Sequential Runner: Scans one target at a time (Blocking I/O).
    
    results = []
    
    
    config = ScannerConfig(connection_timeout=5.0, verify_certificates=False)
    
    for target in targets:
        
        scanner = TLSScannerCore(config)
        
        
        scanner.register_check(DeepCertificateAnalysisCheck())
        scanner.register_check(DelegatedCredentialsCheck())
        scanner.register_check(ProtocolSupportCheck())
        scanner.register_check(CipherConfigurationCheck())
        scanner.register_check(SessionTicketCheck())
        scanner.register_check(ZombiePoodleCheck())
        scanner.register_check(AlpnCheck())
        scanner.register_check(TlsCompressionCheck())
        scanner.register_check(OcspStaplingCheck())
        
        
        result = scanner.scan(target)
        results.append(result)

    return results
