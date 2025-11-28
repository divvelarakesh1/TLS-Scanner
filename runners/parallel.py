import multiprocessing
import time
from typing import Optional, List, Union
from core.scanner import TLSScannerCore
from core.models import ScannerConfig, ScanTarget

from checks.certificates import DeepCertificateAnalysisCheck, DelegatedCredentialsCheck
from checks.protocols import ProtocolSupportCheck
from checks.ciphers import CipherConfigurationCheck, SessionTicketCheck
from checks.attacks import TicketBleedCheck, ZombiePoodleCheck
from checks.feature import AlpnCheck, TlsCompressionCheck, OcspStaplingCheck

def run_scan(targets: list[ScanTarget], pool_size: int = 20, connection_timeout: float = 10.0):
    
    runner = ParallelRunner(targets=targets, workers=pool_size, timeout=connection_timeout)
    return runner.run()

class ParallelRunner:
    def __init__(self, targets: Union[List[ScanTarget], str], workers: int = 20, timeout: float = 10.0):
        self.targets_input = targets
        self.workers = workers
        self.timeout = timeout
        self.queue = multiprocessing.JoinableQueue(maxsize=workers * 2)

    def _worker_process(self):
        
        #Consumer process: Scans targets from the queue.
        
        
        config = ScannerConfig(connection_timeout=self.timeout, verify_certificates=False)
        scanner = TLSScannerCore(config)
        
        
        scanner.register_check(DeepCertificateAnalysisCheck())
        scanner.register_check(ProtocolSupportCheck())
        scanner.register_check(CipherConfigurationCheck())
        scanner.register_check(SessionTicketCheck())
        #scanner.register_check(HeartbleedCheck())
        scanner.register_check(ZombiePoodleCheck())
        scanner.register_check(AlpnCheck())
        scanner.register_check(DelegatedCredentialsCheck())
        scanner.register_check(TlsCompressionCheck())
        scanner.register_check(OcspStaplingCheck())

        while True:
            target_obj = self.queue.get()
            
            
            if target_obj is None:
                self.queue.task_done()
                break

            try:
                
                if isinstance(target_obj, str):
                    if ":" in target_obj:
                        h, p = target_obj.split(":")
                        real_target = ScanTarget(h, int(p))
                    else:
                        real_target = ScanTarget(target_obj, 443)
                else:
                    real_target = target_obj

                
                scanner.scan(real_target)
                
            except Exception:
                
                pass
            
            self.queue.task_done()

    def run(self):
        processes = []
        
        
        for _ in range(self.workers):
            p = multiprocessing.Process(target=self._worker_process)
            p.start()
            processes.append(p)
            
        
        count = 0
        if isinstance(self.targets_input, list):
            
            for t in self.targets_input:
                self.queue.put(t)
                count += 1
        elif isinstance(self.targets_input, str):
            
            try:
                with open(self.targets_input, "r") as f:
                    for line in f:
                        d = line.strip()
                        if d and not d.startswith("#"):
                            self.queue.put(d)
                            count += 1
            except FileNotFoundError:
                print(f"[!] File {self.targets_input} not found.")

        
        for _ in range(self.workers):
            self.queue.put(None)

        
        self.queue.join()
        
        for p in processes:
            p.join()
            
        return count

if __name__ == "__main__":
    # To run this standalone: python -m runners.paralle
    runner = ParallelRunner("targets.txt", workers=5)
    runner.run()
