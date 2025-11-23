from typing import List, Dict, Optional
from datetime import datetime, timezone
import traceback
from .models import ScannerConfig, ScanResult, ScanTarget
from .context import ConnectionContext
from .base_check import BaseCheck

class CheckRegistry:
    def __init__(self):
        self._checks: Dict[str, BaseCheck] = {}

    def register(self, check: BaseCheck):
        self._checks[check.check_id] = check

    def get_enabled_checks(self, config: ScannerConfig) -> List[BaseCheck]:
        all_checks = list(self._checks.values())
        if config.enabled_checks:
            all_checks = [c for c in all_checks if c.check_id in config.enabled_checks]
        all_checks = [c for c in all_checks if c.check_id not in config.disabled_checks]
        return all_checks

class TLSScannerCore:
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()
        self.registry = CheckRegistry()

    def register_check(self, check: BaseCheck):
        self.registry.register(check)

    def _run_single_check(self, check: BaseCheck, context: ConnectionContext) -> tuple:
        try:
            findings = check.run(context)
            return (check.check_id, findings, None)
        except Exception as e:
            return (check.check_id, [], {
                "check_id": check.check_id,
                "error": str(e),
                "traceback": traceback.format_exc()
            })

    def scan(self, target: ScanTarget) -> ScanResult:
        start_time = datetime.now()
        all_findings = []
        errors = []
        checks = self.registry.get_enabled_checks(self.config)
        context = ConnectionContext(target, self.config)

        for check in checks:
            check_id, findings, error = self._run_single_check(check, context)
            if error:
                errors.append(error)
                if self.config.stop_on_error:
                    break
            else:
                all_findings.extend(findings)

        end_time = datetime.now()
        
        return ScanResult(
            target=target,
            findings=all_findings,
            start_time=start_time,
            end_time=end_time,
            total_checks=len(checks),
            successful_checks=len(checks) - len(errors),
            failed_checks=len(errors),
            errors=errors
        )
