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
        return list(self._checks.values())

class TLSScannerCore:
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()
        self.registry = CheckRegistry()

    def register_check(self, check: BaseCheck):
        self.registry.register(check)

    def scan(self, target: ScanTarget) -> ScanResult:
        start_time = datetime.now(timezone.utc)
        all_findings = []
        errors = []
        checks = self.registry.get_enabled_checks(self.config)
        context = ConnectionContext(target, self.config)

        for check in checks:
            try:
                findings = check.run(context)
                all_findings.extend(findings)
            except Exception as e:
                errors.append({"check": check.name, "error": str(e)})

        end_time = datetime.now(timezone.utc)
        return ScanResult(target, all_findings, start_time, end_time, len(checks), len(checks)-len(errors), len(errors), errors)