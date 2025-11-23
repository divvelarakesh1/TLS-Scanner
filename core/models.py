from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime, timezone

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    check_name: str
    severity: Severity
    title: str
    description: str
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class ScanTarget:
    hostname: str
    port: int = 443
    sni_hostname: Optional[str] = None
    starttls_protocol: Optional[str] = None

    @property
    def effective_sni(self) -> str:
        return self.sni_hostname or self.hostname

@dataclass
class Certificate:
    pem: str
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: str
    not_before: datetime
    not_after: datetime
    san: List[str]
    fingerprint_sha256: str
    public_key_algorithm: str
    signature_algorithm: str
    key_size: int

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.not_after

    @property
    def is_not_yet_valid(self) -> bool:
        return datetime.now(timezone.utc) < self.not_before

    @property
    def days_until_expiry(self) -> int:
        delta = self.not_after - datetime.now(timezone.utc)
        return delta.days

@dataclass
class ScannerConfig:
    connection_timeout: float = 5.0
    handshake_timeout: float = 10.0
    stop_on_error: bool = False
    enabled_checks: Optional[List[str]] = None
    disabled_checks: List[str] = field(default_factory=list)
    verify_certificates: bool = False 

@dataclass
class ScanResult:
    target: ScanTarget
    findings: List[Finding]
    start_time: datetime
    end_time: datetime
    total_checks: int
    successful_checks: int
    failed_checks: int
    errors: List[Dict[str, str]] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]
@dataclass
class DelegatedCredential:
    pem: str
    algorithm: str
    not_before: datetime
    not_after: datetime
    public_key_algorithm: str
    key_size: int
    signature_algorithm: str
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.not_after
    
    @property
    def is_not_yet_valid(self) -> bool:
        return datetime.now() < self.not_before
    
    @property
    def days_until_expiry(self) -> int:
        delta = self.not_after - datetime.now()
        return delta.days
    
    @property
    def total_lifetime_hours(self) -> float:
        delta = self.not_after - self.not_before
        return delta.total_seconds() / 3600
