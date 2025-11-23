from abc import ABC, abstractmethod
from typing import List,Optional
from .models import Finding, Severity
from .context import ConnectionContext


class BaseCheck(ABC):
    def __init__(self):
        self.name = self.__class__.__name__
        self.description = self.__doc__ or "No description provided"

    @abstractmethod
    def run(self, context: ConnectionContext) -> List[Finding]:
        pass

    @property
    def check_id(self) -> str:
        return self.name.lower().replace(" ", "_")

    def create_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        remediation: Optional[str] = None,
        **metadata
    ) -> Finding:
        """Helper to create a finding with this check's name"""
        return Finding(
            check_name=self.name,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            metadata=metadata
        )
