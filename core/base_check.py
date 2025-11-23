from abc import ABC, abstractmethod
from typing import List
from .models import Finding, Severity
from .context import ConnectionContext

class BaseCheck(ABC):
    def __init__(self):
        self.name = self.__class__.__name__

    @abstractmethod
    def run(self, context: ConnectionContext) -> List[Finding]:
        pass

    @property
    def check_id(self) -> str:
        return self.name.lower().replace(" ", "_")

    def create_finding(self, severity: Severity, title: str, description: str, **kwargs) -> Finding:
        return Finding(
            check_name=self.name,
            severity=severity,
            title=title,
            description=description,
            **kwargs
        )