from dataclasses import dataclass, field
from typing import Any
from enum import Enum


class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


CVSS_MAP = {
    Severity.informational: 0.0,
    Severity.low: 3.5,
    Severity.medium: 5.5,
    Severity.high: 7.5,
    Severity.critical: 9.5,
}

SEVERITY_WEIGHTS = {
    Severity.informational: 1,
    Severity.low: 5,
    Severity.medium: 20,
    Severity.high: 50,
    Severity.critical: 100,
}


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    category: str
    module: str
    affected_url: str = ""
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""
    references: list = field(default_factory=list)
    owasp_category: str = ""
    cvss_score: float = 0.0
    cve: str = ""

    def __post_init__(self):
        if not self.cvss_score:
            self.cvss_score = CVSS_MAP.get(self.severity, 0.0)


@dataclass
class ScanResult:
    module: str
    findings: list[Finding] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0


def calculate_risk_score(findings: list[Finding]) -> float:
    if not findings:
        return 100.0
    total_weight = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = max(0.0, 100.0 - (total_weight * 0.8))
    return round(score, 1)
