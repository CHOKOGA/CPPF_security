"""
Modèle de données typé pour DevSecAssist (Finding, ScanResult, Severity, Confidence).
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional

class Severity(str, Enum):
    HAUTE = "HAUTE"
    MOYENNE = "MOYENNE"
    BASSE = "BASSE"
    INFO = "INFO"

class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    """Représente une alerte ou découverte de sécurité normalisée."""
    id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    recommendation: str
    file: Optional[str] = None
    line: Optional[int] = None
    target: Optional[str] = None
    snippet: Optional[str] = None
    evidence: Optional[str] = None
    source: str = "DevSecAssist"

    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'objet Finding en dictionnaire."""
        return {
            "id": self.id,
            "title": self.title,
            "type": self.title,  # Rétrocompatibilité
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file": self.file,
            "line": self.line,
            "target": self.target,
            "snippet": self.snippet,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "source": self.source
        }

@dataclass
class ScanResult:
    """Résultat global d'un scan de sécurité."""
    target: str
    findings: List[Finding] = field(default_factory=list)
    score: int = 100
    risk_grade: str = "A (Excellent)"
    stats: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Export au format dictionnaire."""
        return {
            "target": self.target,
            "score": self.score,
            "risk_grade": self.risk_grade,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings]
        }
