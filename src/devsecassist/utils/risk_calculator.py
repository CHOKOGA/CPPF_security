"""
Calculateur de risque global et déduplicateurs de découvertes (Finding).
"""
from typing import List, Tuple, Dict
from devsecassist.models import Finding, Severity

class RiskCalculator:
    """Calcule un score de sécurité global (0-100) et déduplique les découvertes."""

    @staticmethod
    def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
        """Élimine les découvertes identiques basées sur la signature."""
        seen = set()
        unique = []

        for f in findings:
            key = (f.id, f.category, f.file or f.target, f.line, f.snippet)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    @staticmethod
    def calculate_score(findings: List[Finding]) -> Tuple[int, str, Dict[str, int]]:
        """Calcule un score global (0-100) et la note de sécurité."""
        stats = {
            "high": sum(1 for f in findings if f.severity == Severity.HAUTE),
            "med": sum(1 for f in findings if f.severity == Severity.MOYENNE),
            "low": sum(1 for f in findings if f.severity == Severity.BASSE),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
            "total": len(findings)
        }

        deductions = (stats["high"] * 15) + (stats["med"] * 7) + (stats["low"] * 2)
        score = max(0, 100 - deductions)

        if score >= 90:
            grade = "A (Excellent)"
        elif score >= 75:
            grade = "B (Bon)"
        elif score >= 50:
            grade = "C (Moyen - Corrections requises)"
        elif score >= 25:
            grade = "D (Risqué - Faiblesses critiques)"
        else:
            grade = "F (Critique - Risque élevé)"

        return score, grade, stats
