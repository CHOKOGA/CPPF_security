"""
Module de calcul de score de risque global et de déduplication des alerte.
"""
from typing import List, Dict, Any, Tuple

class RiskCalculator:
    """Calcule un score de sécurité global (0-100) et déduplique les alertes."""

    @staticmethod
    def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Élimine les alertes en double basées sur le type, la catégorie, le fichier/cible et la ligne."""
        seen = set()
        unique = []

        for f in findings:
            key = (
                f.get("type"),
                f.get("category"),
                f.get("file") or f.get("target"),
                f.get("line"),
                f.get("snippet")
            )
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    @staticmethod
    def calculate_score(findings: List[Dict[str, Any]]) -> Tuple[int, str, Dict[str, int]]:
        """
        Calcule un score de sécurité de 0 à 100 et attribue une note (A à F).
        """
        stats = {
            "high": sum(1 for f in findings if f.get("severity") == "HAUTE"),
            "med": sum(1 for f in findings if f.get("severity") == "MOYENNE"),
            "low": sum(1 for f in findings if f.get("severity") == "BASSE"),
            "info": sum(1 for f in findings if f.get("severity") == "INFO"),
            "total": len(findings)
        }

        # Déductions
        deductions = (stats["high"] * 15) + (stats["med"] * 7) + (stats["low"] * 2)
        score = max(0, 100 - deductions)

        # Attribution de la note
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
