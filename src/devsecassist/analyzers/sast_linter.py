"""
Module d'analyse statique du code (SASTLinter).
"""
import re
from pathlib import Path
from typing import List, Optional
from devsecassist.models import Finding, Severity, Confidence
from devsecassist.utils.exclusion_manager import ExclusionManager
from devsecassist.analyzers.base import BaseAnalyzer

class SASTLinter(BaseAnalyzer):
    """Effectue l'analyse statique du code source pour repérer des modèles risqués."""

    RULES = [
        {
            "id": "SAST-001",
            "category": "Concaténation SQL potentiellement risquée",
            "severity": Severity.HAUTE,
            "confidence": Confidence.HIGH,
            "extensions": {".py", ".js", ".ts", ".php", ".java"},
            "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+|f[\"'].*?(SELECT|INSERT|UPDATE|DELETE)|(SELECT|INSERT|UPDATE|DELETE)\s+.*?%",
            "recommendation": "Utilisez systématiquement des requêtes préparées avec paramètres liés pour éviter les injections SQL."
        },
        {
            "id": "SAST-002",
            "category": "Exécution dynamique de code (eval/exec)",
            "severity": Severity.HAUTE,
            "confidence": Confidence.HIGH,
            "extensions": {".py", ".js", ".ts", ".php"},
            "pattern": r"\b(eval|exec)\s*\(",
            "recommendation": "Évitez l'utilisation de eval() ou exec(). Privilégiez des structures de données dynamiques sécurisées."
        },
        {
            "id": "SAST-003",
            "category": "Algorithme de hachage obsolète / faible (MD5/SHA1)",
            "severity": Severity.MOYENNE,
            "confidence": Confidence.MEDIUM,
            "extensions": {".py", ".js", ".ts", ".php", ".java"},
            "pattern": r"(?i)\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)",
            "recommendation": "Utilisez des algorithmes modernes et sûrs comme SHA-256, SHA-3, ou Argon2 / bcrypt pour les mots de passe."
        },
        {
            "id": "SAST-004",
            "category": "Désactivation de la vérification TLS/SSL",
            "severity": Severity.HAUTE,
            "confidence": Confidence.HIGH,
            "extensions": {".py", ".js", ".ts"},
            "pattern": r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false",
            "recommendation": "Conservez la vérification des certificats TLS pour empêcher les attaques de type Man-in-the-Middle (MitM)."
        },
        {
            "id": "SAST-005",
            "category": "Rendu HTML brut non sécurisé (dangerouslySetInnerHTML / innerHTML)",
            "severity": Severity.MOYENNE,
            "confidence": Confidence.MEDIUM,
            "extensions": {".js", ".jsx", ".ts", ".tsx", ".html"},
            "pattern": r"dangerouslySetInnerHTML|\.innerHTML\s*=",
            "recommendation": "Assurez-vous de neutraliser/échapper le contenu utilisateur avant de l'insérer directement dans le DOM."
        },
        {
            "id": "SAST-006",
            "category": "Mode Débogage Actif en Production",
            "severity": Severity.BASSE,
            "confidence": Confidence.LOW,
            "extensions": {".py", ".env", ".json", ".yaml", ".yml"},
            "pattern": r"(?i)DEBUG\s*=\s*True|app\.debug\s*=\s*True",
            "recommendation": "Désactivez le mode de débogage en environnement de production."
        }
    ]

    def analyze(self, directory: Path, exclusion_mgr: Optional[ExclusionManager] = None) -> List[Finding]:
        findings: List[Finding] = []
        if not directory.exists():
            return findings

        if exclusion_mgr is None:
            exclusion_mgr = ExclusionManager(directory)

        for path in directory.rglob("*"):
            if path.is_file() and not exclusion_mgr.should_ignore_path(path):
                self._analyze_file(path, directory, findings, exclusion_mgr)

        return findings

    def _analyze_file(self, file_path: Path, root_path: Path, findings: List[Finding], exclusion_mgr: ExclusionManager):
        ext = file_path.suffix.lower()
        applicable_rules = [r for r in self.RULES if ext in r["extensions"] and not exclusion_mgr.should_ignore_rule(r["id"])]
        if not applicable_rules:
            return

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line_idx, line in enumerate(lines, start=1):
                clean_line = line.strip()

                if clean_line.startswith("#") or clean_line.startswith("//") or ExclusionManager.has_inline_ignore(line):
                    continue

                for rule in applicable_rules:
                    if re.search(rule["pattern"], line):
                        relative_file = str(file_path.relative_to(root_path))
                        findings.append(Finding(
                            id=rule["id"],
                            title="Code Non Sécurisé (SAST)",
                            category=rule["category"],
                            severity=rule["severity"],
                            confidence=rule["confidence"],
                            file=relative_file,
                            line=line_idx,
                            snippet=clean_line[:120],
                            recommendation=rule["recommendation"],
                            source="SASTLinter"
                        ))
        except Exception:
            pass
