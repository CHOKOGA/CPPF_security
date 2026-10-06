"""
Module de linter de code statique (SAST - Static Application Security Testing).
Identifie les règles de codage non sécurisées dans le code source (Python, JavaScript/TypeScript, PHP, HTML).
"""
import re
from pathlib import Path
from typing import List, Dict, Any

class SASTLinter:
    """Effectue l'analyse statique du code source pour repérer des modèles risqués."""

    RULES = [
        {
            "id": "SAST-001",
            "category": "Concaténation SQL potentiellement risquée",
            "severity": "HAUTE",
            "extensions": {".py", ".js", ".ts", ".php", ".java"},
            "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+|f[\"'].*?(SELECT|INSERT|UPDATE|DELETE)|(SELECT|INSERT|UPDATE|DELETE)\s+.*?%",
            "recommendation": "Utilisez systématiquement des requêtes préparées avec paramètres liés pour éviter les injections SQL."
        },
        {
            "id": "SAST-002",
            "category": "Exécution dynamique de code (eval/exec)",
            "severity": "HAUTE",
            "extensions": {".py", ".js", ".ts", ".php"},
            "pattern": r"\b(eval|exec)\s*\(",
            "recommendation": "Évitez l'utilisation de eval() ou exec(). Privilégiez des structures de données dynamiques sécurisées."
        },
        {
            "id": "SAST-003",
            "category": "Algorithme de hachage obsolète / faible (MD5/SHA1)",
            "severity": "MOYENNE",
            "extensions": {".py", ".js", ".ts", ".php", ".java"},
            "pattern": r"(?i)\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)",
            "recommendation": "Utilisez des algorithmes modernes et sûrs comme SHA-256, SHA-3, ou Argon2 / bcrypt pour les mots de passe."
        },
        {
            "id": "SAST-004",
            "category": "Désactivation de la vérification TLS/SSL",
            "severity": "HAUTE",
            "extensions": {".py", ".js", ".ts"},
            "pattern": r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false",
            "recommendation": "Conservez la vérification des certificats TLS pour empêcher les attaques de type Man-in-the-Middle (MitM)."
        },
        {
            "id": "SAST-005",
            "category": "Rendu HTML brut non sécurisé (dangerouslySetInnerHTML / innerHTML)",
            "severity": "MOYENNE",
            "extensions": {".js", ".jsx", ".ts", ".tsx", ".html"},
            "pattern": r"dangerouslySetInnerHTML|\.innerHTML\s*=",
            "recommendation": "Assurez-vous de neutraliser/échapper le contenu utilisateur avant de l'insérer directement dans le DOM."
        },
        {
            "id": "SAST-006",
            "category": "Mode Débogage Actif en Production",
            "severity": "BASSE",
            "extensions": {".py", ".env", ".json", ".yaml", ".yml"},
            "pattern": r"(?i)DEBUG\s*=\s*True|app\.debug\s*=\s*True",
            "recommendation": "Désactivez le mode de débogage en environnement de production."
        }
    ]

    IGNORE_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build"}

    @classmethod
    def analyze_directory(cls, directory: Path) -> List[Dict[str, Any]]:
        """Analyse le code source d'un projet à la recherche de modèles non sécurisés."""
        findings = []

        if not directory.exists():
            return findings

        for path in directory.rglob("*"):
            if path.is_file() and not any(part in cls.IGNORE_DIRS for part in path.parts):
                cls._analyze_file(path, directory, findings)

        return findings

    @classmethod
    def _analyze_file(cls, file_path: Path, root_path: Path, findings: List[Dict[str, Any]]):
        ext = file_path.suffix.lower()
        applicable_rules = [r for r in cls.RULES if ext in r["extensions"]]
        if not applicable_rules:
            return

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line_idx, line in enumerate(lines, start=1):
                for rule in applicable_rules:
                    if re.search(rule["pattern"], line):
                        relative_file = str(file_path.relative_to(root_path))
                        findings.append({
                            "id": rule["id"],
                            "type": "Code Non Sécurisé (SAST)",
                            "severity": rule["severity"],
                            "category": rule["category"],
                            "file": relative_file,
                            "line": line_idx,
                            "snippet": line.strip()[:120],
                            "recommendation": rule["recommendation"]
                        })
        except Exception:
            pass
