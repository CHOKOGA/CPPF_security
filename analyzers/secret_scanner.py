"""
Module de détection de secrets et clés d'accès exposées dans le code source et les configurations.
"""
import re
from pathlib import Path
from typing import List, Dict, Any

class SecretScanner:
    """Analyseur de secrets et données sensibles codées en dur."""

    PATTERNS = {
        "Clé d'API AWS": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "Clé Privée RSA/PEM": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
        "Jeton JWT (JSON Web Token)": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "Clé d'API Slack": r"xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "Clé d'API GitHub": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "Mot de passe en clair / Secret (assignation)": r"(?i)(password|passwd|secret|api_key|apikey|access_token)\s*[:=]\s*[\"']([^\"']{8,})[\"']",
        "Chaîne de connexion Base de données": r"(?i)(mongodb|postgres|postgresql|mysql|redis)://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_.-]+:[0-9]+",
    }

    IGNORE_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", ".pytest_cache", "dist", "build"}
    IGNORE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".pyc", ".exe", ".so", ".dll"}

    @classmethod
    def scan_directory(cls, directory: Path) -> List[Dict[str, Any]]:
        """Parcourt un dossier et recherche d'éventuels secrets exposés."""
        findings = []

        if not directory.exists():
            return findings

        for path in directory.rglob("*"):
            if path.is_file():
                # Ignorer répertoires et extensions non pertinents
                if any(part in cls.IGNORE_DIRS for part in path.parts):
                    continue
                if path.suffix.lower() in cls.IGNORE_EXTENSIONS:
                    continue

                cls._scan_file(path, directory, findings)

        return findings

    @classmethod
    def _scan_file(cls, file_path: Path, root_path: Path, findings: List[Dict[str, Any]]):
        """Analyse un fichier ligne par ligne à la recherche de secrets."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line_idx, line in enumerate(lines, start=1):
                for label, pattern in cls.PATTERNS.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        matched_str = match.group(0)
                        # Masquer partiellement le secret trouvé pour des raisons d'affichage
                        masked = matched_str[:4] + "..." + matched_str[-4:] if len(matched_str) > 8 else "***"
                        
                        relative_file = str(file_path.relative_to(root_path))
                        findings.append({
                            "type": "Secret Exposé",
                            "severity": "HAUTE",
                            "category": label,
                            "file": relative_file,
                            "line": line_idx,
                            "snippet": line.strip()[:120],
                            "evidence": f"Secret masqué : {masked}",
                            "recommendation": "Stockez les clés et secrets dans des variables d'environnement sécurisées et ne les commitez jamais dans le code source."
                        })
        except Exception:
            pass
