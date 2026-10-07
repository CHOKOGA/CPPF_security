"""
Module de détection de secrets et clés d'accès exposées (SecretScanner).
"""
import re
from pathlib import Path
from typing import List, Optional
from devsecassist.models import Finding, Severity, Confidence
from devsecassist.utils.exclusion_manager import ExclusionManager
from devsecassist.analyzers.base import BaseAnalyzer

class SecretScanner(BaseAnalyzer):
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

    EXACT_PLACEHOLDERS = {
        "AKIAIOSFODNN7EXAMPLE", "YOUR_API_KEY", "SECRET_KEY", "CHANGE_ME",
        "MY_SECRET", "DUMMY_TOKEN", "TEST_KEY", "YOUR_SECRET_HERE"
    }

    IGNORE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".pyc", ".exe", ".so", ".dll", ".sarif"}

    def analyze(self, directory: Path, exclusion_mgr: Optional[ExclusionManager] = None) -> List[Finding]:
        findings: List[Finding] = []
        if not directory.exists():
            return findings

        if exclusion_mgr is None:
            exclusion_mgr = ExclusionManager(directory)

        for path in directory.rglob("*"):
            if path.is_file():
                if exclusion_mgr.should_ignore_path(path):
                    continue
                if path.suffix.lower() in self.IGNORE_EXTENSIONS:
                    continue

                self._scan_file(path, directory, findings, exclusion_mgr)

        return findings

    def _scan_file(self, file_path: Path, root_path: Path, findings: List[Finding], exclusion_mgr: ExclusionManager):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line_idx, line in enumerate(lines, start=1):
                if ExclusionManager.has_inline_ignore(line):
                    continue

                for label, pattern in self.PATTERNS.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        matched_str = match.group(0)

                        if matched_str in self.EXACT_PLACEHOLDERS or "EXAMPLE" in matched_str.upper():
                            continue

                        masked = matched_str[:4] + "..." + matched_str[-4:] if len(matched_str) > 8 else "***"
                        relative_file = str(file_path.relative_to(root_path))

                        findings.append(Finding(
                            id="SEC-001",
                            title="Secret Exposé",
                            category=label,
                            severity=Severity.HAUTE,
                            confidence=Confidence.HIGH,
                            file=relative_file,
                            line=line_idx,
                            snippet=line.strip()[:120],
                            evidence=f"Secret masqué : {masked}",
                            recommendation="Stockez les clés et secrets dans des variables d'environnement sécurisées et ne les commitez jamais dans le code source.",
                            source="SecretScanner"
                        ))
        except Exception:
            pass
