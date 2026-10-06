"""
Gestionnaire d'exclusions et de règles d'ignoration (.devsecignore et commentaires inline).
"""
import fnmatch
from pathlib import Path
from typing import List, Set, Optional

class ExclusionManager:
    """Gère l'exclusion de fichiers, répertoires et règles spécifiques."""

    DEFAULT_IGNORES = {
        ".git", "venv", ".venv", "node_modules", "dist", "build",
        ".pytest_cache", "__pycache__", ".idea", ".vscode"
    }

    def __init__(self, root_dir: Path, ignore_file: str = ".devsecignore"):
        self.root_dir = root_dir.resolve()
        self.ignore_patterns: Set[str] = set(self.DEFAULT_IGNORES)
        self.ignored_rules: Set[str] = set()
        
        self._load_ignore_file(self.root_dir / ignore_file)

    def _load_ignore_file(self, ignore_path: Path):
        """Lit et interprète le fichier .devsecignore s'il existe."""
        if not ignore_path.exists():
            return

        try:
            with open(ignore_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if not clean or clean.startswith("#"):
                        continue
                    
                    if clean.startswith("rule:"):
                        # Ignorer une règle spécifique (ex: rule:SAST-001)
                        rule_id = clean.split("rule:")[1].strip()
                        self.ignored_rules.add(rule_id)
                    else:
                        # Nettoyer les slashes finaux
                        pattern = clean.rstrip("/")
                        self.ignore_patterns.add(pattern)
        except Exception:
            pass

    def should_ignore_path(self, path: Path) -> bool:
        """Vérifie si un chemin de fichier/dossier doit être ignoré."""
        try:
            relative_path = path.relative_to(self.root_dir)
            relative_parts = relative_path.parts
        except ValueError:
            relative_parts = path.parts

        for part in relative_parts:
            if part in self.ignore_patterns:
                return True

        relative_str = str(relative_path) if 'relative_path' in locals() else str(path)
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(relative_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True

        return False

    def should_ignore_rule(self, rule_id: Optional[str]) -> bool:
        """Vérifie si une règle d'analyse spécifique a été désactivée."""
        if not rule_id:
            return False
        return rule_id in self.ignored_rules

    @staticmethod
    def has_inline_ignore(line_content: str) -> bool:
        """Vérifie la présence d'un commentaire d'ignoration inline (ex: # devsec-ignore ou # nosec)."""
        lower = line_content.lower()
        return "devsec-ignore" in lower or "nosec" in lower or "fmt: skip" in lower
