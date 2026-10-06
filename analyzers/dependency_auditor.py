"""
Module d'audit des dépendances et manifests (requirements.txt, package.json).
"""
import json
from pathlib import Path
from typing import List, Dict, Any

class DependencyAuditor:
    """Audite les fichiers de manifeste de dépendances pour détecter les mauvaises pratiques de gestion de packages."""

    KNOWN_INSECURE_PACKAGES = {
        "pycrypto": "Le package 'pycrypto' n'est plus maintenu et contient des vulnérabilités. Utilisez 'pycryptodome' ou 'cryptography'.",
        "node-serialize": "Le package 'node-serialize' est vulnérable à la désérialisation de code arbitraire.",
        "eval": "Le package npm 'eval' exécute du code dynamique non sécurisé.",
    }

    IGNORE_DIRS = {".git", "venv", ".venv", "node_modules", "dist", "build"}

    @classmethod
    def audit_dependencies(cls, directory: Path) -> List[Dict[str, Any]]:
        """Scanne le répertoire à la recherche de manifests de dépendances."""
        findings = []

        if not directory.exists():
            return findings

        cls._audit_requirements_txt(directory, findings)
        cls._audit_package_json(directory, findings)

        return findings

    @classmethod
    def _audit_requirements_txt(cls, root: Path, findings: List[Dict[str, Any]]):
        req_files = list(root.glob("**/requirements*.txt"))
        for req in req_files:
            if any(p in req.parts for p in cls.IGNORE_DIRS):
                continue
            try:
                with open(req, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                relative = str(req.relative_to(root))
                for line_idx, line in enumerate(lines, start=1):
                    clean_line = line.strip()
                    if not clean_line or clean_line.startswith("#"):
                        continue

                    pkg_name = clean_line.split("==")[0].split(">=")[0].split("<=")[0].strip().lower()

                    # 1. Verification de packages obsolètes/risqués
                    if pkg_name in cls.KNOWN_INSECURE_PACKAGES:
                        findings.append({
                            "type": "Dépendance Risquée ou Obsolète",
                            "severity": "HAUTE",
                            "category": f"Package Python : {pkg_name}",
                            "file": relative,
                            "line": line_idx,
                            "evidence": f"Ligne : {clean_line}",
                            "recommendation": cls.KNOWN_INSECURE_PACKAGES[pkg_name]
                        })

                    # 2. Dépendances non verrouillées (absence d'opérateur ==)
                    if "==" not in clean_line and not clean_line.startswith("-r") and not clean_line.startswith("-e"):
                        findings.append({
                            "type": "Version de Dépendance Non Fixée",
                            "severity": "BASSE",
                            "category": f"Package Python : {pkg_name}",
                            "file": relative,
                            "line": line_idx,
                            "evidence": f"Version non figée : '{clean_line}'",
                            "recommendation": "Verrouillez les versions de vos dépendances avec '==' (ex: requests==2.31.0) pour garantir la reproductibilité et éviter les régressions de sécurité."
                        })
            except Exception:
                pass

    @classmethod
    def _audit_package_json(cls, root: Path, findings: List[Dict[str, Any]]):
        pkg_files = list(root.glob("**/package.json"))
        for pkg_file in pkg_files:
            if any(p in pkg_file.parts for p in cls.IGNORE_DIRS):
                continue
            try:
                with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)

                relative = str(pkg_file.relative_to(root))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

                for pkg_name, version in deps.items():
                    pkg_lower = pkg_name.lower()
                    if pkg_lower in cls.KNOWN_INSECURE_PACKAGES:
                        findings.append({
                            "type": "Dépendance NPM Risquée",
                            "severity": "HAUTE",
                            "category": f"Package NPM : {pkg_name}",
                            "file": relative,
                            "evidence": f"Package '{pkg_name}': '{version}'",
                            "recommendation": cls.KNOWN_INSECURE_PACKAGES[pkg_lower]
                        })

                    # Vérification des versions jocker "*"
                    if version == "*" or version == "latest":
                        findings.append({
                            "type": "Version NPM Floue (* / latest)",
                            "severity": "BASSE",
                            "category": f"Package NPM : {pkg_name}",
                            "file": relative,
                            "evidence": f"Version déclarée : '{version}'",
                            "recommendation": "Spécifiez une version exacte ou une plage sémantique maîtrisée au lieu de '*' ou 'latest'."
                        })
            except Exception:
                pass
