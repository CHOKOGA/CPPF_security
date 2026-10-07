"""
Module d'audit des dépendances (DependencyAuditor).
"""
import json
from pathlib import Path
from typing import List, Optional
from devsecassist.models import Finding, Severity, Confidence
from devsecassist.utils.exclusion_manager import ExclusionManager
from devsecassist.analyzers.base import BaseAnalyzer

class DependencyAuditor(BaseAnalyzer):
    """Audite les fichiers de manifeste de dépendances."""

    KNOWN_INSECURE_PACKAGES = {
        "pycrypto": "Le package 'pycrypto' n'est plus maintenu et contient des vulnérabilités. Utilisez 'pycryptodome' ou 'cryptography'.",
        "node-serialize": "Le package 'node-serialize' est vulnérable à la désérialisation de code arbitraire.",
        "eval": "Le package npm 'eval' exécute du code dynamique non sécurisé.",
    }

    def analyze(self, directory: Path, exclusion_mgr: Optional[ExclusionManager] = None) -> List[Finding]:
        findings: List[Finding] = []
        if not directory.exists():
            return findings

        if exclusion_mgr is None:
            exclusion_mgr = ExclusionManager(directory)

        self._audit_requirements_txt(directory, findings, exclusion_mgr)
        self._audit_package_json(directory, findings, exclusion_mgr)

        return findings

    def _audit_requirements_txt(self, root: Path, findings: List[Finding], exclusion_mgr: ExclusionManager):
        req_files = list(root.glob("**/requirements*.txt"))
        for req in req_files:
            if exclusion_mgr.should_ignore_path(req):
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

                    if pkg_name in self.KNOWN_INSECURE_PACKAGES:
                        findings.append(Finding(
                            id="DEP-001",
                            title="Dépendance Risquée ou Obsolète",
                            category=f"Package Python : {pkg_name}",
                            severity=Severity.HAUTE,
                            confidence=Confidence.HIGH,
                            file=relative,
                            line=line_idx,
                            evidence=f"Ligne : {clean_line}",
                            recommendation=self.KNOWN_INSECURE_PACKAGES[pkg_name],
                            source="DependencyAuditor"
                        ))

                    if "==" not in clean_line and not clean_line.startswith("-r") and not clean_line.startswith("-e"):
                        findings.append(Finding(
                            id="DEP-002",
                            title="Version de Dépendance Non Fixée",
                            category=f"Package Python : {pkg_name}",
                            severity=Severity.BASSE,
                            confidence=Confidence.HIGH,
                            file=relative,
                            line=line_idx,
                            evidence=f"Version non figée : '{clean_line}'",
                            recommendation="Verrouillez les versions de vos dépendances avec '==' (ex: requests==2.31.0).",
                            source="DependencyAuditor"
                        ))
            except Exception:
                pass

    def _audit_package_json(self, root: Path, findings: List[Finding], exclusion_mgr: ExclusionManager):
        pkg_files = list(root.glob("**/package.json"))
        for pkg_file in pkg_files:
            if exclusion_mgr.should_ignore_path(pkg_file):
                continue
            try:
                with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)

                relative = str(pkg_file.relative_to(root))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

                for pkg_name, version in deps.items():
                    pkg_lower = pkg_name.lower()
                    if pkg_lower in self.KNOWN_INSECURE_PACKAGES:
                        findings.append(Finding(
                            id="DEP-003",
                            title="Dépendance NPM Risquée",
                            category=f"Package NPM : {pkg_name}",
                            severity=Severity.HAUTE,
                            confidence=Confidence.HIGH,
                            file=relative,
                            evidence=f"Package '{pkg_name}': '{version}'",
                            recommendation=self.KNOWN_INSECURE_PACKAGES[pkg_lower],
                            source="DependencyAuditor"
                        ))

                    if version == "*" or version == "latest":
                        findings.append(Finding(
                            id="DEP-004",
                            title="Version NPM Floue (* / latest)",
                            category=f"Package NPM : {pkg_name}",
                            severity=Severity.BASSE,
                            confidence=Confidence.HIGH,
                            file=relative,
                            evidence=f"Version déclarée : '{version}'",
                            recommendation="Spécifiez une version exacte ou une plage sémantique maîtrisée au lieu de '*' ou 'latest'.",
                            source="DependencyAuditor"
                        ))
            except Exception:
                pass
