"""
Module d'audit de configuration (ConfigAuditor).
"""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional
from devsecassist.models import Finding, Severity, Confidence
from devsecassist.utils.exclusion_manager import ExclusionManager
from devsecassist.analyzers.base import BaseAnalyzer

class ConfigAuditor(BaseAnalyzer):
    """Analyse les configurations de projets web et mobiles."""

    def analyze(self, directory: Path, exclusion_mgr: Optional[ExclusionManager] = None) -> List[Finding]:
        findings: List[Finding] = []
        if not directory.exists():
            return findings

        if exclusion_mgr is None:
            exclusion_mgr = ExclusionManager(directory)

        self._audit_env_files(directory, findings, exclusion_mgr)
        self._audit_android_manifests(directory, findings, exclusion_mgr)
        self._audit_ios_plists(directory, findings, exclusion_mgr)
        self._audit_dockerfiles(directory, findings, exclusion_mgr)

        return findings

    def _audit_env_files(self, root: Path, findings: List[Finding], exclusion_mgr: ExclusionManager):
        env_files = list(root.glob("**/.env*"))
        for env_file in env_files:
            if exclusion_mgr.should_ignore_path(env_file):
                continue
            if env_file.name == ".env":
                relative = str(env_file.relative_to(root))
                findings.append(Finding(
                    id="CFG-001",
                    title="Fichier .env Décelé dans le Répertoire",
                    category="Fichier de Configuration Sensible",
                    severity=Severity.MOYENNE,
                    confidence=Confidence.HIGH,
                    file=relative,
                    evidence="Fichier .env présent dans le répertoire de travail.",
                    recommendation="Assurez-vous que le fichier .env est listé dans le fichier .gitignore pour éviter son commit dans le contrôle de version.",
                    source="ConfigAuditor"
                ))

    def _audit_android_manifests(self, root: Path, findings: List[Finding], exclusion_mgr: ExclusionManager):
        manifests = list(root.glob("**/AndroidManifest.xml"))
        for manifest in manifests:
            if exclusion_mgr.should_ignore_path(manifest):
                continue

            try:
                tree = ET.parse(manifest)
                xml_root = tree.getroot()
                relative = str(manifest.relative_to(root))
                ns = "{http://schemas.android.com/apk/res/android}"

                application = xml_root.find("application")
                if application is not None:
                    allow_backup = application.attrib.get(f"{ns}allowBackup")
                    if allow_backup == "true":
                        findings.append(Finding(
                            id="CFG-002",
                            title="Configuration Mobile Sécurité Faible",
                            category="Android Manifest : allowBackup",
                            severity=Severity.MOYENNE,
                            confidence=Confidence.HIGH,
                            file=relative,
                            evidence="android:allowBackup='true'",
                            recommendation="Définissez android:allowBackup='false' pour empêcher la sauvegarde des données privées via ADB.",
                            source="ConfigAuditor"
                        ))

                    cleartext = application.attrib.get(f"{ns}usesCleartextTraffic")
                    if cleartext == "true":
                        findings.append(Finding(
                            id="CFG-003",
                            title="Transmission HTTP en Clair Autorisée",
                            category="Android Manifest : usesCleartextTraffic",
                            severity=Severity.HAUTE,
                            confidence=Confidence.HIGH,
                            file=relative,
                            evidence="android:usesCleartextTraffic='true'",
                            recommendation="Désactivez la transmission HTTP en clair pour forcer l'usage du protocole HTTPS.",
                            source="ConfigAuditor"
                        ))

                    for comp in application.findall("activity") + application.findall("service") + application.findall("receiver"):
                        exported = comp.attrib.get(f"{ns}exported")
                        name = comp.attrib.get(f"{ns}name", "Composant")
                        if exported == "true":
                            permission = comp.attrib.get(f"{ns}permission")
                            if not permission:
                                findings.append(Finding(
                                    id="CFG-004",
                                    title="Composant Android Exporté Sans Protection",
                                    category="Android Manifest : Exported Component",
                                    severity=Severity.HAUTE,
                                    confidence=Confidence.MEDIUM,
                                    file=relative,
                                    evidence=f"Composant '{name}' est exporté (exported='true') sans permission requise.",
                                    recommendation="Associez une permission explicite ou passez exported='false'.",
                                    source="ConfigAuditor"
                                ))
            except Exception:
                pass

    def _audit_ios_plists(self, root: Path, findings: List[Finding], exclusion_mgr: ExclusionManager):
        plists = list(root.glob("**/Info.plist"))
        for plist in plists:
            if exclusion_mgr.should_ignore_path(plist):
                continue
            try:
                with open(plist, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                relative = str(plist.relative_to(root))
                if "NSAllowsArbitraryLoads" in content and "<true/>" in content:
                    findings.append(Finding(
                        id="CFG-005",
                        title="Configuration ATS Permissive (iOS)",
                        category="iOS Info.plist : App Transport Security",
                        severity=Severity.HAUTE,
                        confidence=Confidence.HIGH,
                        file=relative,
                        evidence="NSAllowsArbitraryLoads est activé (true).",
                        recommendation="Désactivez NSAllowsArbitraryLoads pour obliger toutes les connexions réseau à respecter HTTPS.",
                        source="ConfigAuditor"
                    ))
            except Exception:
                pass

    def _audit_dockerfiles(self, root: Path, findings: List[Finding], exclusion_mgr: ExclusionManager):
        dockerfiles = list(root.glob("**/Dockerfile*"))
        for df in dockerfiles:
            if exclusion_mgr.should_ignore_path(df):
                continue
            try:
                with open(df, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                relative = str(df.relative_to(root))
                has_user_instruction = any(line.strip().startswith("USER ") for line in lines)
                if not has_user_instruction:
                    findings.append(Finding(
                        id="CFG-006",
                        title="Exécution en tant que Root dans le Container",
                        category="Dockerfile : Absence d'instruction USER",
                        severity=Severity.MOYENNE,
                        confidence=Confidence.HIGH,
                        file=relative,
                        evidence="Aucune directive 'USER <non-root>' trouvée dans le Dockerfile.",
                        recommendation="Spécifiez un utilisateur non privilégié avec la directive USER.",
                        source="ConfigAuditor"
                    ))
            except Exception:
                pass
