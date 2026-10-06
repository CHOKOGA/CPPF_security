"""
Module d'audit de fichiers de configuration (Mobile Android/iOS, Docker, Fichiers d'environnement).
"""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any

class ConfigAuditor:
    """Analyse les configurations de projets web et mobiles pour identifier des faiblesses."""

    IGNORE_DIRS = {".git", "venv", ".venv", "node_modules", "dist", "build"}

    @classmethod
    def audit_project(cls, directory: Path) -> List[Dict[str, Any]]:
        """Scanne les fichiers de configuration du projet."""
        findings = []

        if not directory.exists():
            return findings

        cls._audit_env_files(directory, findings)
        cls._audit_android_manifests(directory, findings)
        cls._audit_ios_plists(directory, findings)
        cls._audit_dockerfiles(directory, findings)

        return findings

    @classmethod
    def _audit_env_files(cls, root: Path, findings: List[Dict[str, Any]]):
        """Détecte si des fichiers .env sont enregistrés dans le dépôt."""
        env_files = list(root.glob("**/.env*"))
        for env_file in env_files:
            if any(p in env_file.parts for p in cls.IGNORE_DIRS):
                continue
            
            # Si le fichier s'appelle exactement .env (et non .env.example)
            if env_file.name == ".env":
                relative = str(env_file.relative_to(root))
                findings.append({
                    "type": "Fichier .env Décelé dans le Répertoire",
                    "severity": "MOYENNE",
                    "category": "Fichier de Configuration Sensible",
                    "file": relative,
                    "evidence": "Fichier .env présent dans le répertoire de travail.",
                    "recommendation": "Assurez-vous que le fichier .env est listé dans le fichier .gitignore pour éviter son commit dans le contrôle de version."
                })

    @classmethod
    def _audit_android_manifests(cls, root: Path, findings: List[Dict[str, Any]]):
        """Audite les fichiers AndroidManifest.xml des projets mobiles Android."""
        manifests = list(root.glob("**/AndroidManifest.xml"))
        for manifest in manifests:
            if any(p in manifest.parts for p in cls.IGNORE_DIRS):
                continue

            try:
                tree = ET.parse(manifest)
                xml_root = tree.getroot()
                relative = str(manifest.relative_to(root))

                # Espace de noms Android
                ns = "{http://schemas.android.com/apk/res/android}"

                application = xml_root.find("application")
                if application is not None:
                    # 1. Verification allowBackup
                    allow_backup = application.attrib.get(f"{ns}allowBackup")
                    if allow_backup == "true":
                        findings.append({
                            "type": "Configuration Mobile Sécurité Faible",
                            "severity": "MOYENNE",
                            "category": "Android Manifest : allowBackup",
                            "file": relative,
                            "evidence": "android:allowBackup='true'",
                            "recommendation": "Définissez android:allowBackup='false' pour empêcher la sauvegarde non autorisée des données privées de l'application via ADB."
                        })

                    # 2. Verification usesCleartextTraffic
                    cleartext = application.attrib.get(f"{ns}usesCleartextTraffic")
                    if cleartext == "true":
                        findings.append({
                            "type": "Transmission HTTP en Clair Autorisée",
                            "severity": "HAUTE",
                            "category": "Android Manifest : usesCleartextTraffic",
                            "file": relative,
                            "evidence": "android:usesCleartextTraffic='true'",
                            "recommendation": "Désactivez la transmission HTTP en clair en passant la valeur à 'false' pour forcer l'usage du protocole HTTPS."
                        })

                    # 3. Composants exportés sans permission
                    for comp in application.findall("activity") + application.findall("service") + application.findall("receiver"):
                        exported = comp.attrib.get(f"{ns}exported")
                        name = comp.attrib.get(f"{ns}name", "Composant")
                        if exported == "true":
                            permission = comp.attrib.get(f"{ns}permission")
                            if not permission:
                                findings.append({
                                    "type": "Composant Android Exporté Sans Protection",
                                    "severity": "HAUTE",
                                    "category": "Android Manifest : Exported Component",
                                    "file": relative,
                                    "evidence": f"Composant '{name}' est exporté (exported='true') sans permission requise.",
                                    "recommendation": "Associez une permission explicite ou passez exported='false' si le composant n'a pas besoin d'être appelé par d'autres applications."
                                })
            except Exception:
                pass

    @classmethod
    def _audit_ios_plists(cls, root: Path, findings: List[Dict[str, Any]]):
        """Audite les fichiers Info.plist des projets iOS."""
        plists = list(root.glob("**/Info.plist"))
        for plist in plists:
            if any(p in plist.parts for p in cls.IGNORE_DIRS):
                continue
            try:
                with open(plist, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                relative = str(plist.relative_to(root))
                if "NSAllowsArbitraryLoads" in content and "<true/>" in content:
                    findings.append({
                        "type": "Configuration ATS Permissive (iOS)",
                        "severity": "HAUTE",
                        "category": "iOS Info.plist : App Transport Security",
                        "file": relative,
                        "evidence": "NSAllowsArbitraryLoads est activé (true).",
                        "recommendation": "Désactivez NSAllowsArbitraryLoads pour obliger toutes les connexions réseau à respecter les normes HTTPS sécurisées (ATS)."
                    })
            except Exception:
                pass

    @classmethod
    def _audit_dockerfiles(cls, root: Path, findings: List[Dict[str, Any]]):
        """Audite la configuration des Dockerfile."""
        dockerfiles = list(root.glob("**/Dockerfile*"))
        for df in dockerfiles:
            if any(p in df.parts for p in cls.IGNORE_DIRS):
                continue
            try:
                with open(df, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                relative = str(df.relative_to(root))
                has_user_instruction = any(line.strip().startswith("USER ") for line in lines)
                if not has_user_instruction:
                    findings.append({
                        "type": "Exécution en tant que Root dans le Container",
                        "severity": "MOYENNE",
                        "category": "Dockerfile : Absence d'instruction USER",
                        "file": relative,
                        "evidence": "Aucune directive 'USER <non-root>' trouvée dans le Dockerfile.",
                        "recommendation": "Spécifiez un utilisateur non priviligié avec la directive USER (ex: USER node ou USER appuser) pour respecter le principe du moindre privilège."
                    })
            except Exception:
                pass
