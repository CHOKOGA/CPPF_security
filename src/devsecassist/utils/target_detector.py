"""
Détecteur de type de cible et de projet.
"""
from pathlib import Path
from typing import Dict, Any

class TargetDetector:
    """Détecte les caractéristiques d'un projet local ou d'un endpoint."""

    @staticmethod
    def detect_project_type(project_path: Path) -> Dict[str, Any]:
        """Examine un répertoire local pour identifier les stacks web, mobile ou API."""
        detected = {
            "is_web": False,
            "is_mobile": False,
            "is_api": False,
            "stacks": [],
            "files_found": []
        }

        if not project_path.exists() or not project_path.is_dir():
            return detected

        indicators = {
            "package.json": ("Web/NodeJS", "is_web"),
            "requirements.txt": ("Python App", "is_web"),
            "pyproject.toml": ("Python App", "is_web"),
            "pom.xml": ("Java App", "is_web"),
            "build.gradle": ("Android/Java App", "is_mobile"),
            "AndroidManifest.xml": ("Android Mobile", "is_mobile"),
            "Info.plist": ("iOS Mobile", "is_mobile"),
            "Dockerfile": ("Docker Container", "is_web"),
            "swagger.json": ("API Spec", "is_api"),
            "openapi.yaml": ("API Spec", "is_api"),
            "openapi.json": ("API Spec", "is_api"),
        }

        for file_name, (stack_name, category) in indicators.items():
            matches = list(project_path.glob(f"**/{file_name}"))
            valid_matches = [m for m in matches if not any(p in m.parts for p in ["venv", ".venv", "node_modules", ".git", "dist", "build"])]
            if valid_matches:
                detected[category] = True
                detected["stacks"].append(stack_name)
                detected["files_found"].extend([str(m.relative_to(project_path)) for m in valid_matches[:3]])

        detected["stacks"] = list(set(detected["stacks"]))
        return detected
