"""
Interface de base pour tous les analyseurs de sécurité de DevSecAssist.
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional
from devsecassist.models import Finding
from devsecassist.utils.exclusion_manager import ExclusionManager

class BaseAnalyzer(ABC):
    """Classe abstraite de référence pour les analyseurs de sécurité."""

    @abstractmethod
    def analyze(self, directory: Path, exclusion_mgr: Optional[ExclusionManager] = None) -> List[Finding]:
        """Méthode d'exécution d'analyse qui renvoie une liste d'objets Finding."""
        pass
