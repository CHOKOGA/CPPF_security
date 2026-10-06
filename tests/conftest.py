import sys
from pathlib import Path

# Ajouter la racine du projet au sys.path pour les tests pytest
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
