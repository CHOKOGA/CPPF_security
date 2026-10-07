"""
Moteur d'orchestration de scan de sécurité (ScanEngine).
"""
from pathlib import Path
from typing import Optional, List

from devsecassist.models import Finding, ScanResult
from devsecassist.utils.exclusion_manager import ExclusionManager
from devsecassist.utils.risk_calculator import RiskCalculator
from devsecassist.analyzers.secret_scanner import SecretScanner
from devsecassist.analyzers.sast_linter import SASTLinter
from devsecassist.analyzers.header_auditor import HeaderAuditor
from devsecassist.analyzers.config_auditor import ConfigAuditor
from devsecassist.analyzers.dependency_auditor import DependencyAuditor

class ScanEngine:
    """Orchestrateur central des moteurs d'analyse de sécurité."""

    def __init__(self, target_dir: Path, ignore_file: str = ".devsecignore"):
        self.target_dir = target_dir.resolve()
        self.exclusion_mgr = ExclusionManager(self.target_dir, ignore_file=ignore_file)

    def run_scan(self, url: Optional[str] = None) -> ScanResult:
        """Exécute tous les analyseurs, déduplique les résultats et calcule le score."""
        raw_findings: List[Finding] = []

        # 1. Secret Scanner
        secret_scanner = SecretScanner()
        raw_findings.extend(secret_scanner.analyze(self.target_dir, self.exclusion_mgr))

        # 2. SAST Linter
        sast_linter = SASTLinter()
        raw_findings.extend(sast_linter.analyze(self.target_dir, self.exclusion_mgr))

        # 3. Config Auditor
        config_auditor = ConfigAuditor()
        raw_findings.extend(config_auditor.analyze(self.target_dir, self.exclusion_mgr))

        # 4. Dependency Auditor
        dep_auditor = DependencyAuditor()
        raw_findings.extend(dep_auditor.analyze(self.target_dir, self.exclusion_mgr))

        # 5. Header Auditor (si URL fournie)
        if url:
            raw_findings.extend(HeaderAuditor.audit_target(url))

        # Déduplication et Calcul du score
        unique_findings = RiskCalculator.deduplicate_findings(raw_findings)
        score, grade, stats = RiskCalculator.calculate_score(unique_findings)

        target_name = str(self.target_dir if not url else url)

        return ScanResult(
            target=target_name,
            findings=unique_findings,
            score=score,
            risk_grade=grade,
            stats=stats
        )
