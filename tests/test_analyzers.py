"""
Tests unitaires pour DevSecAssist v0.3.0.
"""
from pathlib import Path
from devsecassist.models import Severity, Confidence, Finding, ScanResult
from devsecassist.utils.target_detector import TargetDetector
from devsecassist.utils.risk_calculator import RiskCalculator
from devsecassist.utils.exclusion_manager import ExclusionManager
from devsecassist.analyzers.secret_scanner import SecretScanner
from devsecassist.analyzers.sast_linter import SASTLinter
from devsecassist.analyzers.config_auditor import ConfigAuditor
from devsecassist.engine import ScanEngine
from devsecassist.reporting.json_reporter import JSONReporter, SARIFReporter

def test_secret_scanner(tmp_path: Path):
    test_file = tmp_path / "config.py"
    test_file.write_text("AWS_KEY = 'AKIA1234567890123456'\n", encoding="utf-8")
    
    scanner = SecretScanner()
    findings = scanner.analyze(tmp_path)
    assert len(findings) >= 1
    assert findings[0].category == "Clé d'API AWS"
    assert findings[0].severity == Severity.HAUTE

def test_inline_ignore(tmp_path: Path):
    test_file = tmp_path / "config.py"
    test_file.write_text("AWS_KEY = 'AKIA1234567890123456' # devsec-ignore\n", encoding="utf-8")
    
    scanner = SecretScanner()
    findings = scanner.analyze(tmp_path)
    assert len(findings) == 0

def test_devsecignore_file(tmp_path: Path):
    ignore_file = tmp_path / ".devsecignore"
    ignore_file.write_text("ignored_folder/\nrule:SAST-001\n", encoding="utf-8")

    mgr = ExclusionManager(tmp_path)
    assert mgr.should_ignore_path(tmp_path / "ignored_folder" / "app.py") is True
    assert mgr.should_ignore_rule("SAST-001") is True

def test_sast_linter(tmp_path: Path):
    test_file = tmp_path / "app.py"
    test_file.write_text("query = f'SELECT * FROM users WHERE name = {user_input}'\n", encoding="utf-8")
    
    linter = SASTLinter()
    findings = linter.analyze(tmp_path)
    assert len(findings) >= 1
    assert "SAST-001" in [f.id for f in findings]

def test_config_auditor(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET_KEY=123456\n", encoding="utf-8")
    
    auditor = ConfigAuditor()
    findings = auditor.analyze(tmp_path)
    assert len(findings) >= 1
    assert findings[0].title == "Fichier .env Décelé dans le Répertoire"

def test_scan_engine(tmp_path: Path):
    test_file = tmp_path / "app.py"
    test_file.write_text("AWS_KEY = 'AKIA1234567890123456'\n", encoding="utf-8")
    
    engine = ScanEngine(tmp_path)
    result = engine.run_scan()
    assert isinstance(result, ScanResult)
    assert len(result.findings) >= 1
    assert result.score < 100

def test_sarif_reporter(tmp_path: Path):
    sarif_file = tmp_path / "results.sarif"
    findings = [Finding(
        id="SEC-001",
        title="Secret Exposé",
        category="AWS",
        severity=Severity.HAUTE,
        confidence=Confidence.HIGH,
        file="main.py",
        line=5,
        recommendation="Fix it"
    )]
    result = ScanResult(target=str(tmp_path), findings=findings)
    SARIFReporter.generate_report(result, sarif_file)
    assert sarif_file.exists()
    assert "2.1.0" in sarif_file.read_text(encoding="utf-8")
