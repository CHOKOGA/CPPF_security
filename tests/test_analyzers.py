"""
Tests unitaires pour DevSecAssist.
"""
from pathlib import Path
from utils.target_detector import TargetDetector
from utils.risk_calculator import RiskCalculator
from utils.exclusion_manager import ExclusionManager
from analyzers.secret_scanner import SecretScanner
from analyzers.sast_linter import SASTLinter
from analyzers.config_auditor import ConfigAuditor
from reporting.json_reporter import JSONReporter, SARIFReporter

def test_secret_scanner(tmp_path: Path):
    test_file = tmp_path / "config.py"
    test_file.write_text("AWS_KEY = 'AKIA1234567890123456'\n", encoding="utf-8")
    
    findings = SecretScanner.scan_directory(tmp_path)
    assert len(findings) >= 1
    assert findings[0]["category"] == "Clé d'API AWS"

def test_inline_ignore(tmp_path: Path):
    test_file = tmp_path / "config.py"
    # Ligne ignorée via # devsec-ignore
    test_file.write_text("AWS_KEY = 'AKIA1234567890123456' # devsec-ignore\n", encoding="utf-8")
    
    findings = SecretScanner.scan_directory(tmp_path)
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
    
    findings = SASTLinter.analyze_directory(tmp_path)
    assert len(findings) >= 1
    assert "SAST-001" in [f["id"] for f in findings]

def test_config_auditor(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET_KEY=123456\n", encoding="utf-8")
    
    findings = ConfigAuditor.audit_project(tmp_path)
    assert len(findings) >= 1
    assert findings[0]["type"] == "Fichier .env Décelé dans le Répertoire"

def test_risk_calculator():
    findings = [
        {"type": "Secret Exposé", "category": "AWS", "severity": "HAUTE", "file": "app.py", "line": 10},
        {"type": "Secret Exposé", "category": "AWS", "severity": "HAUTE", "file": "app.py", "line": 10}, # Doublon
        {"type": "Config", "category": "Env", "severity": "MOYENNE", "file": ".env", "line": 1}
    ]
    unique = RiskCalculator.deduplicate_findings(findings)
    assert len(unique) == 2

    score, grade, stats = RiskCalculator.calculate_score(unique)
    assert score == 78
    assert "B" in grade

def test_sarif_reporter(tmp_path: Path):
    sarif_file = tmp_path / "results.sarif"
    findings = [{"type": "Secret", "category": "AWS", "severity": "HAUTE", "file": "main.py", "line": 5}]
    SARIFReporter.generate_report(findings, sarif_file)
    assert sarif_file.exists()
    assert "2.1.0" in sarif_file.read_text(encoding="utf-8")
