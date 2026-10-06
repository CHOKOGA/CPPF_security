"""
Tests unitaires pour DevSecAssist.
"""
from pathlib import Path
from utils.target_detector import TargetDetector
from analyzers.secret_scanner import SecretScanner
from analyzers.sast_linter import SASTLinter
from analyzers.config_auditor import ConfigAuditor

def test_secret_scanner(tmp_path: Path):
    test_file = tmp_path / "config.py"
    test_file.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    
    findings = SecretScanner.scan_directory(tmp_path)
    assert len(findings) >= 1
    assert findings[0]["category"] == "Clé d'API AWS"

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
