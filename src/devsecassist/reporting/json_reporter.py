"""
Générateur de rapports JSON et SARIF v2.1.0 à partir d'objets ScanResult typés.
"""
import json
from pathlib import Path
from devsecassist.models import ScanResult, Severity

class JSONReporter:
    """Exportation au format JSON structuré."""

    @staticmethod
    def generate_report(scan_result: ScanResult, output_path: Path):
        data = {
            "tool": "DevSecAssist",
            "version": "0.3.0",
            "summary": {
                "target": scan_result.target,
                "security_score": scan_result.score,
                "risk_grade": scan_result.risk_grade,
                "stats": scan_result.stats
            },
            "findings": [f.to_dict() for f in scan_result.findings]
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


class SARIFReporter:
    """Exportation au format SARIF v2.1.0 (Standard OASIS pour GitHub Code Scanning)."""

    @staticmethod
    def generate_report(scan_result: ScanResult, output_path: Path):
        rules = []
        results = []
        rule_ids = set()

        severity_map = {
            Severity.HAUTE: "error",
            Severity.MOYENNE: "warning",
            Severity.BASSE: "note",
            Severity.INFO: "note"
        }

        for idx, f in enumerate(scan_result.findings):
            rule_id = f.id or f"DEVSEC-{idx+1:03d}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f.category or "Security Check",
                    "shortDescription": {"text": f.title},
                    "help": {"text": f.recommendation}
                })

            result = {
                "ruleId": rule_id,
                "level": severity_map.get(f.severity, "warning"),
                "message": {"text": f"{f.title}: {f.category} - {f.evidence or ''}"},
                "locations": []
            }

            if f.file:
                result["locations"].append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line or 1}
                    }
                })

            results.append(result)

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DevSecAssist",
                            "version": "0.3.0",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)
