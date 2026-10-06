"""
Générateur de rapports au format JSON et SARIF (Standard OASIS pour CI/CD et GitHub Security).
"""
import json
from pathlib import Path
from typing import List, Dict, Any

class JSONReporter:
    """Exportation des alertes de sécurité au format JSON structuré."""

    @staticmethod
    def generate_report(target: str, score: int, grade: str, stats: Dict[str, int], findings: List[Dict[str, Any]], output_path: Path):
        data = {
            "tool": "DevSecAssist",
            "version": "0.2.0",
            "target": target,
            "summary": {
                "security_score": score,
                "risk_grade": grade,
                "stats": stats
            },
            "findings": findings
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


class SARIFReporter:
    """Exportation au format SARIF v2.1.0 pour intégration native GitHub Code Scanning."""

    @staticmethod
    def generate_report(findings: List[Dict[str, Any]], output_path: Path):
        rules = []
        results = []
        rule_ids = set()

        severity_map = {
            "HAUTE": "error",
            "MOYENNE": "warning",
            "BASSE": "note",
            "INFO": "note"
        }

        for idx, f in enumerate(findings):
            rule_id = f.get("id", f"DEVSEC-{idx+1:03d}")
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f.get("category", "Security Check"),
                    "shortDescription": {"text": f.get("type", "Security Finding")},
                    "help": {"text": f.get("recommendation", "")}
                })

            result = {
                "ruleId": rule_id,
                "level": severity_map.get(f.get("severity"), "warning"),
                "message": {"text": f"{f.get('type')}: {f.get('category')} - {f.get('evidence', '')}"},
                "locations": []
            }

            file_path = f.get("file")
            if file_path:
                result["locations"].append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": f.get("line", 1)}
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
                            "version": "0.2.0",
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
