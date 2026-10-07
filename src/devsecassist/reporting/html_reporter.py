"""
Module de génération de rapports HTML clairs et synthétiques (HTMLReporter).
"""
from pathlib import Path
from jinja2 import Template
from devsecassist.models import ScanResult

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Audit de Sécurité Local - DevSecAssist</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --high-color: #ef4444;
            --med-color: #f59e0b;
            --low-color: #3b82f6;
            --info-color: #10b981;
            --border-color: #334155;
        }

        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            background-color: var(--card-bg);
            padding: 2rem;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        h1 {
            margin: 0 0 0.5rem 0;
            color: #38bdf8;
            font-size: 2rem;
        }

        .subtitle {
            color: var(--text-secondary);
            margin: 0;
        }

        .score-box {
            text-align: center;
            background: rgba(15, 23, 42, 0.6);
            padding: 1rem 1.5rem;
            border-radius: 10px;
            border: 2px solid #38bdf8;
        }

        .score-val {
            font-size: 2.5rem;
            font-weight: bold;
            color: #38bdf8;
        }

        .grade-badge {
            font-size: 1rem;
            font-weight: 600;
            color: #f8fafc;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            background: #3b82f6;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .summary-card {
            background-color: var(--card-bg);
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            text-align: center;
        }

        .summary-card .number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-top: 0.5rem;
        }

        .number.high { color: var(--high-color); }
        .number.med { color: var(--med-color); }
        .number.low { color: var(--low-color); }
        .number.total { color: var(--text-primary); }

        .finding-card {
            background-color: var(--card-bg);
            border-radius: 8px;
            border-left: 6px solid var(--border-color);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border-top: 1px solid var(--border-color);
            border-right: 1px solid var(--border-color);
            border-bottom: 1px solid var(--border-color);
        }

        .finding-card.HAUTE { border-left-color: var(--high-color); }
        .finding-card.MOYENNE { border-left-color: var(--med-color); }
        .finding-card.BASSE { border-left-color: var(--low-color); }
        .finding-card.INFO { border-left-color: var(--info-color); }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }

        .finding-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0;
        }

        .badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
            text-transform: uppercase;
        }

        .badge.HAUTE { background-color: rgba(239, 68, 68, 0.2); color: var(--high-color); }
        .badge.MOYENNE { background-color: rgba(245, 158, 11, 0.2); color: var(--med-color); }
        .badge.BASSE { background-color: rgba(59, 130, 246, 0.2); color: var(--low-color); }
        .badge.INFO { background-color: rgba(16, 185, 129, 0.2); color: var(--info-color); }

        .badge-conf {
            background-color: rgba(255, 255, 255, 0.1);
            color: #cbd5e1;
            font-size: 0.75rem;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            margin-left: 0.5rem;
        }

        .meta {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }

        .code-block {
            background-color: #090d16;
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.9rem;
            color: #cbd5e1;
            overflow-x: auto;
            margin-bottom: 1rem;
        }

        .recommendation {
            background-color: rgba(56, 189, 248, 0.1);
            border-left: 3px solid #38bdf8;
            padding: 0.75rem 1rem;
            border-radius: 0 6px 6px 0;
            font-size: 0.95rem;
        }

        footer {
            text-align: center;
            margin-top: 3rem;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ Rapport DevSecAssist v0.3.0</h1>
                <p class="subtitle">Assistant de Sécurité Local pour Développeurs (Web, Mobile, API)</p>
                <p style="margin-top: 0.5rem; font-size: 0.9rem;">Projet analysé : <code>{{ result.target }}</code></p>
            </div>
            <div class="score-box">
                <div style="font-size: 0.9rem; color: var(--text-secondary);">Score de Sécurité</div>
                <div class="score-val">{{ result.score }}/100</div>
                <div class="grade-badge">{{ result.risk_grade }}</div>
            </div>
        </header>

        <div class="summary-grid">
            <div class="summary-card">
                <div>Haute Sévérité</div>
                <div class="number high">{{ result.stats.high }}</div>
            </div>
            <div class="summary-card">
                <div>Moyenne Sévérité</div>
                <div class="number med">{{ result.stats.med }}</div>
            </div>
            <div class="summary-card">
                <div>Basse Sévérité</div>
                <div class="number low">{{ result.stats.low }}</div>
            </div>
            <div class="summary-card">
                <div>Total Alertes</div>
                <div class="number total">{{ result.stats.total }}</div>
            </div>
        </div>

        <h2>Résultats de l'Audit Normalisés</h2>

        {% if not result.findings %}
            <div class="finding-card INFO">
                <p>✨ Aucune alerte de sécurité détectée ! Le projet respecte les règles vérifiées.</p>
            </div>
        {% endif %}

        {% for finding in result.findings %}
            <div class="finding-card {{ finding.severity.value }}">
                <div class="finding-header">
                    <h3 class="finding-title">
                        {{ finding.title }} - {{ finding.category }}
                        <span class="badge-conf">Confiance : {{ finding.confidence.value }}</span>
                    </h3>
                    <span class="badge {{ finding.severity.value }}">{{ finding.severity.value }}</span>
                </div>
                
                <div class="meta">
                    {% if finding.file %}
                        📍 Fichier : <code>{{ finding.file }}</code> {% if finding.line %}(Ligne {{ finding.line }}){% endif %}
                    {% endif %}
                    {% if finding.target %}
                        🌐 Cible HTTP : <code>{{ finding.target }}</code>
                    {% endif %}
                </div>

                {% if finding.snippet or finding.evidence %}
                    <div class="code-block">
                        {{ finding.snippet or finding.evidence }}
                    </div>
                {% endif %}

                <div class="recommendation">
                    💡 <strong>Conseil de Correction :</strong> {{ finding.recommendation }}
                </div>
            </div>
        {% endfor %}

        <footer>
            Généré automatiquement par DevSecAssist v0.3.0
        </footer>
    </div>
</body>
</html>
"""

class HTMLReporter:
    """Génère le rapport HTML à partir du ScanResult."""

    @classmethod
    def generate_report(cls, scan_result: ScanResult, output_path: Path):
        template = Template(HTML_TEMPLATE)
        html_content = template.render(result=scan_result)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
