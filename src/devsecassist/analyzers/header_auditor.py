"""
Module d'audit passif des en-têtes HTTP de sécurité et cookies (HeaderAuditor).
"""
from typing import List
import httpx
from devsecassist.models import Finding, Severity, Confidence

class HeaderAuditor:
    """Analyse passive des en-têtes de réponse HTTP et des attributs de cookies."""

    RECOMMENDED_HEADERS = {
        "Content-Security-Policy": {
            "severity": Severity.HAUTE,
            "confidence": Confidence.HIGH,
            "description": "Protection contre les attaques XSS et les injections de scripts.",
            "recommendation": "Définissez une politique CSP restrictive (ex: default-src 'self')."
        },
        "X-Frame-Options": {
            "severity": Severity.MOYENNE,
            "confidence": Confidence.HIGH,
            "description": "Protection contre l'inclusion dans des iframes (Clickjacking).",
            "recommendation": "Définissez X-Frame-Options à DENY ou SAMEORIGIN."
        },
        "X-Content-Type-Options": {
            "severity": Severity.BASSE,
            "confidence": Confidence.HIGH,
            "description": "Empêche le navigateur d'interpréter les fichiers différemment du Content-Type annoncé.",
            "recommendation": "Ajoutez l'en-tête X-Content-Type-Options: nosniff."
        },
        "Referrer-Policy": {
            "severity": Severity.BASSE,
            "confidence": Confidence.HIGH,
            "description": "Contrôle les informations de référence transmises lors des navigations vers d'autres pages.",
            "recommendation": "Définissez Referrer-Policy à strict-origin-when-cross-origin ou no-referrer."
        },
        "Permissions-Policy": {
            "severity": Severity.BASSE,
            "confidence": Confidence.HIGH,
            "description": "Restreint l'accès aux fonctionnalités du navigateur (caméra, géolocalisation, etc.).",
            "recommendation": "Configurez Permissions-Policy pour limiter les fonctionnalités non utilisées."
        }
    }

    SENSITIVE_SERVER_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]

    @classmethod
    def audit_target(cls, target_url: str, timeout: float = 5.0) -> List[Finding]:
        findings: List[Finding] = []

        try:
            with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
                response = client.get(target_url)

            headers = response.headers

            for header_name, meta in cls.RECOMMENDED_HEADERS.items():
                if header_name == "Strict-Transport-Security" and not target_url.lower().startswith("https"):
                    continue

                if not any(h.lower() == header_name.lower() for h in headers.keys()):
                    findings.append(Finding(
                        id="HDR-001",
                        title="En-tête de Sécurité Manquant",
                        category=f"En-tête HTTP : {header_name}",
                        severity=meta["severity"],
                        confidence=meta["confidence"],
                        target=target_url,
                        evidence=f"En-tête '{header_name}' absente de la réponse HTTP.",
                        recommendation=meta["recommendation"],
                        source="HeaderAuditor"
                    ))

            for s_header in cls.SENSITIVE_SERVER_HEADERS:
                val = headers.get(s_header)
                if val:
                    findings.append(Finding(
                        id="HDR-002",
                        title="Divulgation d'Informations Serveur",
                        category=f"Divulgation d'en-tête : {s_header}",
                        severity=Severity.BASSE,
                        confidence=Confidence.HIGH,
                        target=target_url,
                        evidence=f"En-tête exposée '{s_header}: {val}'",
                        recommendation=f"Masquez l'en-tête '{s_header}' dans la configuration du serveur web.",
                        source="HeaderAuditor"
                    ))

            cors_origin = headers.get("Access-Control-Allow-Origin")
            cors_creds = headers.get("Access-Control-Allow-Credentials")
            if cors_origin == "*" and cors_creds == "true":
                findings.append(Finding(
                    id="HDR-003",
                    title="Configuration CORS Risquée",
                    category="CORS Misconfiguration",
                    severity=Severity.HAUTE,
                    confidence=Confidence.HIGH,
                    target=target_url,
                    evidence="Access-Control-Allow-Origin est '*' avec Access-Control-Allow-Credentials = true.",
                    recommendation="Spécifiez une origine explicite au lieu de '*' lorsque la gestion des identifiants est activée.",
                    source="HeaderAuditor"
                ))

            for cookie in response.headers.get_list("set-cookie"):
                cookie_str = str(cookie).lower()
                cookie_name = cookie_str.split("=")[0] if "=" in cookie_str else "cookie"
                
                missing_flags = []
                if "httponly" not in cookie_str:
                    missing_flags.append("HttpOnly")
                if "samesite" not in cookie_str:
                    missing_flags.append("SameSite")
                if target_url.startswith("https") and "secure" not in cookie_str:
                    missing_flags.append("Secure")

                if missing_flags:
                    findings.append(Finding(
                        id="HDR-004",
                        title="Attributs de Cookie Insuffisants",
                        category=f"Cookie : {cookie_name}",
                        severity=Severity.MOYENNE,
                        confidence=Confidence.HIGH,
                        target=target_url,
                        evidence=f"Cookie '{cookie_name}' manque les drapeaux : {', '.join(missing_flags)}",
                        recommendation="Configurez tous les cookies de session avec les attributs HttpOnly, Secure et SameSite=Lax/Strict.",
                        source="HeaderAuditor"
                    ))

        except Exception as e:
            findings.append(Finding(
                id="HDR-ERR",
                title="Erreur de Connexion à la Cible",
                category="Connexion HTTP",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                target=target_url,
                evidence=str(e),
                recommendation="Vérifiez que l'application tourne bien localement à l'adresse indiquée.",
                source="HeaderAuditor"
            ))

        return findings
