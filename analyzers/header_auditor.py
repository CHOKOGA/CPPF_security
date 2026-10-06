"""
Module d'audit passif des en-têtes HTTP de sécurité et des cookies.
Interroge une application ou API web locale (ex: http://localhost:8000) et évalue sa configuration de sécurité réseau.
"""
from typing import Dict, Any, List
import httpx

class HeaderAuditor:
    """Analyse passive des en-têtes de réponse HTTP et des attributs de cookies."""

    RECOMMENDED_HEADERS = {
        "Content-Security-Policy": {
            "severity": "HAUTE",
            "description": "Protection contre les attaques XSS et les injections de scripts.",
            "recommendation": "Définissez une politique CSP restrictive (ex: default-src 'self')."
        },
        "X-Frame-Options": {
            "severity": "MOYENNE",
            "description": "Protection contre l'inclusion dans des iframes (Clickjacking).",
            "recommendation": "Définissez X-Frame-Options à DENY ou SAMEORIGIN."
        },
        "X-Content-Type-Options": {
            "severity": "BASSE",
            "description": "Empêche le navigateur d'interpréter les fichiers différemment du Content-Type annoncé.",
            "recommendation": "Ajoutez l'en-tête X-Content-Type-Options: nosniff."
        },
        "Referrer-Policy": {
            "severity": "BASSE",
            "description": "Contrôle les informations de référence transmises lors des navigations vers d'autres pages.",
            "recommendation": "Définissez Referrer-Policy à strict-origin-when-cross-origin ou no-referrer."
        },
        "Permissions-Policy": {
            "severity": "BASSE",
            "description": "Restreint l'accès aux fonctionnalités du navigateur (caméra, géolocalisation, etc.).",
            "recommendation": "Configurez Permissions-Policy pour limiter les fonctionnalités non utilisées."
        }
    }

    SENSITIVE_SERVER_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]

    @classmethod
    def audit_target(cls, target_url: str, timeout: float = 5.0) -> List[Dict[str, Any]]:
        """Effectue une requête GET passive et vérifie la présence et les valeurs des en-têtes."""
        findings = []

        try:
            with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
                response = client.get(target_url)

            headers = response.headers

            # 1. Vérification des en-têtes de sécurité manquants
            for header_name, meta in cls.RECOMMENDED_HEADERS.items():
                # HSTS est pertinent uniquement sur HTTPS
                if header_name == "Strict-Transport-Security" and not target_url.lower().startswith("https"):
                    continue

                if not any(h.lower() == header_name.lower() for h in headers.keys()):
                    findings.append({
                        "type": "En-tête de Sécurité Manquant",
                        "severity": meta["severity"],
                        "category": f"En-tête HTTP : {header_name}",
                        "target": target_url,
                        "evidence": f"En-tête '{header_name}' absente de la réponse HTTP.",
                        "recommendation": meta["recommendation"]
                    })

            # 2. Vérification de l'exposition d'en-têtes d'information serveur
            for s_header in cls.SENSITIVE_SERVER_HEADERS:
                val = headers.get(s_header)
                if val:
                    findings.append({
                        "type": "Divulgation d'Informations Serveur",
                        "severity": "BASSE",
                        "category": f"Divulgation d'en-tête : {s_header}",
                        "target": target_url,
                        "evidence": f"En-tête exposée '{s_header}: {val}'",
                        "recommendation": f"Masquez l'en-tête '{s_header}' dans la configuration du serveur web ou du framework."
                    })

            # 3. Vérification de la configuration CORS permissive
            cors_origin = headers.get("Access-Control-Allow-Origin")
            cors_creds = headers.get("Access-Control-Allow-Credentials")
            if cors_origin == "*" and cors_creds == "true":
                findings.append({
                    "type": "Configuration CORS Risquée",
                    "severity": "HAUTE",
                    "category": "CORS Misconfiguration",
                    "target": target_url,
                    "evidence": "Access-Control-Allow-Origin est '*' avec Access-Control-Allow-Credentials = true.",
                    "recommendation": "Spécifiez une origine explicite au lieu de '*' lorsque la gestion des identifiants (cookies/tokens) est activée."
                })

            # 4. Audit des cookies de session
            cookies = response.cookies
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
                    findings.append({
                        "type": "Attributs de Cookie Insuffisants",
                        "severity": "MOYENNE",
                        "category": f"Cookie : {cookie_name}",
                        "target": target_url,
                        "evidence": f"Cookie '{cookie_name}' manque les drapeaux : {', '.join(missing_flags)}",
                        "recommendation": "Configurez tous les cookies de session avec les attributs HttpOnly, Secure (sur HTTPS) et SameSite=Lax/Strict."
                    })

        except Exception as e:
            findings.append({
                "type": "Erreur de Connexion à la Cible",
                "severity": "INFO",
                "category": "Connexion HTTP",
                "target": target_url,
                "evidence": str(e),
                "recommendation": "Vérifiez que l'application tourne bien localement à l'adresse indiquée."
            })

        return findings
