# 🛡️ DevSecAssist - Assistant de Sécurité Local pour Développeurs

**DevSecAssist** est une application Python modulaire conçue pour aider les développeurs à identifier et corriger les faiblesses de sécurité dans leurs projets **Web, Mobiles (Android/iOS) et API** avant le déploiement.

L'outil adopte une approche **défensive et passive** (SAST, Secret Scanning, Configuration Auditing, Header Auditing) garantissant une exécution sûre sans risque d'impact sur l'environnement de développement local.

---

## 🚀 Fonctionnalités

1. **Analyse Statique du Code (SAST)** :
   - Détection des requêtes SQL dynamiques/concaténées.
   - Utilisation de fonctions risquées (`eval()`, `exec()`).
   - Algorithmes de hachage obsolètes (`MD5`, `SHA1`).
   - Injection HTML brute (`innerHTML`, `dangerouslySetInnerHTML`).

2. **Détection de Secrets (Secret Scanning)** :
   - Clés d'API (AWS, Slack, GitHub).
   - Jetons JWT et clés privées RSA.
   - Mots de passe et chaînes de connexion codés en dur.

3. **Audit des Configurations (Web, Mobile, Containers)** :
   - Présence de fichiers `.env` non ignorés.
   - Mobile Android : `allowBackup`, `usesCleartextTraffic`, composants exportés non protégés.
   - Mobile iOS : `NSAllowsArbitraryLoads` (ATS).
   - Docker : Absence d'instruction `USER` (exécution root).

4. **Audit des Dépendances (SCA)** :
   - Détection de packages obsolètes ou vulnérables connus (`pycrypto`, `node-serialize`).
   - Versions non verrouillées.

5. **Audit Passif HTTP / Cookies** :
   - Vérification des en-têtes HTTP de sécurité (`CSP`, `X-Frame-Options`, `Referrer-Policy`).
   - Audit des attributs de cookies (`HttpOnly`, `Secure`, `SameSite`).

6. **Rapports HTML Interactifs** :
   - Génération d'un rapport clair catégorisé par sévérité avec conseils de correction guidés.

---

## 🛠️ Installation

```bash
# 1. Cloner le projet
cd CPPF_security

# 2. Installer les dépendances
pip install -r requirements.txt
```

---

## 💻 Utilisation

### Analyser le répertoire du projet courant :
```bash
python cli.py --path .
```

### Analyser le projet + l'application en cours d'exécution locale :
```bash
python cli.py --path . --url http://localhost:8000
```

### Exécuter les tests unitaires :
```bash
pytest tests/
```
