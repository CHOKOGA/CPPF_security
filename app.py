"""
API Web FastAPI pour DevSecAssist (Service Web Public / Microservice de Sécurité).
"""
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_PATH = PROJECT_ROOT / "src"
if SRC_PATH.exists() and str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Query, Depends
from fastapi.responses import HTMLResponse, JSONResponse

from devsecassist.engine import ScanEngine
from devsecassist.reporting.html_reporter import HTMLReporter
from devsecassist.reporting.json_reporter import SARIFReporter

app = FastAPI(
    title="DevSecAssist Web API",
    description="Service API d'audit de sécurité local pour développeurs (SAST, Secret Scanning, Config & En-têtes HTTP)",
    version="0.3.0"
)

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Vérification optionnelle de la clé d'API si configurée dans la variable d'environnement API_KEY."""
    expected_key = os.getenv("API_KEY")
    if expected_key and x_api_key != expected_key:
        raise HTTPException(status_code=401, detail="Accès non autorisé : Clé API invalide ou manquante.")

@app.get("/")
def root():
    """Point d'entrée public du service pour éviter le 404 à la racine."""
    return {
        "status": "ok",
        "service": "DevSecAssist API",
        "version": "0.3.0",
        "health": "/health",
        "docs": "/docs",
        "scan_url": "/scan/url",
        "scan_file": "/scan/file",
    }

@app.get("/health")
def health_check():
    """Endpoint de santé pour Render / Railway / Docker."""
    return {"status": "ok", "service": "DevSecAssist API", "version": "0.3.0"}

@app.get("/scan/url")
def scan_url(
    url: str = Query(..., description="URL de l'application locale ou du service web (ex: http://localhost:8000)"),
    format: str = Query("json", enum=["json", "html"]),
    dependencies: None = Depends(verify_api_key)
):
    """Effectue un audit passif d'en-têtes HTTP et cookies sur une URL."""
    temp_dir = Path(tempfile.mkdtemp())
    try:
        engine = ScanEngine(target_dir=temp_dir)
        scan_result = engine.run_scan(url=url)

        if format == "html":
            html_content = HTMLReporter.render_html(scan_result)
            return HTMLResponse(content=html_content)
        
        return scan_result.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    format: str = Query("json", enum=["json", "html", "sarif"]),
    dependencies: None = Depends(verify_api_key)
):
    """
    Reçoit un fichier de code (ou archive .zip de projet), lance le scan de sécurité et retourne le rapport.
    """
    temp_dir = Path(tempfile.mkdtemp())
    try:
        file_location = temp_dir / file.filename
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        scan_dir = temp_dir / "project"
        scan_dir.mkdir(exist_ok=True)

        # Si c'est une archive ZIP, l'extraire
        if file.filename.endswith(".zip"):
            with zipfile.ZipFile(file_location, 'r') as zip_ref:
                zip_ref.extractall(scan_dir)
        else:
            # Sinon, copier le fichier simple dans le dossier de scan
            shutil.copy(file_location, scan_dir / file.filename)

        engine = ScanEngine(target_dir=scan_dir)
        scan_result = engine.run_scan()

        if format == "html":
            html_content = HTMLReporter.render_html(scan_result)
            return HTMLResponse(content=html_content)
        elif format == "sarif":
            sarif_path = temp_dir / "report.sarif"
            SARIFReporter.generate_report(scan_result, sarif_path)
            sarif_text = sarif_path.read_text(encoding="utf-8")
            return HTMLResponse(content=sarif_text, media_type="application/json")

        return scan_result.to_dict()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur d'analyse : {str(e)}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
