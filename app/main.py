import hmac
import hashlib
from fastapi import FastAPI, Header, Request, HTTPException
from app.sonarqube.client import SonarQubeClient
from app.adapter.sonar import SonarAdapter
from app.settings import SONAR_WEBHOOK_SECRET
from app.defectdojo.client import DefectDojoClient
from app.storage import mark_processed, is_processed
import json


app = FastAPI()

sonar_client = SonarQubeClient()
sonar_adapter = SonarAdapter()
dd_client = DefectDojoClient()

def verify_sonar_signature(payload: bytes, signature: str):
    if not SONAR_WEBHOOK_SECRET:
        return True
    
    expected = hmac.new(
        SONAR_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.post("/api/v1/sonar/webhook")
async def sonar_webhook(
    request: Request,
    x_sonar_webhook_hmac_sha256: str = Header(None)
):
    body = await request.body()
    
    if x_sonar_webhook_hmac_sha256:
        if not verify_sonar_signature(body, x_sonar_webhook_hmac_sha256):
            raise HTTPException(status_code=401, detail="Invalid HMAC signature")

    data = await request.json()
    if data.get("status") != "SUCCESS":
        return {"status": "ignored", "reason": "Analysis status != SUCCESS"}

    project_key = data["project"]["key"]
    properties = data.get("properties", {})
    
    storage_key = f"sonar:{project_key}:{data['taskId']}"
    if is_processed(storage_key):
        return {"status": "skipped"}

    # Топаем в сонар
    issues = await sonar_client.get_vulnerabilities(project_key)

    # 4. Трансформация и отправка в DefectDojo
    payload = sonar_adapter.normalize(issues, properties)
    await dd_client.import_scan(payload)
    
    mark_processed(storage_key)
    return {"status": "ok"}