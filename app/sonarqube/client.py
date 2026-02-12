import httpx
from app.settings import SONAR_URL, SONAR_TOKEN, REQUEST_TIMEOUT

class SonarQubeClient:
    async def get_vulnerabilities(self, project_key: str):
        url = f"{SONAR_URL}/api/issues/search"
        params = {
            "componentKeys": project_key,
            "types": "VULNERABILITY,BUG",
            "statuses": "OPEN,REOPENED",
            "ps": 500
        }

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            r = await client.get(url, params=params, auth=(SONAR_TOKEN, ""))
            if not r.is_success:
                raise Exception(f"Error fetching issues: {r.status_code} - {r.text}")
            data = r.json()
            return data.get("issues", [])
