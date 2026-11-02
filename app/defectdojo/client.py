# app/defectdojo/client.py
import json
import httpx
import logging

logger = logging.getLogger(__name__)

class DefectDojoClient:

    def _git_base(self):
        from app.settings import GIT_DOMAIN
        if GIT_DOMAIN.startswith("http"):
            return GIT_DOMAIN.rstrip("/")
        return f"https://{GIT_DOMAIN}"

    def _replace_locations(self, report: dict, project_key: str, branch: str) -> dict:
        """
        Формирует прямую ссылку на уязвимость в SonarQube.

        Используем собственный URL SonarQube, который ведёт на конкретный
        файл, строку и проект, а не на GitLab/GitHub. Приоритет отдаём ключу
        инцидента (permalink вида project/issues?id=...&open=...), в противном
        случае строим ссылку на просмотр кода в ветке.
        """
        from app.settings import SONAR_URL

        sonar_base = (SONAR_URL or "").rstrip("/")

        # Внутри data находятся 'findings'
        for finding in report.get("findings", []):
            file_path = finding.get("file_path")
            line = finding.get("line", 1)
            issue_key = finding.get("sonar_issue_key")

            if issue_key:
                # Прямая ссылка на конкретный инцидент (файл + строка + проект)
                location_url = (
                    f"{sonar_base}/project/issues"
                    f"?id={project_key}&open={issue_key}"
                )
            elif file_path and not file_path.startswith("http"):
                # Фолбэк: просмотр кода в ветке, на конкретной строке
                location_url = (
                    f"{sonar_base}/code"
                    f"?id={project_key}&branch={branch}"
                    f"&selected={project_key}:{file_path}&line={line}"
                )
            else:
                continue

            finding["file_path"] = location_url

        return report


    async def import_scan(self, payload: dict):
        # Обрабатываем секцию findings
        report_data = self._replace_locations(payload["file"], payload.get("sonar_project_key", ""), payload.get("branch_tag", "main"))

        data = {
            "scan_type": payload["scan_type"],
            "product_type_name": payload["product_type_name"],
            "product_name": payload["product_name"],
            "engagement_name": payload["engagement_name"],
            "branch_tag": payload.get("branch_tag", "main"),
            "commit_hash": payload.get("commit_hash", ""),
            "source_code_management_uri": f"{self._git_base()}/{payload['product_name']}",
            "auto_create_context": "true",
            "close_old_findings": "true",
            "close_old_findings_product_scope": "true",
            "deduplication_on_engagement": "true",
        }

        # Generic Findings Import ожидает JSON файл с корнем {"findings": [...]}
        files = {
            "file": ("report.json", json.dumps(report_data), "application/json")
        }

        from app.settings import DD_URL, DD_TOKEN, REQUEST_TIMEOUT

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            try:
                r = await client.post(
                    f"{DD_URL}/api/v2/import-scan/",
                    headers={"Authorization": f"Token {DD_TOKEN}"},
                    data=data,
                    files=files,
                )
                if r.status_code not in [200, 201]:
                    logger.error(f"DefectDojo error: {r.status_code} - {r.text}")
                    raise RuntimeError(f"DefectDojo returned {r.status_code}")
                
                print(f"[DefectDojoClient] Successfully imported to {payload['product_name']}")
                return r.json()
            except httpx.RequestError as exc:
                logger.error(f"Connection error to DefectDojo: {str(exc)}")
                raise RuntimeError(f"Could not reach DefectDojo")