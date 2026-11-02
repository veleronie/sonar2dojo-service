import json
import logging
import httpx
from app.settings import SONAR_URL, SONAR_TOKEN, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)

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

            # Логируем полный отчёт, полученный от API SonarQube
            logger.info("[SonarQube] Full API report for project '%s': %s",
                        project_key, json.dumps(data, ensure_ascii=False))

            issues = data.get("issues", [])

            # Обогащаем каждый issue сниппетом исходного кода (api/sources/show)
            for issue in issues:
                component = issue.get("component")
                if not component:
                    continue

                start_line, end_line = self._resolve_line_range(issue)
                if start_line is None:
                    continue

                try:
                    lines = await self._get_source_lines(client, component, start_line, end_line)
                except Exception as exc:  # не роняем весь импорт из-за одного файла
                    logger.warning("[SonarQube] Failed to fetch source for %s: %s", component, exc)
                    continue

                if lines:
                    issue["_source_snippet"] = {
                        "path": component.split(":", 1)[-1] if ":" in component else component,
                        "start_line": start_line,
                        "end_line": end_line,
                        "lines": lines,
                    }

            return issues

    @staticmethod
    def _resolve_line_range(issue: dict):
        """
        Определяем диапазон строк для сниппета: по textRange, иначе по line.
        Возвращает (start_line, end_line) или (None, None).
        """
        text_range = issue.get("textRange") or {}
        start = text_range.get("startLine") or issue.get("line")
        if not start:
            return None, None

        end = text_range.get("endLine") or issue.get("line") or start

        # Небольшой контекст вокруг проблемной строки для читаемости
        context = 3
        snippet_start = max(1, int(start) - context)
        snippet_end = int(end) + context
        return snippet_start, snippet_end

    async def _get_source_lines(self, client: httpx.AsyncClient, component: str,
                                start_line: int, end_line: int):
        """
        Получает строки исходного кода файла через api/sources/show.
        Возвращает список строк [(line_number, code), ...].
        """
        url = f"{SONAR_URL}/api/sources/show"
        params = {
            "key": component,
            "from": start_line,
            "to": end_line,
        }
        r = await client.get(url, params=params, auth=(SONAR_TOKEN, ""))
        if not r.is_success:
            raise Exception(f"sources/show error {r.status_code}: {r.text}")

        data = r.json()
        # Формат ответа: {"sources": [[line_number, "code"], ...]}
        sources = data.get("sources") or []
        return [(int(item[0]), item[1]) for item in sources if len(item) >= 2]
