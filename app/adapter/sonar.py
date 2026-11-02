# app/adapter/sonar.py

class SonarAdapter:
    # Используем Generic тип, чтобы DD не пытался применять свои хрупкие парсеры
    scan_type = "Generic Findings Import"

    def normalize(self, sonar_issues: list, properties: dict, project_key: str = ""):

        project_path = properties.get("sonar.analysis.project_path", "unknown")
        branch = properties.get("sonar.analysis.branch", "main")
        commit = properties.get("sonar.analysis.commit_sha", "unknown")

        parts = project_path.split("/")
        group = "/".join(parts[:-1]) if len(parts) > 1 else "default"

        # Маппинг серьезности: Sonar -> DefectDojo
        severity_map = {
            "BLOCKER": "Critical",
            "CRITICAL": "High",
            "MAJOR": "Medium",
            "MINOR": "Low",
            "INFO": "Info"
        }

        findings = []
        for issue in sonar_issues:

            raw_message = issue.get("message", "No description")
            clean_title = raw_message.replace('"', '').replace("'", "")
            component = issue.get("component", "")
            path = component.split(":", 1)[-1] if ":" in component else component
            # Ключ инцидента в SonarQube нужен для прямой ссылки на файл/строку
            issue_key = issue.get("key", "")
            
            # Извлекаем CWE если он есть в правиле (например, "python:S4830")
            cwe = None
            rule_id = issue.get('rule', '')
            if ':' in rule_id:
                try:
                    # Попытка достать числовой ID, если он там есть
                    potential_cwe = rule_id.split(':')[1]
                    if potential_cwe.isdigit():
                        cwe = int(potential_cwe)
                except:
                    pass

            findings.append({
                "title": clean_title,
                "date": "2026-02-11",  # DD требует дату в Generic формате
                "severity": severity_map.get(issue.get("severity"), "Info"),
                "description": self._build_description(rule_id, issue),
                "file_path": path,
                "line": issue.get("line", 1),
                "active": True,
                "verified": False,
                "cwe": cwe,
                "sonar_issue_key": issue_key,
            })

        payload = {
            "scan_type": self.scan_type,
            "product_type_name": group.lower(),
            "product_name": project_path.lower(),
            "engagement_name": f"Sonar Scan: {branch}",
            "branch_tag": branch,
            "commit_hash": commit,
            "sonar_project_key": project_key,
            "file": {
                "findings": findings  # ВАЖНО: Ключ должен называться 'findings'
            },
        }

        print(f"[SonarAdapter] Transformed {len(findings)} issues into Generic format")
        return payload

    def _build_description(self, rule_id: str, issue: dict) -> str:
        """
        Собирает Markdown-описание находки: правило, сообщение SonarQube
        и (при наличии) сниппет уязвимого кода.
        """
        parts = [
            f"**Rule:** {rule_id}",
            f"**Sonar Message:** {issue.get('message')}",
        ]

        snippet = self._format_code_snippet(issue)
        if snippet:
            parts.append(snippet)

        return "\n".join(parts)

    @staticmethod
    def _format_code_snippet(issue: dict) -> str:
        """
        Формирует читаемый Markdown-блок с уязвимым кодом: путь, номер строки
        и фрагмент исходного кода (с тройными обратными кавычками).

        Если сниппет был получен заранее (поле _source_snippet), используем его;
        иначе ограничиваемся ссылкой/координатами без текста кода.
        """
        snippet = issue.get("_source_snippet")
        if not snippet:
            return ""

        path = snippet.get("path", "")
        lines = snippet.get("lines", [])
        highlight_line = issue.get("line")

        if path:
            header_parts = [f"**File:** `{path}`"]
        else:
            header_parts = []

        if highlight_line:
            header_parts.append(f"**Line:** {highlight_line}")

        header = "  \n".join(header_parts)

        # Нумеруем строки и выделяем проблемную
        code_lines = []
        for line_no, code in lines:
            marker = "  <-- vulnerable line" if line_no == highlight_line else ""
            code_lines.append(f"{line_no:>4} | {code}{marker}")

        code_block = "```\n" + "\n".join(code_lines) + "\n```"

        return "\n\n### Vulnerable Code\n\n" + (header + "\n\n" if header else "") + code_block