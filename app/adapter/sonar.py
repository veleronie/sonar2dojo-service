# app/adapter/sonar.py

class SonarAdapter:
    # Используем Generic тип, чтобы DD не пытался применять свои хрупкие парсеры
    scan_type = "Generic Findings Import"

    def normalize(self, sonar_issues: list, properties: dict):

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
                "description": f"**Rule:** {rule_id}\n**Sonar Message:** {issue.get('message')}",
                "file_path": path,
                "line": issue.get("line", 1),
                "active": True,
                "verified": False,
                "cwe": cwe
            })

        payload = {
            "scan_type": self.scan_type,
            "product_type_name": group.lower(),
            "product_name": project_path.lower(),
            "engagement_name": f"Sonar Scan: {branch}",
            "branch_tag": branch,
            "commit_hash": commit,
            "file": {
                "findings": findings  # ВАЖНО: Ключ должен называться 'findings'
            },
        }

        print(f"[SonarAdapter] Transformed {len(findings)} issues into Generic format")
        return payload