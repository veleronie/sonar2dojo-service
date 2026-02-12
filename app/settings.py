import os

# ... существующие настройки (DD_URL, DD_TOKEN и т.д.) ...
DD_URL = os.environ["DD_URL"]
DD_TOKEN = os.environ["DD_TOKEN"]
GIT_DOMAIN = os.environ["GIT_DOMAIN"]

SONAR_URL = os.getenv("SONAR_URL", "https://sonarqube.example.com")
SONAR_TOKEN = os.getenv("SONAR_TOKEN")  # Токен для API запросов
SONAR_WEBHOOK_SECRET = os.getenv("SONAR_WEBHOOK_SECRET")  # Тот самый Secret из настроек вебхука

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
MAX_REPORT_SIZE_MB = int(os.getenv("MAX_REPORT_SIZE_MB", "20"))
