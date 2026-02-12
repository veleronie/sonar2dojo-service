# --- Этап 1: Сборка зависимостей ---
FROM python:3.11-slim as builder

# Запрещаем Python писать файлы .pyc и включаем буферизацию логов
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Устанавливаем системные зависимости для сборки (если потребуются библиотекам)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Копируем только файл зависимостей, чтобы закешировать этот слой
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# --- Этап 2: Финальный образ ---
FROM python:3.11-slim

WORKDIR /app

# Настройки окружения
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Копируем установленные библиотеки из этапа builder
COPY --from=builder /install /usr/local

# Создаем непривилегированного пользователя для безопасности
# (В продакшене нельзя запускать код от root)
RUN useradd -m appuser && chown -R appuser /app
USER appuser

# Копируем исходный код приложения
COPY ./app /app/app

# Открываем порт
EXPOSE 8000

# Запуск через uvicorn
# --host 0.0.0.0 обязателен для Docker
# --workers 4 (или другое число) для обработки очереди вебхуков
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]