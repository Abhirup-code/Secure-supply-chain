# ---- build stage: install pinned dependencies into a virtualenv ----
FROM python:3.11-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m venv /venv
COPY requirements.txt .
RUN /venv/bin/pip install -r requirements.txt

# ---- runtime stage: only the app and its venv, no build tools ----
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/venv/bin:$PATH" DB_PATH=/data/links.db
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir /data && chown appuser:appuser /data
COPY --from=build /venv /venv
WORKDIR /srv
COPY app ./app
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "app.main:create_app()"]
