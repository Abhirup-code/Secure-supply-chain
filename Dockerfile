# ---- build stage: install pinned dependencies into a virtualenv ----
FROM python:3.14-slim@sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1 AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m venv /venv
COPY requirements.txt .
RUN /venv/bin/pip install --require-hashes -r requirements.txt \
    && /venv/bin/pip uninstall -y pip   # no package manager left in the app venv

# ---- runtime stage: only the app and its venv, no build tools ----
FROM python:3.14-slim@sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1
# Apply the latest OS security patches and remove pip/setuptools, which the app never uses at runtime
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
RUN python -m pip uninstall -y pip setuptools wheel || true
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/venv/bin:$PATH" DB_PATH=/data/links.db
# Fixed numeric UID/GID so Kubernetes can prove the container is non-root (runAsNonRoot)
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin appuser \
    && mkdir /data && chown 10001:10001 /data
COPY --from=build /venv /venv
WORKDIR /srv
COPY app ./app
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "app.main:create_app()"]
