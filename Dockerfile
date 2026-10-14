# GRC-pal image: portal and command line in one small, non-root image.
#   docker build -t grc-pal .
#   docker run --rm -p 8000:8000 -e GRCPAL_AUTH_MODE=dev -e GRCPAL_ENV=development -e GRCPAL_DEMO=1 grc-pal
# Your catalog is not baked in: the portal loads it from storage (grcpal publish-config) or from a
# mounted folder (GRCPAL_BASE). Without either it shows the built-in starter catalog.
FROM python:3.14-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY grcpal ./grcpal
RUN pip wheel --wheel-dir /wheels ".[portal,aws,gcp]"

FROM python:3.14-slim
LABEL org.opencontainers.image.title="GRC-pal" \
      org.opencontainers.image.description="Open-source SOC 2 compliance automation and evidence portal" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/seattlespicybite/grc-pal"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links /wheels "grc-pal[portal,aws,gcp]" && rm -rf /wheels \
 && useradd --system --uid 10001 --no-create-home grcpal \
 && mkdir -p /data && chown 10001:10001 /data && chmod 700 /data
# /data belongs to the app user, so a Docker volume mounted there is writable (new volumes copy this ownership)
WORKDIR /tmp
USER 10001
ENV GRCPAL_ENV=production GRCPAL_AUTH_MODE=local GRCPAL_EVIDENCE_DIR=/tmp/evidence GRCPAL_SQLITE=/tmp/grcpal.db
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1
CMD ["uvicorn", "grcpal.portal.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header", "--limit-concurrency", "50"]
