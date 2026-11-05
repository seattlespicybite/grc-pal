# GRC-pal image: portal and command line in one small, non-root image.
#   docker build -t grc-pal .
#   docker run --rm -p 8000:8000 -e GRCPAL_AUTH_MODE=dev -e GRCPAL_ENV=development -e GRCPAL_DEMO=1 grc-pal
# Your catalog is not baked in: the portal loads it from storage (grcpal publish-config) or from a
# mounted folder (GRCPAL_BASE). Without either it shows the built-in starter catalog.
# Reproducible: the base image is pinned by digest (Dependabot proposes updates) and every Python package comes from
# requirements/image.txt with its SHA-256 (pip refuses anything else), so the image a release publishes contains
# exactly the versions CI tested and pip-audit checked. Regenerate the lock after changing pyproject.toml:
#   uv pip compile pyproject.toml --extra portal --extra aws --extra gcp --universal --python-version 3.12 \
#     --generate-hashes -o requirements/image.txt
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY requirements ./requirements
RUN python -m venv /opt/grcpal \
 && /opt/grcpal/bin/pip install --require-hashes --only-binary :all: -r requirements/image.txt \
 && /opt/grcpal/bin/pip install --require-hashes -r requirements/build.txt
COPY pyproject.toml README.md LICENSE ./
COPY grcpal ./grcpal
# GRC-pal itself: no dependency resolution and no download at this point (everything above is already pinned)
RUN /opt/grcpal/bin/pip install --no-deps --no-build-isolation --no-index . \
 && /opt/grcpal/bin/pip uninstall -y setuptools wheel packaging >/dev/null \
 && /opt/grcpal/bin/pip check

FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30
LABEL org.opencontainers.image.title="GRC-pal" \
      org.opencontainers.image.description="Open-source SOC 2 compliance automation and evidence portal" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/seattlespicybite/grc-pal"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/grcpal/bin:$PATH
COPY --from=build /opt/grcpal /opt/grcpal
RUN useradd --system --uid 10001 --no-create-home grcpal \
 && mkdir -p /data && chown 10001:10001 /data && chmod 700 /data
# /data belongs to the app user, so a Docker volume mounted there is writable (new volumes copy this ownership)
WORKDIR /tmp
USER 10001
ENV GRCPAL_ENV=production GRCPAL_AUTH_MODE=local GRCPAL_EVIDENCE_DIR=/tmp/evidence GRCPAL_SQLITE=/tmp/grcpal.db
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1
# --forwarded-allow-ips "*" lets uvicorn read the scheme (https) from the platform's proxy. It also makes
# request.client the left-most X-Forwarded-For entry, which the caller controls, so GRC-pal never records that:
# security.client_ip takes only the address our own proxy added (GRCPAL_TRUSTED_PROXY_HOPS).
CMD ["uvicorn", "grcpal.portal.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header", "--limit-concurrency", "50"]
