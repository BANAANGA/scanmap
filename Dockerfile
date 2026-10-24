# scanmap - nmap + zmap in a browser
#
# The app itself is pure Python standard library; the image only adds the two
# scanners. Runs as an unprivileged user that is granted NET_RAW/NET_ADMIN at
# runtime (see docker-compose.yml).

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="scanmap" \
      org.opencontainers.image.description="Web interface for nmap and zmap" \
      org.opencontainers.image.source="https://github.com/BANAANGA/scanmap" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        zmap \
        python3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin scanmap \
    && mkdir -p /data /opt/scanmap \
    && chown -R scanmap:scanmap /data /opt/scanmap

COPY --chown=scanmap:scanmap app /opt/scanmap/app

WORKDIR /opt/scanmap
USER scanmap

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SCANMAP_HOST=0.0.0.0 \
    SCANMAP_PORT=8080 \
    SCANMAP_DATA_DIR=/data \
    SCANMAP_MAX_PARALLEL=2

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3).read()" || exit 1

ENTRYPOINT ["python3", "-m", "app.main"]
