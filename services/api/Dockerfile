FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system sleep && useradd --system --gid sleep --home-dir /app sleep

COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY migrations ./migrations
COPY docker-entrypoint.sh ./docker-entrypoint.sh
RUN pip install --no-cache-dir .
# COPY keeps host file modes. The service runs as the unprivileged "sleep"
# user, so make sure every copied file is readable regardless of how it was
# created on the host (for example with mode 600).
RUN chmod -R a+rX /app && chmod 755 ./docker-entrypoint.sh

USER sleep

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2)" || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["uvicorn", "sleep_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
