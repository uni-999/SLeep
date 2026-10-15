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
# COPY keeps host file modes; make every file readable for the unprivileged user.
RUN chmod -R a+rX /app && chmod 755 ./docker-entrypoint.sh

USER sleep

# The healthcheck reads the heartbeat that the updater loop itself writes: the
# container turns unhealthy when the loop stops, or when one sync runs longer
# than SLEEP_VULNDB_MAX_SYNC_MINUTES, or when the database does not answer.
# Feed freshness is reported by `sleep-vulndb status`, so a feed that is
# temporarily unreachable never marks the container unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --start-interval=2s --retries=3 \
  CMD ["sleep-vulndb", "health"]

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["sleep-vulndb", "run"]
