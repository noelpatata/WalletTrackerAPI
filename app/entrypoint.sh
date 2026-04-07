#!/bin/sh
set -e

echo "[entrypoint] Waiting for database..."
until uv run python -c "
import os, sqlalchemy
url = 'mysql://{}:{}@{}/{}'.format(
    os.environ.get('WALLET_TRACKER_DB_USER', 'root'),
    os.environ.get('DATABASE_ROOT_PASSWORD', '12345678'),
    os.environ.get('WALLET_TRACKER_DB_HOST', 'db'),
    os.environ.get('DATABASE_NAME', 'wallet_tracker'),
)
sqlalchemy.create_engine(url).connect()
" 2>/dev/null; do
  echo "[entrypoint] DB not ready, retrying in 2s..."
  sleep 2
done

echo "[entrypoint] Running migrations..."
uv run python migrate_all.py

echo "[entrypoint] Starting uWSGI..."
exec uv run uwsgi --ini uwsgi.ini
