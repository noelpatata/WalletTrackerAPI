"""
Applies Flask-Migrate migrations to every tenant database.
Tenant databases are identified by the DATABASE_NAME prefix (e.g. wallet_tracker_u1).
Run this script after every deploy, before restarting the service.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy import create_engine, text
from flask_migrate import upgrade as migrate_upgrade
from app import create_app

DATABASE_PASSWORD = os.environ.get("DATABASE_ROOT_PASSWORD", "12345678")
DATABASE_NAME     = os.environ.get("DATABASE_NAME", "wallet_tracker")
DATABASE_USERNAME = os.environ.get("WALLET_TRACKER_DB_USER", "root")
DATABASE_HOST     = os.environ.get("WALLET_TRACKER_DB_HOST", "db")

TENANT_PREFIX  = f"{DATABASE_NAME}_u"
MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations_tenant")


def get_tenant_databases():
    admin_url = f"mysql://{DATABASE_USERNAME}:{DATABASE_PASSWORD}@{DATABASE_HOST}/{DATABASE_NAME}"
    engine = create_engine(admin_url)
    with engine.connect() as conn:
        rows = conn.execute(text("SHOW DATABASES"))
        dbs = [row[0] for row in rows if row[0].startswith(TENANT_PREFIX)]
    engine.dispose()
    return dbs


def migrate_tenant(db_name):
    url = f"mysql://{DATABASE_USERNAME}:{DATABASE_PASSWORD}@{DATABASE_HOST}/{db_name}"
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = url
    with app.app_context():
        migrate_upgrade(directory=MIGRATIONS_DIR)
    print(f"[OK] {db_name}")


if __name__ == "__main__":
    tenant_dbs = get_tenant_databases()

    if not tenant_dbs:
        print("No tenant databases found.")
        sys.exit(0)

    print(f"Migrating {len(tenant_dbs)} tenant database(s)...")
    for db_name in tenant_dbs:
        migrate_tenant(db_name)
    print("Done.")
