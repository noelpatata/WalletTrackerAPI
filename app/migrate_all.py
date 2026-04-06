import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy import create_engine, text
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from flask_migrate import upgrade as migrate_upgrade
from app import create_app


def stamp_head(engine, migrations_dir):
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", migrations_dir)
    script = ScriptDirectory.from_config(cfg)
    head_revision = script.get_current_head()
    with engine.connect() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS alembic_version "
            "(version_num VARCHAR(32) NOT NULL, "
            "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
        ))
        conn.execute(text(f"INSERT INTO alembic_version (version_num) VALUES ('{head_revision}')"))
        conn.commit()

DATABASE_PASSWORD = os.environ.get("DATABASE_ROOT_PASSWORD", "12345678")
DATABASE_NAME     = os.environ.get("DATABASE_NAME", "wallet_tracker")
DATABASE_USERNAME = os.environ.get("WALLET_TRACKER_DB_USER", "root")
DATABASE_HOST     = os.environ.get("WALLET_TRACKER_DB_HOST", "db")

MAIN_MIGRATIONS_DIR   = os.path.join(os.path.dirname(__file__), "migrations_main")
TENANT_MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations_tenant")
TENANT_PREFIX         = f"{DATABASE_NAME}_u"


def get_tenant_databases(engine):
    with engine.connect() as conn:
        rows = conn.execute(text("SHOW DATABASES"))
        return [row[0] for row in rows if row[0].startswith(TENANT_PREFIX)]


def needs_stamp(engine):
    with engine.connect() as conn:
        tables = conn.execute(text("SHOW TABLES")).fetchall()
        table_names = [row[0] for row in tables]
        return len(table_names) > 0 and "alembic_version" not in table_names



def migrate_app(app, migrations_dir, engine):
    with app.app_context():
        if needs_stamp(engine):
            print(f"[migrate_all] Pre-Alembic DB detected, stamping head...")
            stamp_head(engine, migrations_dir)
        migrate_upgrade(directory=migrations_dir)


def main():
    admin_url = f"mysql://{DATABASE_USERNAME}:{DATABASE_PASSWORD}@{DATABASE_HOST}/{DATABASE_NAME}"
    admin_engine = create_engine(admin_url)

    # 1. Main DB
    print("[migrate_all] Migrating main DB...")
    app = create_app()
    migrate_app(app, MAIN_MIGRATIONS_DIR, admin_engine)
    print("[migrate_all] Main DB done.")

    # 2. Tenant DBs
    tenant_dbs = get_tenant_databases(admin_engine)
    admin_engine.dispose()

    if not tenant_dbs:
        print("[migrate_all] No tenant databases found.")
        return

    print(f"[migrate_all] Migrating {len(tenant_dbs)} tenant database(s)...")
    for db_name in tenant_dbs:
        url = f"mysql://{DATABASE_USERNAME}:{DATABASE_PASSWORD}@{DATABASE_HOST}/{db_name}"
        tenant_engine = create_engine(url)
        tenant_app = create_app()
        tenant_app.config["SQLALCHEMY_DATABASE_URI"] = url
        migrate_app(tenant_app, TENANT_MIGRATIONS_DIR, tenant_engine)
        tenant_engine.dispose()
        print(f"[migrate_all]   [OK] {db_name}")

    print("[migrate_all] Done.")


if __name__ == "__main__":
    main()
