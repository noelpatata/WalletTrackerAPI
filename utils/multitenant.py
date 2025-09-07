import secrets
import threading
from sqlalchemy import create_engine, text
from sqlalchemy.orm import scoped_session, sessionmaker
from db import db
from config import MYSQLHOST, MYSQLDBNAME

_engine_cache = {}
_lock = threading.Lock()


def construct_db_name(base: str, user_id: int) -> str:
    return f"{base}_u{user_id}"


def construct_db_connection_string(db_username: str, db_password: str, user_id: int) -> str:
    user_dbname = construct_db_name(MYSQLDBNAME, user_id)
    return f"mysql://{db_username}:{db_password}@{MYSQLHOST}/{user_dbname}"


def create_tenant_user_and_db(user) -> tuple[str, str]:
    admin_engine = db.engine
    user_dbname = construct_db_name(MYSQLDBNAME, user.id)
    db_username = f"u{user.id}"
    db_password = secrets.token_urlsafe(16)

    with admin_engine.connect() as conn:
        conn.execute(
            text(
                f"CREATE DATABASE IF NOT EXISTS `{user_dbname}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        )

        conn.execute(
            text(f"CREATE USER IF NOT EXISTS '{db_username}'@'%' IDENTIFIED BY :pwd"),
            {"pwd": db_password},
        )

        conn.execute(
            text(f"GRANT ALL PRIVILEGES ON `{user_dbname}`.* TO '{db_username}'@'%'")
        )
        conn.execute(text("FLUSH PRIVILEGES"))

    user.db_username = db_username
    user.db_password = db_password
    initialise_tenant_db(user)

    return db_username, db_password


def initialise_tenant_db(user):
    with _lock:
        if user.id in _engine_cache:
            return _engine_cache[user.id]

        uri = construct_db_connection_string(user.db_username, user.db_password, user.id)
        eng = create_engine(uri, pool_pre_ping=True, pool_recycle=3600)
        _engine_cache[user.id] = eng

        from repositories.ExpenseRepository import Expense
        from repositories.ExpenseCategoryRepository import ExpenseCategory

        db.metadata.create_all(
            bind=eng, tables=[Expense.__table__, ExpenseCategory.__table__]
        )

        return eng


def get_tenant_session(user):
    eng = initialise_tenant_db(user)
    return scoped_session(sessionmaker(bind=eng))
