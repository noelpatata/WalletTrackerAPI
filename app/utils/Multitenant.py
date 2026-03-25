import secrets
from sqlalchemy import text
from sqlalchemy.orm import scoped_session, sessionmaker
from db import db
from config import DATABASE_NAME
from exceptions.Http import HttpException
from utils.Constants import MultitenantMessages
from utils.MultitenantCore import construct_db_name, initialise_tenant_db


def create_tenant_user_and_db(user) -> tuple[str, str]:
    try:
        admin_engine = db.engine
        user_dbname = construct_db_name(DATABASE_NAME, user.id)
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
        user.save()
        initialise_tenant_db(user)

        return db_username, db_password
    except Exception as e:
        raise HttpException(MultitenantMessages.INIT_TENANT_FAILED, 500, e)


def get_tenant_session(user):
    try:
        eng = initialise_tenant_db(user)
        return scoped_session(sessionmaker(bind=eng))
    except Exception as e:
        raise HttpException(MultitenantMessages.INIT_TENANT_FAILED, 500, e)
