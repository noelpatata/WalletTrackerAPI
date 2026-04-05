import os
from alembic import context
from flask import current_app
from logging.config import fileConfig

config = context.config

if config.config_file_name is not None and os.path.isfile(config.config_file_name):
    fileConfig(config.config_file_name)

config.set_main_option(
    "sqlalchemy.url",
    current_app.config["SQLALCHEMY_DATABASE_URI"]
)

target_metadata = current_app.extensions["migrate"].db.metadata

TENANT_TABLES = {"Expense", "ExpenseCategory", "Season", "Importe"}

def include_name(name, type_, parent_names):
    if type_ == "table":
        return name in TENANT_TABLES
    return True


def run_migrations_offline():
    context.configure(
        url=current_app.config["SQLALCHEMY_DATABASE_URI"],
        target_metadata=target_metadata,
        literal_binds=True,
        include_name=include_name,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = current_app.extensions["migrate"].db.engine
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_name=include_name,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
