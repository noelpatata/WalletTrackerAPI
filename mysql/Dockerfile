FROM mysql:latest
RUN apt update && apt install -y gettext-base && rm -rf /var/lib/apt/lists/*
COPY sql_schema/init.sql.template /docker-entrypoint-initdb.d/init.sql.template