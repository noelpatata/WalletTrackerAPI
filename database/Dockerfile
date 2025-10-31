FROM mariadb:latest
RUN apt-get update && \
    apt-get install -y gettext-base

COPY sql_schema/init.sql.template /docker-entrypoint-initdb.d/init.sql.template