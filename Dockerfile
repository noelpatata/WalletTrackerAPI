FROM mysql:8.0-debian
RUN apt update && apt install -y gettext-base && rm -rf /var/lib/apt/lists/*
COPY sql_schema/init.sql.template /docker-entrypoint-initdb.d/init.sql.template
ENTRYPOINT ["sh", "-c", "envsubst < /docker-entrypoint-initdb.d/init.sql.template > /docker-entrypoint-initdb.d/init.sql && exec docker-entrypoint.sh mysqld"]

