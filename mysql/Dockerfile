FROM mysql:8.0-debian

# Fix MySQL APT key issue before updating
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://repo.mysql.com/RPM-GPG-KEY-mysql-2023 | tee /etc/apt/keyrings/mysql.gpg > /dev/null \
    && chmod 644 /etc/apt/keyrings/mysql.gpg \
    && sed -i 's|deb http://repo.mysql.com/apt/debian/|deb [signed-by=/etc/apt/keyrings/mysql.gpg] http://repo.mysql.com/apt/debian/|' /etc/apt/sources.list.d/mysql.list \
    && apt-get update \
    && apt-get install -y gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY sql_schema/init.sql.template /docker-entrypoint-initdb.d/init.sql.template
