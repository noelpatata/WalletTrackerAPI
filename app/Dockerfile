FROM python:3.12-alpine

RUN apk update && \
    apk add --no-cache mariadb-dev gcc musl-dev build-base linux-headers

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock* ./
RUN uv sync --no-dev --frozen

RUN apk del gcc musl-dev build-base linux-headers

COPY . .

EXPOSE 5000

CMD ["uv", "run", "uwsgi", "--ini", "uwsgi.ini"]
