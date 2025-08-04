FROM python:3.12-bookworm AS builder

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache \
    POETRY_VERSION=2.1.2 \
    PYTHON_PKG="netprism"

RUN pip install "poetry==$POETRY_VERSION"

WORKDIR /app

COPY pyproject.toml ./
COPY README.md ./
COPY ./${PYTHON_PKG} /app/${PYTHON_PKG}

RUN poetry install

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

ENTRYPOINT [ "netprism" ]
