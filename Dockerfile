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
COPY . ./
RUN poetry install

FROM python:3.12-slim-bookworm as runtime

ENV VIRTUAL_ENV=/app/.venv \
      PATH="/app/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
COPY ./${PYTHON_PKG} /app/${PYTHON_PKG}

ENTRYPOINT [ "netprism" ]


