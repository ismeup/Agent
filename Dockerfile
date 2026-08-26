FROM python:3.11-slim AS builder

WORKDIR /app

RUN pip install --no-cache-dir hatch

COPY pyproject.toml ./
COPY src/ ./src/

RUN hatch build

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/dist/*.whl .

RUN pip install --no-cache-dir *.whl && rm *.whl

VOLUME /app/data
ENV AGENT_KEY_PATH=/app/data/identity.key
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["ismeup-agent"]
