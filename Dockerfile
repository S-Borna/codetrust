FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
COPY pyproject.toml .
COPY src/ src/
COPY README.md .

RUN pip install --no-cache-dir .

# --- Production image ---
FROM python:3.12-slim

LABEL maintainer="Said <said@maketheplay.ai>"
LABEL description="CodeTrust — AI code verification platform"

WORKDIR /app

# Copy installed packages and application code
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

# Copy Alembic config for migrations
COPY alembic.ini .
COPY alembic/ alembic/

# Non-root user for security
RUN useradd --create-home --shell /bin/bash codetrust
USER codetrust

# Environment defaults
ENV CODETRUST_HOST=0.0.0.0 \
    CODETRUST_PORT=8000 \
    CODETRUST_DEBUG=false \
    CODETRUST_REDIS_URL=redis://redis:6379

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8000/v1/status'); assert r.status_code == 200"

# Default: run the FastAPI server
# Override with: docker run codetrust python -m src.server  (for MCP mode)
CMD ["sh", "-c", "alembic upgrade head && uvicorn src.api:app --host 0.0.0.0 --port 8000"]
