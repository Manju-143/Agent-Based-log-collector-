FROM python:3.11-slim

# Basic hygiene
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (minimal). Add build-essential only if a dependency ever needs compiling.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Install python deps first (better caching)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY . /app

# Default envs (safe defaults; override in compose)
ENV PKSL_SERVER_HOST=0.0.0.0 \
    PKSL_SERVER_PORT=9000 \
    PKSL_STORAGE_DIR=/app/data \
    PKSL_LOG_FILE=verified_logs.jsonl

# Expose server port
EXPOSE 9000

# Default command (server). Compose will override for agent.
CMD ["python", "-m", "server.server"]