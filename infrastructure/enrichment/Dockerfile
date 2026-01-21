# Agent Opulence - Enrichment Pipeline Container
# ==============================================
# Watches for raw scan files and processes them through:
# 1. Parsers (nmap, nuclei, httpx, subfinder)
# 2. Enrichers (CVE, services, web)
# 3. CAS formatter (YAML output)
# 4. Manifest updater

FROM python:3.11-slim

LABEL maintainer="Agent Opulence"
LABEL description="Enrichment pipeline for scan data processing"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create app directory structure
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY watcher.py .
COPY parsers/ ./parsers/
COPY enrichers/ ./enrichers/
COPY format-cas.py .
COPY update-manifest.py .

# Create artifact directories (will be overridden by volume mounts)
RUN mkdir -p /artifacts/raw /artifacts/processed /artifacts/logs

# Health check - verify watcher is running (uses /proc directly, no procps needed)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD grep -q watcher.py /proc/1/cmdline || exit 1

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ARTIFACTS_DIR=/artifacts
ENV RAW_DIR=/artifacts/raw
ENV LOG_LEVEL=INFO

# Run the watcher
CMD ["python3", "/app/watcher.py"]
