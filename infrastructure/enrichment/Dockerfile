# Agent Opulence - Faraday-integrated Enrichment Pipeline
# ========================================================
# Watches for raw scan files and processes them through:
# 1. Faraday API (80+ built-in parsers for nmap, nuclei, httpx, etc.)
# 2. Custom enrichers (services, web)
# 3. CAS formatter (YAML output)
# 4. PTT initialization

FROM docker.io/library/python:3.11-slim

LABEL maintainer="Agent Opulence"
LABEL description="Faraday-integrated enrichment pipeline for scan data processing"

# Install system dependencies
# - curl: healthcheck and general utilities
# - jq: JSON processing
# - nodejs/npm: for gemini-cli (attack guidance generation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install gemini-cli for AI-powered attack guidance
RUN npm install -g @google/gemini-cli

# Copy Gemini CLI settings
COPY enrichment/settings.json /etc/gemini/settings.json

# Create app directory structure
WORKDIR /app

# Copy requirements first for caching
COPY enrichment/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Faraday integration
COPY enrichment/faraday_client.py .
COPY enrichment/faraday_watcher.py .

# Copy processing scripts
COPY enrichment/format-cas.py .
COPY enrichment/init-ptt.py .
COPY enrichment/update-manifest.py .
COPY enrichment/regenerate-cas.py .

# Copy prompts for Gemini attack guidance
COPY enrichment/prompts/ ./prompts/

# Keep custom enrichers (services, web - provide logic beyond Faraday)
COPY enrichment/enrichers/enrich-services.py ./enrichers/
COPY enrichment/enrichers/enrich-web.py ./enrichers/

# PTT module dependency
COPY PrEP/ptt.py .

# Create artifact directories (will be overridden by volume mounts)
RUN mkdir -p /artifacts/raw /artifacts/results /artifacts/processed /artifacts/logs

# Faraday connection defaults
ENV FARADAY_URL=http://faraday-server:5985
ENV FARADAY_USER=faraday
ENV FARADAY_PASSWORD=changeme
ENV FARADAY_WORKSPACE=pentest

# Path configuration
ENV RAW_DIR=/artifacts/raw
ENV RESULTS_DIR=/artifacts/results
ENV LOGS_DIR=/artifacts/logs

# Behavior configuration
ENV POLL_INTERVAL=30
ENV FILE_STABLE_SECONDS=4
ENV AUTORECON_POLL_INTERVAL=30
ENV GENERATE_CAS=true
ENV GENERATE_PTT=true

# Healthcheck port
ENV HEALTHCHECK_PORT=8080

# Python settings
ENV PYTHONUNBUFFERED=1

# Health check - HTTP endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose healthcheck port
EXPOSE 8080

# Create non-root user for security
RUN useradd -r -u 1001 -g root appuser && \
    chown -R appuser:root /artifacts /app
USER appuser

# Run the Faraday-integrated watcher
CMD ["python3", "/app/faraday_watcher.py"]
