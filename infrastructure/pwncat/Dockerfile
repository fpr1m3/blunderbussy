# Agent Opulence - Pwncat MCP Server
FROM python:3.11-slim

LABEL maintainer="Agent Opulence"
LABEL description="Pwncat-cs MCP interface for post-exploitation"

WORKDIR /app

# Install system dependencies for pwncat (netifaces needs libc-dev for stdlib.h)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV PYTHONUNBUFFERED=1
ENV PWNCAT_SOCKET=/tmp/pwncat.sock

CMD ["python3", "/app/server.py"]
