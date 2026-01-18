# Agent Opulence - Metasploit MCP Server
FROM python:3.11-slim

LABEL maintainer="Agent Opulence"
LABEL description="Metasploit Framework MCP interface"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV PYTHONUNBUFFERED=1
ENV MSF_HOST=msf
ENV MSF_PORT=55553
ENV MSF_TOKEN=msfrpc_token

CMD ["python3", "/app/server.py"]
