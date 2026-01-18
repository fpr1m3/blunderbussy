# Agent Opulence - MetaMCP Capability Gateway
FROM python:3.11-slim

LABEL maintainer="Agent Opulence"
LABEL description="Capability gateway for tool aggregation"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV PYTHONUNBUFFERED=1
ENV MSF_HOST=msf
ENV MSF_PORT=55553
ENV SLIVER_HOST=sliver
ENV SLIVER_PORT=31337

CMD ["python3", "/app/server.py"]
