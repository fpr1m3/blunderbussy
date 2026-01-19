FROM node:22-slim

# Install tmux, uv (for uvx), and deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    tmux curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

# Install uv (provides uvx for mcp-server-qdrant)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Install gemini-cli globally
RUN npm install -g @google/gemini-cli

WORKDIR /app

COPY docker-entrypoint.sh /usr/local/bin/
COPY settings.json /etc/gemini/settings.json
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["tmux", "attach", "-t", "dame"]
