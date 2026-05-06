# Stage 1: build Python dependencies once
FROM python:3.11-slim AS builder
ARG VOLATILITY_VERSION=2.27.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    libyara-dev \
    pkg-config \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "volatility3[full]==${VOLATILITY_VERSION}" \
    fastmcp==3.2.3 \
 && python -c "import Crypto.Cipher, volatility3, yara; print('vol3 deps ok')"

# Some older Windows samples, including prolaco.vmem, need the official
# Windows symbol pack. Relying only on on-demand symbol generation can produce
# incomplete tables and fail with missing types such as _ETHREAD.
RUN python -c "from pathlib import Path; import urllib.request, zipfile; target = Path('/opt/volatility-symbols/windows.zip'); target.parent.mkdir(parents=True, exist_ok=True); urllib.request.urlretrieve('https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/windows.zip', target); assert zipfile.is_zipfile(target), 'downloaded windows.zip is not a valid zip'; print(f'windows symbols installed: {target} ({target.stat().st_size} bytes)')"

# Stage 2: small runtime image
FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    libyara10 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /opt/volatility-symbols /app/symbols

RUN mkdir -p /data/memory_dumps /data/cache/results /data/cache/volatility3-2.27-symbolpack-v1 /app/symbols /app/volatility_mcp_server/tools

WORKDIR /app

COPY __init__.py /app/volatility_mcp_server/__init__.py
COPY __main__.py /app/volatility_mcp_server/__main__.py
COPY server.py /app/volatility_mcp_server/server.py
COPY tools/ /app/volatility_mcp_server/tools/

ENV PYTHONPATH=/app
ENV MCP_TRANSPORT=http
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000
ENV MCP_PATH=/mcp
ENV DUMPS_DIR=/data/memory_dumps
ENV CACHE_DIR=/data/cache/results
ENV VOL_FRAMEWORK_CACHE_DIR=/data/cache/volatility3-2.27-symbolpack-v1
ENV VOL_SYMBOL_DIRS=/app/symbols
ENV XDG_CACHE_HOME=/data/cache
ENV VOL_TIMEOUT=300
ENV MAX_OUTPUT=2000000
ENV MAX_ROWS_FULL=80
ENV PYTHONUNBUFFERED=1

RUN python -m compileall -q /app/volatility_mcp_server

# Docker Compose now runs a normal HTTP MCP service at http://localhost:8000/mcp.
# The Streamlit app connects to that URL directly; no docker exec stdio bridge is needed.
CMD ["python", "-m", "volatility_mcp_server"]
