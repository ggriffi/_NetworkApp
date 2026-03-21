# ── NetProbe Server — Dockerfile ────────────────────────────────────────────
# Multi-stage build: keeps the final image lean (~200 MB).
#
# Build:
#   docker build -t netprobe-server .
#
# Run:
#   docker run -d \
#     --name netprobe \
#     --cap-add NET_RAW \
#     --cap-add NET_ADMIN \
#     --network host \
#     -e NETPROBE_API_KEY=your-secret-key \
#     -p 8765:8765 \
#     netprobe-server

# ── stage 1: build deps ───────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System packages needed to compile psutil / scapy / cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="NetProbe Server"
LABEL org.opencontainers.image.description="Remote network analysis API"

# Runtime system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    traceroute \
    iproute2 \
    net-tools \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Application source
COPY core/    ./core/
COPY server/  ./server/
COPY main.py  .

# Non-root user for everything except raw-socket ops
# (NET_RAW capability is granted via docker run --cap-add)
RUN useradd -r -s /bin/false netprobe
USER netprobe

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8765/health')" || exit 1

ENTRYPOINT ["python", "main.py"]
CMD []
