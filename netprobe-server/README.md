# NetProbe Server

Remote network analysis backend for the NetProbe iOS client.
Wraps `core/engine.py` in a FastAPI WebSocket + REST API, deployable as a Docker container on any Linux server and exposed securely via Cloudflare Tunnel.

---

## Architecture

```
iPhone (NetProbe iOS)
    │  HTTPS / WSS
    ▼
Cloudflare Edge  ──── Access policy (auth gate)
    │
    │  cloudflared tunnel (encrypted outbound, no open inbound ports)
    ▼
Your Server
    │  Docker / direct
    ▼
NetProbeServer  (FastAPI + uvicorn)
    │  port 8765
    ▼
core/engine.py  →  ping, scan, traceroute, DNS, SSL, WHOIS, WoL...
                    (runs against the network the server is attached to)
```

---

## Quick Start

### 1. Docker (recommended)

```bash
cd netprobe-server
cp .env.example .env
# Edit .env — at minimum set NETPROBE_API_KEY to a long random string

docker compose up -d
# Server now listening on http://localhost:8765
```

With Cloudflare Tunnel (for remote iOS access):
```bash
# One-time tunnel setup — see cloudflare/config.yml.example for full instructions
cp cloudflare/config.yml.example cloudflare/config.yml
# Edit cloudflare/config.yml with your tunnel ID + hostname

docker compose --profile tunnel up -d
# Server now reachable at https://netprobe.yourdomain.com
```

### 2. Direct (Windows .exe or Python)

**Python:**
```bash
pip install -r requirements.txt
cp .env.example .env    # edit API key
python main.py
```

**Windows exe:**
```
# Build once:
pip install pyinstaller
pyinstaller NetProbeServer.spec --clean

# Distribute:
copy dist\NetProbeServer.exe  somewhere\
copy .env.example             somewhere\.env   # edit API key

# Run:
NetProbeServer.exe
NetProbeServer.exe --port 9000
```

> **Windows note:** Run as Administrator for ICMP ping, traceroute, and ARP scanning (raw socket access). The Docker path on Linux doesn't need this — `--cap-add NET_RAW` handles it.

---

## Configuration

All settings via environment variables or a `.env` file next to the binary/`main.py`.

| Variable | Default | Description |
|---|---|---|
| `NETPROBE_API_KEY` | *(empty)* | API key — **set this**. Empty = no auth (dev only) |
| `NETPROBE_HOST` | `0.0.0.0` | Bind address |
| `NETPROBE_PORT` | `8765` | Bind port |
| `NETPROBE_LOG_LEVEL` | `info` | Uvicorn log level |
| `NETPROBE_MAX_CIDR_HOSTS` | `1024` | Max hosts in a single CIDR scan |
| `NETPROBE_MAX_SCAN_PORTS` | `10000` | Max ports in a single port scan |
| `NETPROBE_SCAN_THREADS` | `100` | Port scan concurrency |
| `NETPROBE_CORS_ORIGINS` | `*` | Comma-separated CORS origins |

---

## API Reference

Interactive docs at `http://localhost:8765/docs` when the server is running.

### Authentication

All endpoints accept the API key as:
- Header: `X-API-Key: your-key`
- Query param: `?key=your-key` (required for WebSocket connections)

### WebSocket Endpoints (streaming)

| Endpoint | Params | Description |
|---|---|---|
| `WS /ws/ping` | `host`, `interval` (1.0s) | Continuous ICMP ping stream |
| `WS /ws/traceroute` | `host`, `max_hops` (30) | Per-hop traceroute stream |
| `WS /ws/mtr` | `host`, `interval`, `max_hops` | Continuous MTR snapshot stream |
| `WS /ws/portscan` | `host`, `ports` (1-1024), `proto` (tcp/udp), `threads` | Port scan stream, CIDR-aware |
| `WS /ws/arp` | `network` (e.g. 192.168.1.0/24) | ARP scan stream |

**Message envelope:**
```json
{ "type": "result" | "hop" | "update" | "done" | "error", "data": { ... } }
```

**Stop a streaming session** by sending:
```json
{ "cmd": "stop" }
```

**Example — connect to ping stream:**
```
wss://netprobe.yourdomain.com/ws/ping?host=1.1.1.1&interval=1.0&key=your-key
```

### REST Endpoints (one-shot)

| Method | Endpoint | Key Params | Description |
|---|---|---|---|
| GET | `/health` | — | Health check |
| GET | `/api/ping` | `host`, `count` (4), `interval` (0.5) | Blocking ping, returns all results |
| GET | `/api/dns` | `host`, `types` (A,AAAA,...) | DNS lookup |
| GET | `/api/doh` | `domain`, `type` (A) | Google vs Cloudflare DoH comparison |
| GET | `/api/ssl` | `host`, `port` (443) | SSL/TLS certificate inspection |
| GET | `/api/http` | `url`, `method` (GET), `follow_redirects` | HTTP probe — TTFB, headers, redirects |
| GET | `/api/whois` | `target` | Raw WHOIS lookup |
| GET | `/api/geoip` | `ip` | GeoIP (ip-api.com, cached) |
| GET | `/api/asn` | `ip` | ASN lookup (Team Cymru DNS) |
| GET | `/api/netstat` | `proto`, `state`, `port`, `process` | Server's connection table |
| GET | `/api/interfaces` | — | Server's network interfaces |
| GET | `/api/sweep` | `network` | Fast ping sweep — returns live hosts |
| POST | `/api/wol` | `{mac, broadcast, port}` | Send Wake-on-LAN magic packet |

---

## Cloudflare Tunnel Setup

See [`cloudflare/config.yml.example`](cloudflare/config.yml.example) for the full annotated setup guide.

Summary:
1. `cloudflared tunnel login`
2. `cloudflared tunnel create netprobe`
3. `cloudflared tunnel route dns netprobe netprobe.yourdomain.com`
4. Edit `cloudflare/config.yml` with your tunnel ID
5. `docker compose --profile tunnel up -d`

Optionally add a **Cloudflare Access** policy (Zero Trust → Access → Applications) to gate access with identity (email OTP, Google, GitHub) or a Service Token for the iOS app.

---

## Project Structure

```
netprobe-server/
├── main.py                  # Entry point — loads .env, starts uvicorn
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example             # Copy to .env and fill in
├── NetProbeServer.spec      # PyInstaller build spec → NetProbeServer.exe
│
├── core/                    # Network engine (copy of desktop app's core/)
│   ├── __init__.py
│   └── engine.py
│
├── server/                  # FastAPI application layer
│   ├── __init__.py
│   ├── config.py            # Env-based settings
│   ├── auth.py              # API key middleware
│   └── api.py               # All REST + WebSocket routes
│
└── cloudflare/
    └── config.yml.example   # Annotated Cloudflare Tunnel config template
```

---

## Notes

- **WebSocket keep-alive:** Cloudflare terminates idle WebSocket connections after 100 seconds. The server sends a WS ping frame every 30 seconds via uvicorn's `ws_ping_interval` setting — your client must respond to stay connected.
- **CIDR scanning:** Pass e.g. `host=10.0.0.0/24` to `/ws/portscan` — the API expands the subnet and scans each host sequentially. Maximum hosts controlled by `NETPROBE_MAX_CIDR_HOSTS`.
- **Raw sockets:** ICMP ping, traceroute, and ARP scan require `NET_RAW` capability. In Docker this is granted via `--cap-add NET_RAW`. On bare-metal Linux, run as root or set `CAP_NET_RAW` on the binary. On Windows, run as Administrator.
- **Network scope:** The server scans from wherever it is running. In Docker with `network_mode: host` it can reach your full LAN. Adjust to `bridge` + `ports:` for stricter isolation.
