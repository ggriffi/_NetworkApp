"""
NetProbe Server — FastAPI Application
REST + WebSocket API wrapping core/engine.py network operations.

WebSocket endpoints stream results in real-time.
REST endpoints are one-shot blocking calls run in a thread pool.

Message envelope:
  { "type": "result" | "hop" | "update" | "done" | "error", "data": {...} }
"""
import asyncio
import dataclasses
import ipaddress
import json
import os
import sys
import threading
from typing import List, Optional

from fastapi import (
    Depends, FastAPI, HTTPException, Query, WebSocket,
    WebSocketDisconnect, status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── path setup so core/ is importable from netprobe-server/server/ ──────────
_HERE = os.path.dirname(__file__)
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core import (                         # noqa: E402
    PingMonitor, PingResult,
    MTRMonitor, MTRRow,
    traceroute, HopResult,
    port_scan, udp_port_scan, PortResult, COMMON_PORTS,
    dns_lookup, DNSResult, doh_lookup,
    arp_scan, ping_sweep, get_local_interfaces, ARPEntry,
    ssl_inspect, SSLInfo,
    http_probe, HTTPResult,
    whois_lookup,
    wake_on_lan,
    geoip_lookup, GeoIPResult,
    asn_lookup,
    netstat_snapshot, NetstatEntry,
)
from .auth import verify_key, verify_ws_key
from .config import get_settings

VERSION = "1.1.0"

# ── app factory ─────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="NetProbe Server",
        version=VERSION,
        description="Remote network analysis API — pairs with the NetProbe iOS client.",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    origins = settings.cors_origins if settings.cors_origins != ["*"] else ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Serve the PWA at /app  — must be last so API routes take priority
    _static_dir = os.path.join(os.path.dirname(_HERE), "static", "app")
    if os.path.isdir(_static_dir):
        app.mount("/app", StaticFiles(directory=_static_dir, html=True), name="pwa")

    return app


app = create_app()


# ── helpers ──────────────────────────────────────────────────────────────────

def _dc(obj) -> dict:
    """Convert a dataclass instance to a plain dict, stripping private fields."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        d = dataclasses.asdict(obj)
        return {k: v for k, v in d.items() if not k.startswith("_")}
    return obj


def parse_ports(spec: str) -> List[int]:
    """
    Parse port specification string into a sorted list of ints.
    Examples: "22"  "22,80,443"  "1-1024"  "22,100-200,443"
    """
    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def expand_cidr(target: str, max_hosts: int) -> List[str]:
    """
    Expand a CIDR notation string to a list of host IPs.
    Returns [target] unchanged if not a valid network.
    Raises HTTPException if the network exceeds max_hosts.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > max_hosts:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"CIDR range contains {len(hosts)} hosts, "
                    f"maximum allowed is {max_hosts}. "
                    f"Set NETPROBE_MAX_CIDR_HOSTS env var to increase."
                ),
            )
        return hosts or [target]
    except ValueError:
        return [target]


# ── WebSocket streaming helper ────────────────────────────────────────────────

class _WSSession:
    """
    Bridges threaded callback-based engine functions to a WebSocket stream.

    Usage (continuous monitor):
        session = _WSSession(websocket)
        monitor = PingMonitor(host, callback=session.push_dc)
        await session.stream(start=monitor.start, stop=monitor.stop)

    Usage (one-shot with callback):
        session = _WSSession(websocket)
        def run():
            traceroute(host, callback=session.push_dc)
            session.signal_done()
        await session.stream(start=lambda: threading.Thread(target=run, daemon=True).start())
    """

    def __init__(self, ws: WebSocket):
        self.ws = ws
        self._q: asyncio.Queue = asyncio.Queue()
        self.stopped = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None

    # ── called from engine threads ───────────────────────────────────────────

    def push(self, msg: dict):
        """Push an arbitrary dict onto the stream."""
        if not self.stopped.is_set() and self._loop:
            self._loop.call_soon_threadsafe(self._q.put_nowait, msg)

    def push_dc(self, obj, msg_type: str = "result"):
        """Push a dataclass object wrapped in the standard envelope."""
        self.push({"type": msg_type, "data": _dc(obj)})

    def signal_done(self):
        """Called by one-shot engine thread when the run is complete."""
        if self._loop:
            self._loop.call_soon_threadsafe(self._q.put_nowait, None)

    # ── async orchestration ───────────────────────────────────────────────────

    async def stream(self, start, stop=None):
        """
        Accept the WebSocket, run start(), then pump messages until the client
        disconnects or sends {"cmd":"stop"}. Calls stop() on teardown.
        """
        self._loop = asyncio.get_event_loop()
        await self.ws.accept()
        start()

        async def _sender():
            while True:
                item = await self._q.get()
                if item is None:
                    break
                try:
                    await self.ws.send_json(item)
                except Exception:
                    break

        async def _receiver():
            try:
                while True:
                    raw = await self.ws.receive_text()
                    try:
                        if json.loads(raw).get("cmd") == "stop":
                            return
                    except Exception:
                        pass
            except (WebSocketDisconnect, Exception):
                pass

        send_task = asyncio.create_task(_sender())
        recv_task = asyncio.create_task(_receiver())

        _done, pending = await asyncio.wait(
            [send_task, recv_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        self.stopped.set()
        if stop:
            stop()
        self._q.put_nowait(None)  # unblock sender if still waiting

        for t in pending:
            t.cancel()

        try:
            await self.ws.send_json({"type": "done"})
            await self.ws.close()
        except Exception:
            pass


# ── system routes ─────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "NetProbe Server",
        "version": VERSION,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
async def health():
    return {"status": "ok", "version": VERSION}


# ── WebSocket: Ping (continuous) ──────────────────────────────────────────────

@app.websocket("/ws/ping")
async def ws_ping(
    websocket: WebSocket,
    host: str = Query(..., description="Target hostname or IP"),
    interval: float = Query(1.0, ge=0.1, le=60.0),
):
    if not await verify_ws_key(websocket):
        return
    session = _WSSession(websocket)
    monitor = PingMonitor(
        host,
        interval=interval,
        callback=lambda r: session.push_dc(r, "result"),
    )
    await session.stream(start=monitor.start, stop=monitor.stop)


# ── WebSocket: Traceroute (one-shot, streaming hops) ─────────────────────────

@app.websocket("/ws/traceroute")
async def ws_traceroute(
    websocket: WebSocket,
    host: str = Query(...),
    max_hops: int = Query(30, ge=1, le=64),
):
    if not await verify_ws_key(websocket):
        return
    session = _WSSession(websocket)

    def run():
        traceroute(
            host,
            max_hops=max_hops,
            callback=lambda hop: session.push_dc(hop, "hop"),
        )
        session.signal_done()

    await session.stream(
        start=lambda: threading.Thread(target=run, daemon=True).start()
    )


# ── WebSocket: MTR (continuous, snapshot per hop-cycle) ──────────────────────

@app.websocket("/ws/mtr")
async def ws_mtr(
    websocket: WebSocket,
    host: str = Query(...),
    interval: float = Query(1.0, ge=0.2, le=30.0),
    max_hops: int = Query(30, ge=1, le=64),
):
    if not await verify_ws_key(websocket):
        return
    session = _WSSession(websocket)

    def on_update(rows_dict: dict):
        # rows_dict: {hop_num: MTRRow}
        rows = [_dc(row) for row in sorted(rows_dict.values(), key=lambda r: r.hop)]
        session.push({"type": "update", "data": rows})

    monitor = MTRMonitor(
        host,
        interval=interval,
        max_hops=max_hops,
        callback=on_update,
    )
    await session.stream(start=monitor.start, stop=monitor.stop)


# ── WebSocket: Port Scan (TCP or UDP, CIDR-aware) ────────────────────────────

@app.websocket("/ws/portscan")
async def ws_portscan(
    websocket: WebSocket,
    host: str = Query(..., description="IP, hostname, or CIDR e.g. 10.0.0.0/24"),
    ports: str = Query("1-1024", description="Port spec: 22 | 22,80 | 1-1024"),
    proto: str = Query("tcp", pattern="^(tcp|udp)$"),
    threads: int = Query(100, ge=1, le=500),
):
    if not await verify_ws_key(websocket):
        return

    settings = get_settings()
    hosts = expand_cidr(host, settings.max_cidr_hosts)
    try:
        port_list = parse_ports(ports)
    except ValueError:
        await websocket.close(code=4000, reason="Invalid port specification.")
        return
    if len(port_list) > settings.max_scan_ports:
        await websocket.close(
            code=4000,
            reason=f"Too many ports ({len(port_list)}). Max {settings.max_scan_ports}.",
        )
        return

    session = _WSSession(websocket)

    def run():
        for h in hosts:
            if session.stopped.is_set():
                break
            cb = lambda r: session.push_dc(r, "result")
            if proto == "udp":
                udp_port_scan(h, port_list, callback=cb)
            else:
                port_scan(h, port_list, threads=threads, callback=cb)
        session.signal_done()

    await session.stream(
        start=lambda: threading.Thread(target=run, daemon=True).start()
    )


# ── WebSocket: ARP Scan (one-shot, streaming entries) ────────────────────────

@app.websocket("/ws/arp")
async def ws_arp(
    websocket: WebSocket,
    network: str = Query(..., description="Subnet e.g. 192.168.1.0/24"),
):
    if not await verify_ws_key(websocket):
        return
    session = _WSSession(websocket)

    def run():
        arp_scan(
            network,
            callback=lambda entry: session.push_dc(entry, "result"),
        )
        session.signal_done()

    await session.stream(
        start=lambda: threading.Thread(target=run, daemon=True).start()
    )


# ── REST: DNS ─────────────────────────────────────────────────────────────────

@app.get("/api/dns")
async def api_dns(
    host: str = Query(...),
    types: str = Query("A,AAAA,MX,NS,TXT,CNAME,SOA", description="Comma-separated record types"),
    _key: str = Depends(verify_key),
):
    record_types = [t.strip().upper() for t in types.split(",") if t.strip()]
    loop = asyncio.get_event_loop()
    results: List[DNSResult] = await loop.run_in_executor(
        None, lambda: dns_lookup(host, record_types=record_types)
    )
    return [_dc(r) for r in results]


# ── REST: DNS-over-HTTPS comparison ──────────────────────────────────────────

@app.get("/api/doh")
async def api_doh(
    domain: str = Query(...),
    type: str = Query("A"),
    _key: str = Depends(verify_key),
):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: doh_lookup(domain, type.upper()))
    return result


# ── REST: SSL / TLS certificate inspection ───────────────────────────────────

@app.get("/api/ssl")
async def api_ssl(
    host: str = Query(...),
    port: int = Query(443, ge=1, le=65535),
    _key: str = Depends(verify_key),
):
    loop = asyncio.get_event_loop()
    result: SSLInfo = await loop.run_in_executor(
        None, lambda: ssl_inspect(host, port=port)
    )
    return _dc(result)


# ── REST: HTTP Probe ──────────────────────────────────────────────────────────

@app.get("/api/http")
async def api_http(
    url: str = Query(...),
    method: str = Query("GET", pattern="^(GET|HEAD|POST)$"),
    follow_redirects: bool = Query(True),
    _key: str = Depends(verify_key),
):
    loop = asyncio.get_event_loop()
    result: HTTPResult = await loop.run_in_executor(
        None, lambda: http_probe(url, method=method, follow_redirects=follow_redirects)
    )
    return _dc(result)


# ── REST: WHOIS ───────────────────────────────────────────────────────────────

@app.get("/api/whois")
async def api_whois(
    target: str = Query(..., description="Domain or IP address"),
    _key: str = Depends(verify_key),
):
    loop = asyncio.get_event_loop()
    raw: str = await loop.run_in_executor(None, lambda: whois_lookup(target))
    return {"target": target, "raw": raw}


# ── REST: GeoIP ───────────────────────────────────────────────────────────────

@app.get("/api/geoip")
async def api_geoip(
    ip: str = Query(...),
    _key: str = Depends(verify_key),
):
    loop = asyncio.get_event_loop()
    result: GeoIPResult = await loop.run_in_executor(None, lambda: geoip_lookup(ip))
    return _dc(result)


# ── REST: ASN lookup ──────────────────────────────────────────────────────────

@app.get("/api/asn")
async def api_asn(
    ip: str = Query(...),
    _key: str = Depends(verify_key),
):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: asn_lookup(ip))
    return result if isinstance(result, dict) else {"asn": str(result)}


# ── REST: Netstat ─────────────────────────────────────────────────────────────

@app.get("/api/netstat")
async def api_netstat(
    proto: Optional[str] = Query(None, description="Filter: TCP | UDP | TCP6 | UDP6"),
    state: Optional[str] = Query(None, description="Filter: LISTEN | ESTABLISHED | etc."),
    port: Optional[int] = Query(None, description="Filter by local port"),
    process: Optional[str] = Query(None, description="Filter by process name (case-insensitive)"),
    _key: str = Depends(verify_key),
):
    loop = asyncio.get_event_loop()
    entries: List[NetstatEntry] = await loop.run_in_executor(None, netstat_snapshot)

    if proto:
        entries = [e for e in entries if e.proto.upper() == proto.upper()]
    if state:
        entries = [e for e in entries if e.state.upper() == state.upper()]
    if port is not None:
        entries = [e for e in entries if e.local_port == port or e.remote_port == port]
    if process:
        entries = [e for e in entries if process.lower() in e.process.lower()]

    return [_dc(e) for e in entries]


# ── REST: Network interfaces ──────────────────────────────────────────────────

@app.get("/api/interfaces")
async def api_interfaces(_key: str = Depends(verify_key)):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, get_local_interfaces)
    return result


# ── REST: Ping sweep (quick host discovery) ───────────────────────────────────

@app.get("/api/sweep")
async def api_sweep(
    network: str = Query(..., description="Subnet e.g. 192.168.1.0/24"),
    _key: str = Depends(verify_key),
):
    settings = get_settings()
    expand_cidr(network, settings.max_cidr_hosts)  # raises 400 if too large
    loop = asyncio.get_event_loop()
    live: List[str] = await loop.run_in_executor(None, lambda: ping_sweep(network))
    return {"network": network, "live": live, "count": len(live)}


# ── REST: Wake-on-LAN ─────────────────────────────────────────────────────────

class WoLRequest(BaseModel):
    mac: str
    broadcast: str = "255.255.255.255"
    port: int = 9


@app.post("/api/wol")
async def api_wol(body: WoLRequest, _key: str = Depends(verify_key)):
    loop = asyncio.get_event_loop()
    ok: bool = await loop.run_in_executor(
        None,
        lambda: wake_on_lan(body.mac, broadcast=body.broadcast, port=body.port),
    )
    return {"success": ok, "mac": body.mac, "broadcast": body.broadcast, "port": body.port}


# ── REST: Single ping (one-shot, non-streaming) ───────────────────────────────

@app.get("/api/ping")
async def api_ping(
    host: str = Query(...),
    count: int = Query(4, ge=1, le=100),
    interval: float = Query(0.5, ge=0.1, le=5.0),
    _key: str = Depends(verify_key),
):
    """
    Blocking ping — sends `count` ICMP probes and returns all results.
    For live streaming use the /ws/ping WebSocket endpoint instead.
    """
    import time as _time

    loop = asyncio.get_event_loop()
    results = []
    done = asyncio.Event()

    collected = []
    lock = threading.Lock()

    def _run():
        from core.engine import _icmp_ping
        for seq in range(count):
            r = _icmp_ping(host, seq)
            with lock:
                collected.append(_dc(r))
            if seq < count - 1:
                _time.sleep(interval)
        loop.call_soon_threadsafe(done.set)

    threading.Thread(target=_run, daemon=True).start()
    await done.wait()

    valid = [r["rtt_ms"] for r in collected if r["rtt_ms"] >= 0]
    summary = {
        "host": host,
        "sent": count,
        "received": len(valid),
        "loss_pct": round((count - len(valid)) / count * 100, 1),
        "rtt_min": round(min(valid), 3) if valid else None,
        "rtt_avg": round(sum(valid) / len(valid), 3) if valid else None,
        "rtt_max": round(max(valid), 3) if valid else None,
    }
    return {"summary": summary, "results": collected}
