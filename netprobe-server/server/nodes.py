"""
NetProbe Server — Node Registry

Manages a list of remote NetProbe instances for multi-location probing.
The local server is always the first node (url="self").

Configure extra nodes by creating nodes.json in the netprobe-server/ directory.
See nodes.json.example for the format.
"""
import asyncio
import dataclasses
import json
import os
import sys

_HERE = os.path.dirname(__file__)
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_NODES_FILE = os.path.join(_ROOT, "nodes.json")

_SELF = {
    "id":      "local",
    "name":    "This Server",
    "city":    "",
    "country": "--",
    "flag":    "⬡",
    "url":     "self",
    "key":     "",
}


def load_nodes():
    """Return node list: self node first, then any from nodes.json."""
    extra = []
    try:
        if os.path.isfile(_NODES_FILE):
            with open(_NODES_FILE, encoding="utf-8") as f:
                loaded = json.load(f)
            extra = [n for n in loaded if n.get("url") != "self"]
    except Exception:
        pass
    return [_SELF] + extra


def node_meta(node: dict) -> dict:
    """Public-safe node metadata (no API key)."""
    return {
        "id":      node["id"],
        "name":    node["name"],
        "city":    node.get("city", ""),
        "country": node.get("country", ""),
        "flag":    node.get("flag", ""),
    }


# ── Ping ─────────────────────────────────────────────────────────────────────

async def ping_node(node: dict, host: str, count: int = 1,
                    interval: float = 0.3) -> dict:
    """
    Ping host via node. Returns dict with rtt_ms, ip, sent, received,
    loss_pct, avg_ms.  rtt_ms is -1 on timeout; 'error' key set on failure.
    """
    if node.get("url") == "self":
        return await _ping_self(host, count, interval)
    return await _ping_remote(node, host, count, interval)


async def _ping_self(host: str, count: int, interval: float) -> dict:
    loop = asyncio.get_running_loop()

    def _run():
        import time as _t
        from core.engine import _icmp_ping
        results = []
        for seq in range(count):
            r = _icmp_ping(host, seq)
            results.append(r)
            if seq < count - 1:
                _t.sleep(interval)
        valid = [r.rtt_ms for r in results if r.rtt_ms >= 0]
        last  = results[-1]
        return {
            "rtt_ms":   last.rtt_ms,
            "ip":       last.ip or host,
            "sent":     count,
            "received": len(valid),
            "loss_pct": round((count - len(valid)) / count * 100, 1),
            "avg_ms":   round(sum(valid) / len(valid), 2) if valid else -1,
        }

    try:
        return await loop.run_in_executor(None, _run)
    except Exception as e:
        return {"rtt_ms": -1, "ip": "", "error": str(e),
                "sent": count, "received": 0, "loss_pct": 100.0, "avg_ms": -1}


async def _ping_remote(node: dict, host: str, count: int,
                        interval: float) -> dict:
    loop = asyncio.get_running_loop()
    fetch_timeout = max(count * (interval + 1) + 6, 12)

    def _fetch():
        import urllib.request
        import urllib.parse
        import json as _j
        params = urllib.parse.urlencode({
            "host": host, "count": count,
            "interval": round(min(interval, 5.0), 2),
        })
        url = node["url"].rstrip("/") + f"/api/ping?{params}"
        req = urllib.request.Request(url)
        if node.get("key"):
            req.add_header("X-API-Key", node["key"])
        with urllib.request.urlopen(req, timeout=fetch_timeout) as resp:
            data = _j.loads(resp.read())
        summary = data.get("summary", {})
        results = data.get("results", [])
        last    = results[-1] if results else {}
        return {
            "rtt_ms":   last.get("rtt_ms", -1),
            "ip":       last.get("ip", ""),
            "sent":     summary.get("sent",     count),
            "received": summary.get("received", 0),
            "loss_pct": summary.get("loss_pct", 100.0),
            "avg_ms":   summary.get("rtt_avg")
                        if summary.get("rtt_avg") is not None else -1,
        }

    try:
        return await loop.run_in_executor(None, _fetch)
    except Exception as e:
        return {"rtt_ms": -1, "ip": "", "error": str(e),
                "sent": count, "received": 0, "loss_pct": 100.0, "avg_ms": -1}


# ── Traceroute ────────────────────────────────────────────────────────────────

async def traceroute_node(node: dict, host: str, max_hops: int = 30) -> dict:
    """Run traceroute from node. Returns {"hops": [...dataclass dicts...]}."""
    if node.get("url") == "self":
        return await _trace_self(host, max_hops)
    return await _trace_remote(node, host, max_hops)


async def _trace_self(host: str, max_hops: int) -> dict:
    loop = asyncio.get_running_loop()

    def _run():
        from core.engine import traceroute
        hops = traceroute(host, max_hops=max_hops)
        return {"hops": [dataclasses.asdict(h) for h in hops]}

    try:
        return await loop.run_in_executor(None, _run)
    except Exception as e:
        return {"hops": [], "error": str(e)}


async def _trace_remote(node: dict, host: str, max_hops: int) -> dict:
    loop = asyncio.get_running_loop()

    def _fetch():
        import urllib.request
        import urllib.parse
        import json as _j
        params = urllib.parse.urlencode({"host": host, "max_hops": max_hops})
        url = node["url"].rstrip("/") + f"/api/traceroute?{params}"
        req = urllib.request.Request(url)
        if node.get("key"):
            req.add_header("X-API-Key", node["key"])
        with urllib.request.urlopen(req, timeout=120) as resp:
            hops = _j.loads(resp.read())
        return {"hops": hops}

    try:
        return await loop.run_in_executor(None, _fetch)
    except Exception as e:
        return {"hops": [], "error": str(e)}


# ── Health check ──────────────────────────────────────────────────────────────

async def check_health(node: dict, timeout: float = 4.0) -> bool:
    """Return True if the node's /health endpoint responds."""
    if node.get("url") == "self":
        return True
    loop = asyncio.get_running_loop()

    def _check():
        import urllib.request
        try:
            url = node["url"].rstrip("/") + "/health"
            req = urllib.request.Request(url)
            if node.get("key"):
                req.add_header("X-API-Key", node["key"])
            with urllib.request.urlopen(req, timeout=timeout):
                return True
        except Exception:
            return False

    return await loop.run_in_executor(None, _check)
