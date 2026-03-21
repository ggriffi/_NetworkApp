"""
NetProbe Server — Entry Point
Loads .env, then starts the uvicorn ASGI server.

Usage:
    python main.py                     # defaults from .env or env vars
    python main.py --host 0.0.0.0 --port 8765
    python main.py --reload            # dev mode with hot-reload

When packaged as NetProbeServer.exe:
    NetProbeServer.exe
    NetProbeServer.exe --port 9000
"""
import argparse
import os
import sys

# ── load .env file if present (before importing Settings) ───────────────────
def _load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


_load_dotenv()

# ── now safe to import settings ──────────────────────────────────────────────
from server.config import get_settings  # noqa: E402

_BANNER = r"""
  _   _      _   ____            _
 | \ | | ___| |_|  _ \ _ __ ___| |__   ___
 |  \| |/ _ \ __| |_) | '__/ _ \ '_ \ / _ \
 | |\  |  __/ |_|  __/| | |  __/ |_) |  __/
 |_| \_|\___|\__|_|   |_|  \___|_.__/ \___|  Server v{version}
"""


def main():
    parser = argparse.ArgumentParser(description="NetProbe Server")
    parser.add_argument("--host",   default=None, help="Bind host (default: NETPROBE_HOST or 0.0.0.0)")
    parser.add_argument("--port",   default=None, type=int, help="Bind port (default: NETPROBE_PORT or 8765)")
    parser.add_argument("--reload", action="store_true", help="Enable hot-reload (dev mode)")
    parser.add_argument("--log-level", default=None, help="Uvicorn log level")
    args = parser.parse_args()

    settings = get_settings()
    host      = args.host      or settings.host
    port      = args.port      or settings.port
    log_level = args.log_level or settings.log_level

    from server.api import VERSION
    print(_BANNER.format(version=VERSION))
    print(f"  Listening : http://{host}:{port}")
    print(f"  Auth      : {'enabled (X-API-Key / ?key=)' if settings.auth_enabled else 'DISABLED (dev mode)'}")
    print(f"  Docs      : http://{host}:{port}/docs")
    print()

    import uvicorn
    uvicorn.run(
        "server.api:app",
        host=host,
        port=port,
        log_level=log_level,
        reload=args.reload,
        ws_ping_interval=30,   # keep Cloudflare tunnel alive (100s timeout)
        ws_ping_timeout=10,
    )


if __name__ == "__main__":
    main()
