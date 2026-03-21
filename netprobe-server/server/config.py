"""
NetProbe Server — Configuration
All settings are read from environment variables (or a .env file loaded by main.py).
"""
import os


class Settings:
    def __init__(self):
        self.api_key: str = os.environ.get("NETPROBE_API_KEY", "")
        self.host: str = os.environ.get("NETPROBE_HOST", "0.0.0.0")
        self.port: int = int(os.environ.get("NETPROBE_PORT", "8765"))
        self.log_level: str = os.environ.get("NETPROBE_LOG_LEVEL", "info")
        self.max_cidr_hosts: int = int(os.environ.get("NETPROBE_MAX_CIDR_HOSTS", "1024"))
        self.max_scan_ports: int = int(os.environ.get("NETPROBE_MAX_SCAN_PORTS", "10000"))
        self.scan_threads: int = int(os.environ.get("NETPROBE_SCAN_THREADS", "100"))

        # CORS — comma-separated list of allowed origins, or * for all
        raw_cors = os.environ.get("NETPROBE_CORS_ORIGINS", "*")
        self.cors_origins: list = [o.strip() for o in raw_cors.split(",") if o.strip()]

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_key)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
