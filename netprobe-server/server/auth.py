"""
NetProbe Server — Authentication
Supports API key via X-API-Key header (REST) or ?key= query param (WebSocket + REST).
If NETPROBE_API_KEY is not set, all requests are allowed (dev mode).
"""
from fastapi import HTTPException, Security, WebSocket, status
from fastapi.security.api_key import APIKeyHeader, APIKeyQuery

from .config import get_settings

_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)
_query_scheme  = APIKeyQuery(name="key", auto_error=False)


async def verify_key(
    header_key: str = Security(_header_scheme),
    query_key:  str = Security(_query_scheme),
) -> str:
    """FastAPI dependency for REST endpoints."""
    settings = get_settings()
    if not settings.auth_enabled:
        return "dev"
    key = header_key or query_key
    if key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key.",
        )
    return key


async def verify_ws_key(websocket: WebSocket) -> bool:
    """
    Validate API key for WebSocket connections.
    Returns True if valid (or auth disabled), False + closes socket if invalid.
    Key must be supplied as ?key= query parameter.
    """
    settings = get_settings()
    if not settings.auth_enabled:
        return True
    key = websocket.query_params.get("key", "")
    if key != settings.api_key:
        await websocket.close(code=4003, reason="Invalid or missing API key.")
        return False
    return True
