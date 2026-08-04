"""
SecureIAM API — application entry point.

This module only builds the ASGI app object. Routers, database wiring,
and settings are added in later Phase 1 commits as those layers are built.
"""

from fastapi import FastAPI

app = FastAPI(
    title="SecureIAM",
    description="Identity and Access Management platform — Phase 1 (Authentication)",
    version="0.1.0",
)


@app.get("/health", tags=["health"])
async def health_check() -> dict:
    """Liveness check used by Docker Compose and deployment platforms."""
    return {"status": "ok"}
