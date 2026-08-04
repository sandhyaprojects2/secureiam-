"""
SecureIAM API — application entry point.

Routers are registered here; the app object itself stays free of any
business logic, database, or security code.
"""

from fastapi import FastAPI

from app.api.v1.auth import router as auth_router

app = FastAPI(
    title="SecureIAM",
    description="Identity and Access Management platform — Phase 1 (Authentication)",
    version="0.1.0",
)

app.include_router(auth_router)


@app.get("/health", tags=["health"])
async def health_check() -> dict:
    """Liveness check used by Docker Compose and deployment platforms."""
    return {"status": "ok"}
