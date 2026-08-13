"""
SecureIAM API — application entry point.

Routers are registered here; the app object itself stays free of any
business logic, database, or security code.
"""

from fastapi import FastAPI

from app.api.v1.auth import router as auth_router
from app.api.v1.authorize import router as authorize_router

app = FastAPI(
    title="SecureIAM",
    description="Identity and Access Management platform — Phase 1 (Authentication) "
    "+ Phase 2 (RBAC & Authorization)",
    version="0.2.0",
)

app.include_router(auth_router)
app.include_router(authorize_router)


@app.get("/health", tags=["health"])
async def health_check() -> dict:
    """Liveness check used by Docker Compose and deployment platforms."""
    return {"status": "ok"}
