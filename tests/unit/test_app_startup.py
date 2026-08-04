"""
Application startup tests.

These don't test business logic -- they test that the app object itself is
correctly assembled: the right routes exist, with the right methods, and
the app boots without requiring a live database connection just to import.
"""

from fastapi.testclient import TestClient

from app.main import app


def test_app_boots_and_health_check_responds():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_all_expected_auth_routes_are_registered():
    route_paths = {route.path for route in app.routes}
    expected = {
        "/v1/auth/register",
        "/v1/auth/login",
        "/v1/auth/refresh",
        "/v1/auth/logout",
    }
    assert expected.issubset(route_paths)


def test_auth_routes_only_accept_post():
    route_by_path = {route.path: route for route in app.routes if hasattr(route, "methods")}
    for path in ("/v1/auth/register", "/v1/auth/login", "/v1/auth/refresh", "/v1/auth/logout"):
        methods = route_by_path[path].methods
        assert "POST" in methods
        assert "GET" not in methods


def test_register_endpoint_returns_201_status_code_configured():
    """Confirms the route is wired with the expected default status code
    (201), independent of any particular request body."""
    register_route = next(r for r in app.routes if r.path == "/v1/auth/register")
    assert register_route.status_code == 201


def test_logout_endpoint_returns_204_status_code_configured():
    logout_route = next(r for r in app.routes if r.path == "/v1/auth/logout")
    assert logout_route.status_code == 204


def test_openapi_schema_generates_without_error():
    """A broken response_model or schema reference would typically surface
    as an error generating the OpenAPI schema, before any request is ever
    made."""
    schema = app.openapi()
    assert "/v1/auth/register" in schema["paths"]
    assert "/v1/auth/login" in schema["paths"]
