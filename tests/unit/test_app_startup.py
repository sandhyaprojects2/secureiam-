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


def test_all_expected_authorization_routes_are_registered():
    route_paths = {route.path for route in app.routes}
    expected = {
        "/v1/authorize",
        "/v1/roles",
        "/v1/roles/{role_id}/permissions",
        "/v1/roles/{role_id}/permissions/{permission_id}",
        "/v1/users/me/permissions",
        "/v1/users/{user_id}/roles",
        "/v1/users/{user_id}/roles/{role_id}",
        "/v1/users/{user_id}/permissions",
    }
    assert expected.issubset(route_paths)


def test_users_me_permissions_is_registered_before_the_parameterized_route():
    """Locks in the route-ordering requirement documented in
    app/api/v1/authorize.py: /users/me/permissions must come before
    /users/{user_id}/permissions or Starlette would never reach it."""
    permission_routes = [
        route.path
        for route in app.routes
        if getattr(route, "path", "").startswith("/v1/users/") and "permissions" in route.path
    ]
    assert permission_routes.index("/v1/users/me/permissions") < permission_routes.index(
        "/v1/users/{user_id}/permissions"
    )


def test_create_role_endpoint_returns_201_status_code_configured():
    create_role_route = next(r for r in app.routes if r.path == "/v1/roles")
    assert create_role_route.status_code == 201


def test_role_and_user_mutation_routes_return_204_status_code_configured():
    for path in (
        "/v1/roles/{role_id}/permissions",
        "/v1/users/{user_id}/roles",
    ):
        route = next(
            r for r in app.routes if r.path == path and "POST" in getattr(r, "methods", set())
        )
        assert route.status_code == 204

    for path in (
        "/v1/roles/{role_id}/permissions/{permission_id}",
        "/v1/users/{user_id}/roles/{role_id}",
    ):
        route = next(
            r for r in app.routes if r.path == path and "DELETE" in getattr(r, "methods", set())
        )
        assert route.status_code == 204


def test_all_expected_organization_routes_are_registered():
    route_paths = {route.path for route in app.routes}
    expected = {
        "/v1/organizations",
        "/v1/organizations/{organization_id}/members",
        "/v1/organizations/{organization_id}/members/{user_id}",
        "/v1/users/me/organizations",
    }
    assert expected.issubset(route_paths)


def test_create_organization_endpoint_returns_201_status_code_configured():
    create_org_route = next(r for r in app.routes if r.path == "/v1/organizations")
    assert create_org_route.status_code == 201


def test_organization_mutation_routes_return_204_status_code_configured():
    add_member_route = next(
        r
        for r in app.routes
        if r.path == "/v1/organizations/{organization_id}/members"
        and "POST" in getattr(r, "methods", set())
    )
    assert add_member_route.status_code == 204

    remove_member_route = next(
        r
        for r in app.routes
        if r.path == "/v1/organizations/{organization_id}/members/{user_id}"
        and "DELETE" in getattr(r, "methods", set())
    )
    assert remove_member_route.status_code == 204


def test_audit_log_route_is_registered():
    route_paths = {route.path for route in app.routes}
    assert "/v1/audit-logs" in route_paths


def test_audit_log_route_only_accepts_get():
    route = next(r for r in app.routes if r.path == "/v1/audit-logs")
    assert "GET" in route.methods
    assert "POST" not in route.methods
    assert "DELETE" not in route.methods
