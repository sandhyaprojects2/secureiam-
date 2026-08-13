"""
Dependency wiring tests.

Confirms get_auth_service() / get_authorization_service() actually construct
their respective services wired to real repository instances sharing the
same session -- catching, for example, a typo that accidentally wires the
wrong repository class, or a change that breaks the dependency chain
silently (still returns *something*, just not the right thing).
"""

from app.core.dependencies import get_auth_service, get_authorization_service
from app.domain.services.auth_service import AuthService
from app.domain.services.authorization_service import AuthorizationService
from app.repositories.permission_repository import PermissionRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.repositories.user_role_repository import UserRoleRepository


async def test_get_auth_service_returns_correctly_wired_instance(test_session):
    service = await get_auth_service(session=test_session)

    assert isinstance(service, AuthService)
    assert isinstance(service.user_repository, UserRepository)
    assert isinstance(service.refresh_token_repository, RefreshTokenRepository)


async def test_get_auth_service_repositories_share_the_same_session(test_session):
    """Both repositories must operate on the same session so that a single
    request's operations are part of one logical unit of work."""
    service = await get_auth_service(session=test_session)

    assert service.user_repository.session is test_session
    assert service.refresh_token_repository.session is test_session


async def test_get_authorization_service_returns_correctly_wired_instance(test_session):
    service = await get_authorization_service(session=test_session)

    assert isinstance(service, AuthorizationService)
    assert isinstance(service.user_repository, UserRepository)
    assert isinstance(service.role_repository, RoleRepository)
    assert isinstance(service.permission_repository, PermissionRepository)
    assert isinstance(service.user_role_repository, UserRoleRepository)


async def test_get_authorization_service_repositories_share_the_same_session(test_session):
    service = await get_authorization_service(session=test_session)

    assert service.user_repository.session is test_session
    assert service.role_repository.session is test_session
    assert service.permission_repository.session is test_session
    assert service.user_role_repository.session is test_session
