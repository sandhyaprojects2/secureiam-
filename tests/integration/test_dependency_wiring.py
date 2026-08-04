"""
Dependency wiring tests.

Confirms get_auth_service() actually constructs an AuthService wired to
real repository instances sharing the same session -- catching, for
example, a typo that accidentally wires the wrong repository class, or a
change that breaks the dependency chain silently (still returns *something*,
just not the right thing).
"""

from app.core.dependencies import get_auth_service
from app.domain.services.auth_service import AuthService
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository


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
