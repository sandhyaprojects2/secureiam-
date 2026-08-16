"""
Dependency wiring tests.

Confirms get_auth_service() / get_authorization_service() /
get_organization_service() actually construct their respective services
wired to real repository instances sharing the same session -- catching,
for example, a typo that accidentally wires the wrong repository class, or
a change that breaks the dependency chain silently (still returns
*something*, just not the right thing).
"""

from app.core.dependencies import (
    get_audit_log_service,
    get_auth_service,
    get_authorization_service,
    get_organization_service,
)
from app.domain.services.audit_log_service import AuditLogService
from app.domain.services.auth_service import AuthService
from app.domain.services.authorization_service import AuthorizationService
from app.domain.services.organization_service import OrganizationService
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.organization_membership_repository import (
    OrganizationMembershipRepository,
)
from app.repositories.organization_repository import OrganizationRepository
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
    assert isinstance(service.audit_log_repository, AuditLogRepository)


async def test_get_auth_service_repositories_share_the_same_session(test_session):
    """Both repositories must operate on the same session so that a single
    request's operations are part of one logical unit of work."""
    service = await get_auth_service(session=test_session)

    assert service.user_repository.session is test_session
    assert service.refresh_token_repository.session is test_session
    assert service.audit_log_repository.session is test_session


async def test_get_authorization_service_returns_correctly_wired_instance(test_session):
    service = await get_authorization_service(session=test_session)

    assert isinstance(service, AuthorizationService)
    assert isinstance(service.user_repository, UserRepository)
    assert isinstance(service.role_repository, RoleRepository)
    assert isinstance(service.permission_repository, PermissionRepository)
    assert isinstance(service.user_role_repository, UserRoleRepository)
    assert isinstance(service.organization_repository, OrganizationRepository)
    assert isinstance(
        service.organization_membership_repository, OrganizationMembershipRepository
    )
    assert isinstance(service.audit_log_repository, AuditLogRepository)


async def test_get_authorization_service_repositories_share_the_same_session(test_session):
    service = await get_authorization_service(session=test_session)

    assert service.user_repository.session is test_session
    assert service.role_repository.session is test_session
    assert service.permission_repository.session is test_session
    assert service.user_role_repository.session is test_session
    assert service.organization_repository.session is test_session
    assert service.organization_membership_repository.session is test_session
    assert service.audit_log_repository.session is test_session


async def test_get_organization_service_returns_correctly_wired_instance(test_session):
    service = await get_organization_service(session=test_session)

    assert isinstance(service, OrganizationService)
    assert isinstance(service.organization_repository, OrganizationRepository)
    assert isinstance(
        service.organization_membership_repository, OrganizationMembershipRepository
    )
    assert isinstance(service.user_repository, UserRepository)
    assert isinstance(service.audit_log_repository, AuditLogRepository)


async def test_get_organization_service_repositories_share_the_same_session(test_session):
    service = await get_organization_service(session=test_session)

    assert service.organization_repository.session is test_session
    assert service.organization_membership_repository.session is test_session
    assert service.user_repository.session is test_session
    assert service.audit_log_repository.session is test_session


async def test_get_audit_log_service_returns_correctly_wired_instance(test_session):
    service = await get_audit_log_service(session=test_session)

    assert isinstance(service, AuditLogService)
    assert isinstance(service.audit_log_repository, AuditLogRepository)


async def test_get_audit_log_service_repository_shares_the_same_session(test_session):
    service = await get_audit_log_service(session=test_session)

    assert service.audit_log_repository.session is test_session
