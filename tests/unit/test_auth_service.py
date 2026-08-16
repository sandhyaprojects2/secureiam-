"""
Unit tests for AuthService.

Repositories are mocked (unittest.mock.AsyncMock) -- no database, no
network. This is the layer that should be exhaustively tested since it's
pure business logic.
"""

import inspect
import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.security import hash_password
from app.core.time import utc_now
from app.domain import audit_actions
from app.domain.exceptions import (
    EmailAlreadyExistsError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
)
from app.domain.services import auth_service as auth_service_module
from app.domain.services.auth_service import AuthService
from app.domain.schemas.auth import TokenResponse
from app.repositories.exceptions import DuplicateEmailError


def make_fake_user(
    is_active=True,
    password="correctpassword",
    email="user@example.com",
    user_id=None,
):
    return SimpleNamespace(
        id=user_id or uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        is_active=is_active,
        created_at=utc_now(),
        last_login_at=None,
    )


def make_fake_token(
    user_id=None,
    revoked=False,
    expired=False,
):
    now = utc_now()
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id=user_id or uuid.uuid4(),
        token_hash="a" * 64,
        revoked_at=now if revoked else None,
        expires_at=(now - timedelta(days=1)) if expired else (now + timedelta(days=14)),
        replaced_by=None,
    )


@pytest.fixture
def service():
    user_repo = AsyncMock()
    token_repo = AsyncMock()
    audit_repo = AsyncMock()
    # audit_repo is deliberately not part of the returned tuple -- existing
    # tests don't need to change their destructuring; new Phase 4.3 tests
    # that need to assert on it reach it via svc.audit_log_repository.
    return AuthService(user_repo, token_repo, audit_repo), user_repo, token_repo


# --- Module hygiene: confirm the architectural constraints hold -------------

def test_auth_service_module_has_no_forbidden_imports():
    """AuthService must not import HTTPException, SQLAlchemy, or FastAPI --
    it should be pure business logic, testable with plain mocks.

    Uses the `ast` module to inspect actual import statements and function
    calls/names used in the code, rather than fragile substring matching on
    raw source text (which would false-positive on this very docstring).
    """
    import ast

    source = inspect.getsource(auth_service_module)
    tree = ast.parse(source)

    imported_modules = set()
    used_names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.add(node.module.split(".")[0])
        elif isinstance(node, ast.Name):
            used_names.add(node.id)

    assert "sqlalchemy" not in imported_modules
    assert "fastapi" not in imported_modules
    assert "HTTPException" not in used_names
    assert "HTTPException" not in imported_modules


# --- Register ---------------------------------------------------

async def test_register_success(service):
    svc, user_repo, _ = service
    fake_user = make_fake_user(email="new@example.com")
    user_repo.create_user.return_value = fake_user

    result = await svc.register("new@example.com", "password123")

    assert result.email == "new@example.com"
    assert result.id == fake_user.id


async def test_register_duplicate_email_translated_to_domain_exception(service):
    svc, user_repo, _ = service
    user_repo.create_user.side_effect = DuplicateEmailError("already exists")

    with pytest.raises(EmailAlreadyExistsError):
        await svc.register("dup@example.com", "password123")


async def test_register_hashes_password_before_persisting(service):
    svc, user_repo, _ = service
    user_repo.create_user.return_value = make_fake_user()

    await svc.register("new@example.com", "plaintext-password")

    passed_hash = user_repo.create_user.call_args.kwargs["password_hash"]
    assert passed_hash != "plaintext-password"
    assert passed_hash.startswith("$argon2id$")


async def test_register_issues_no_tokens(service):
    svc, user_repo, token_repo = service
    user_repo.create_user.return_value = make_fake_user()

    await svc.register("new@example.com", "password123")

    token_repo.create.assert_not_called()


# --- Login ---------------------------------------------------

async def test_login_success_returns_token_pair(service):
    svc, user_repo, token_repo = service
    fake_user = make_fake_user(password="correctpassword")
    user_repo.get_by_email.return_value = fake_user

    result = await svc.login("user@example.com", "correctpassword")

    assert isinstance(result, TokenResponse)
    assert result.token_type == "bearer"
    assert result.access_token
    assert result.refresh_token


async def test_login_unknown_email_raises_invalid_credentials(service):
    svc, user_repo, _ = service
    user_repo.get_by_email.return_value = None

    with pytest.raises(InvalidCredentialsError):
        await svc.login("nouser@example.com", "whatever")


async def test_login_wrong_password_raises_invalid_credentials(service):
    svc, user_repo, _ = service
    fake_user = make_fake_user(password="correctpassword")
    user_repo.get_by_email.return_value = fake_user

    with pytest.raises(InvalidCredentialsError):
        await svc.login("user@example.com", "wrongpassword")


async def test_login_unknown_email_and_wrong_password_give_identical_message(service):
    """The core enumeration-prevention guarantee: these two very different
    underlying conditions must be indistinguishable to the caller."""
    svc, user_repo, _ = service

    user_repo.get_by_email.return_value = None
    with pytest.raises(InvalidCredentialsError) as unknown_exc:
        await svc.login("nouser@example.com", "whatever")

    fake_user = make_fake_user(password="correctpassword")
    user_repo.get_by_email.return_value = fake_user
    with pytest.raises(InvalidCredentialsError) as wrong_pw_exc:
        await svc.login("user@example.com", "wrongpassword")

    assert str(unknown_exc.value) == str(wrong_pw_exc.value)


async def test_login_inactive_user_rejected(service):
    svc, user_repo, _ = service
    fake_user = make_fake_user(password="correctpassword", is_active=False)
    user_repo.get_by_email.return_value = fake_user

    with pytest.raises(InactiveUserError):
        await svc.login("user@example.com", "correctpassword")


async def test_login_updates_last_login(service):
    svc, user_repo, _ = service
    fake_user = make_fake_user(password="correctpassword")
    user_repo.get_by_email.return_value = fake_user

    await svc.login("user@example.com", "correctpassword")

    user_repo.update_last_login.assert_called_once_with(fake_user)


async def test_login_stores_refresh_token_hash(service):
    svc, user_repo, token_repo = service
    fake_user = make_fake_user(password="correctpassword")
    user_repo.get_by_email.return_value = fake_user

    result = await svc.login("user@example.com", "correctpassword")

    token_repo.create.assert_called_once()
    stored_hash = token_repo.create.call_args.kwargs["token_hash"]
    assert stored_hash != result.refresh_token  # never store the raw token
    assert len(stored_hash) == 64  # sha256 hex digest


# --- Refresh ---------------------------------------------------

async def test_refresh_valid_token_rotates_successfully(service):
    svc, user_repo, token_repo = service
    fake_user = make_fake_user()
    fake_token = make_fake_token(user_id=fake_user.id)
    token_repo.get_by_hash.return_value = fake_token
    user_repo.get_by_id.return_value = fake_user

    result = await svc.refresh("some-raw-refresh-token")

    assert isinstance(result, TokenResponse)
    token_repo.create_rotation_pair.assert_called_once()


async def test_refresh_unknown_token_rejected(service):
    svc, _, token_repo = service
    token_repo.get_by_hash.return_value = None

    with pytest.raises(InvalidRefreshTokenError):
        await svc.refresh("nonexistent-token")


async def test_refresh_expired_token_rejected(service):
    svc, user_repo, token_repo = service
    fake_token = make_fake_token(expired=True)
    token_repo.get_by_hash.return_value = fake_token

    with pytest.raises(InvalidRefreshTokenError):
        await svc.refresh("expired-token")


async def test_refresh_revoked_token_rejected(service):
    svc, user_repo, token_repo = service
    fake_token = make_fake_token(revoked=True)
    token_repo.get_by_hash.return_value = fake_token

    with pytest.raises(InvalidRefreshTokenError):
        await svc.refresh("revoked-token")


async def test_refresh_inactive_user_rejected(service):
    svc, user_repo, token_repo = service
    fake_user = make_fake_user(is_active=False)
    fake_token = make_fake_token(user_id=fake_user.id)
    token_repo.get_by_hash.return_value = fake_token
    user_repo.get_by_id.return_value = fake_user

    with pytest.raises(InvalidRefreshTokenError):
        await svc.refresh("some-token")


async def test_refresh_failure_reasons_are_indistinguishable(service):
    """Unknown, expired, revoked, and inactive-owner must all raise the
    exact same exception type and message."""
    svc, user_repo, token_repo = service

    token_repo.get_by_hash.return_value = None
    with pytest.raises(InvalidRefreshTokenError) as unknown_exc:
        await svc.refresh("t1")

    token_repo.get_by_hash.return_value = make_fake_token(expired=True)
    with pytest.raises(InvalidRefreshTokenError) as expired_exc:
        await svc.refresh("t2")

    token_repo.get_by_hash.return_value = make_fake_token(revoked=True)
    with pytest.raises(InvalidRefreshTokenError) as revoked_exc:
        await svc.refresh("t3")

    assert str(unknown_exc.value) == str(expired_exc.value) == str(revoked_exc.value)


# --- Logout ---------------------------------------------------

async def test_logout_valid_token_revoked(service):
    svc, _, token_repo = service
    fake_token = make_fake_token()
    token_repo.get_by_hash.return_value = fake_token

    await svc.logout("some-token")

    token_repo.revoke.assert_called_once_with(fake_token)


async def test_logout_unknown_token_succeeds_silently(service):
    svc, _, token_repo = service
    token_repo.get_by_hash.return_value = None

    await svc.logout("nonexistent-token")  # must not raise

    token_repo.revoke.assert_not_called()


async def test_logout_already_revoked_token_succeeds_silently(service):
    svc, _, token_repo = service
    fake_token = make_fake_token(revoked=True)
    token_repo.get_by_hash.return_value = fake_token

    await svc.logout("already-revoked-token")  # must not raise

    token_repo.revoke.assert_not_called()


# --- Audit logging (Phase 4.3) ---------------------------------------------------
#
# Unlike the exceptions these failures raise (deliberately indistinguishable
# to the caller, to prevent enumeration), the audit log is internal-only and
# is free to record the real reason -- these tests assert on that reason via
# event_metadata, not just that *some* audit call happened.

async def test_register_success_records_audit_event(service):
    svc, user_repo, _ = service
    fake_user = make_fake_user(email="new@example.com")
    user_repo.create_user.return_value = fake_user

    await svc.register("new@example.com", "password123")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.USER_REGISTERED,
        actor_user_id=fake_user.id,
        target_type="user",
        target_id=fake_user.id,
    )


async def test_register_duplicate_email_records_audit_event(service):
    svc, user_repo, _ = service
    user_repo.create_user.side_effect = DuplicateEmailError("already exists")

    with pytest.raises(EmailAlreadyExistsError):
        await svc.register("dup@example.com", "password123")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.USER_REGISTRATION_FAILED,
        target_type="user",
        event_metadata={"attempted_email": "dup@example.com", "reason": "duplicate_email"},
    )


async def test_login_success_records_audit_event(service):
    svc, user_repo, _ = service
    fake_user = make_fake_user(password="correctpassword")
    user_repo.get_by_email.return_value = fake_user

    await svc.login("user@example.com", "correctpassword")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.USER_LOGIN_SUCCEEDED,
        actor_user_id=fake_user.id,
        target_type="user",
        target_id=fake_user.id,
    )


async def test_login_unknown_email_records_audit_event_with_reason(service):
    svc, user_repo, _ = service
    user_repo.get_by_email.return_value = None

    with pytest.raises(InvalidCredentialsError):
        await svc.login("nouser@example.com", "whatever")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.USER_LOGIN_FAILED,
        target_type="user",
        event_metadata={"attempted_email": "nouser@example.com", "reason": "unknown_email"},
    )


async def test_login_wrong_password_records_audit_event_with_reason(service):
    """Confirms the internal audit trail DOES distinguish this from an
    unknown email, even though the exception raised to the caller does not
    -- that distinction is exactly what makes the audit log valuable for
    security investigation without weakening the enumeration defense."""
    svc, user_repo, _ = service
    fake_user = make_fake_user(password="correctpassword")
    user_repo.get_by_email.return_value = fake_user

    with pytest.raises(InvalidCredentialsError):
        await svc.login("user@example.com", "wrongpassword")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.USER_LOGIN_FAILED,
        actor_user_id=fake_user.id,
        target_type="user",
        target_id=fake_user.id,
        event_metadata={"reason": "wrong_password"},
    )


async def test_login_inactive_user_records_audit_event_with_reason(service):
    svc, user_repo, _ = service
    fake_user = make_fake_user(password="correctpassword", is_active=False)
    user_repo.get_by_email.return_value = fake_user

    with pytest.raises(InactiveUserError):
        await svc.login("user@example.com", "correctpassword")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.USER_LOGIN_FAILED,
        actor_user_id=fake_user.id,
        target_type="user",
        target_id=fake_user.id,
        event_metadata={"reason": "inactive_account"},
    )


async def test_refresh_success_records_audit_event(service):
    svc, user_repo, token_repo = service
    fake_user = make_fake_user()
    fake_token = make_fake_token(user_id=fake_user.id)
    token_repo.get_by_hash.return_value = fake_token
    user_repo.get_by_id.return_value = fake_user

    await svc.refresh("some-raw-refresh-token")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.REFRESH_TOKEN_ROTATED,
        actor_user_id=fake_user.id,
        target_type="user",
        target_id=fake_user.id,
    )


async def test_refresh_unknown_token_records_audit_event_with_no_actor(service):
    svc, _, token_repo = service
    token_repo.get_by_hash.return_value = None

    with pytest.raises(InvalidRefreshTokenError):
        await svc.refresh("nonexistent-token")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.REFRESH_TOKEN_REJECTED, event_metadata={"reason": "unknown_token"}
    )


async def test_refresh_revoked_token_records_audit_event_with_actor(service):
    svc, _, token_repo = service
    fake_token = make_fake_token(revoked=True)
    token_repo.get_by_hash.return_value = fake_token

    with pytest.raises(InvalidRefreshTokenError):
        await svc.refresh("revoked-token")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.REFRESH_TOKEN_REJECTED,
        actor_user_id=fake_token.user_id,
        target_type="user",
        target_id=fake_token.user_id,
        event_metadata={"reason": "revoked_token"},
    )


async def test_refresh_expired_token_records_audit_event_with_reason(service):
    svc, _, token_repo = service
    fake_token = make_fake_token(expired=True)
    token_repo.get_by_hash.return_value = fake_token

    with pytest.raises(InvalidRefreshTokenError):
        await svc.refresh("expired-token")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.REFRESH_TOKEN_REJECTED,
        actor_user_id=fake_token.user_id,
        target_type="user",
        target_id=fake_token.user_id,
        event_metadata={"reason": "expired_token"},
    )


async def test_refresh_inactive_owner_records_audit_event_with_reason(service):
    svc, user_repo, token_repo = service
    fake_user = make_fake_user(is_active=False)
    fake_token = make_fake_token(user_id=fake_user.id)
    token_repo.get_by_hash.return_value = fake_token
    user_repo.get_by_id.return_value = fake_user

    with pytest.raises(InvalidRefreshTokenError):
        await svc.refresh("some-token")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.REFRESH_TOKEN_REJECTED,
        actor_user_id=fake_token.user_id,
        target_type="user",
        target_id=fake_token.user_id,
        event_metadata={"reason": "inactive_or_deleted_owner"},
    )


async def test_logout_success_records_audit_event(service):
    svc, _, token_repo = service
    fake_token = make_fake_token()
    token_repo.get_by_hash.return_value = fake_token

    await svc.logout("some-token")

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.USER_LOGOUT,
        actor_user_id=fake_token.user_id,
        target_type="user",
        target_id=fake_token.user_id,
    )


async def test_logout_no_op_does_not_record_audit_event(service):
    """A no-op logout (unknown or already-revoked token) carries no
    security signal worth logging -- unlike every other failure path in
    this file, this one is deliberately silent at the audit layer too."""
    svc, _, token_repo = service
    token_repo.get_by_hash.return_value = None

    await svc.logout("nonexistent-token")

    svc.audit_log_repository.record.assert_not_called()
