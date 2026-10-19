from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import get_settings
from src.core.exceptions import (
    ConflictError,
    ForbiddenError,
    TokenInvalidError,
    UnauthorizedError,
)
from src.core.mail import Message, action_link, get_mail_backend
from src.core.security import (
    create_access_token,
    generate_token,
    hash_password,
    hash_token,
    verify_password,
)
from src.modules.auth import repository as auth_repo
from src.modules.auth.models import AuthToken, User
from src.modules.auth.schemas import (
    AuthResponse,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    UserOut,
)

log = structlog.get_logger(__name__)

REFRESH = "refresh"
PASSWORD_RESET = "password_reset"
EMAIL_VERIFY = "email_verify"
EMAIL_CHANGE = "email_change"

GENERIC_FORGOT_PASSWORD = "If an account exists for that email, a reset link has been sent."


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    # SQLite returns naive datetimes; they are always stored as UTC.
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def _issue_secret(
    db: AsyncSession, user: User, kind: str, lifetime: timedelta, extra: str | None = None
) -> str:
    raw = generate_token()
    await auth_repo.create_auth_token(
        db, user.id, kind, hash_token(raw), _now() + lifetime, extra=extra
    )
    return raw


async def _consume_secret(db: AsyncSession, kind: str, raw: str) -> AuthToken:
    """Look up a single-use token and mark it used; reject unknown, used or expired ones."""
    token = await auth_repo.get_auth_token(db, kind, hash_token(raw))
    if token is None or token.used_at is not None or _aware(token.expires_at) <= _now():
        raise TokenInvalidError("Invalid or expired token")
    token.used_at = _now()
    await db.flush()
    return token


async def issue_tokens(db: AsyncSession, user: User) -> AuthResponse:
    settings = get_settings()
    access = create_access_token({"sub": str(user.id), "tv": user.token_version})
    refresh = await _issue_secret(
        db, user, REFRESH, timedelta(days=settings.REFRESH_TOKEN_EXPIRES_DAYS)
    )
    return AuthResponse(
        access_token=access, refresh_token=refresh, user=UserOut.model_validate(user)
    )


async def _send_verification_email(db: AsyncSession, user: User) -> None:
    settings = get_settings()
    raw = await _issue_secret(
        db, user, EMAIL_VERIFY, timedelta(hours=settings.EMAIL_TOKEN_EXPIRES_HOURS)
    )
    await get_mail_backend().send(
        Message(
            to=user.email,
            subject="Verify your Sidewalk email",
            body=f"Confirm your email address: {action_link('verify-email', raw)}",
        )
    )


async def register(db: AsyncSession, payload: RegisterRequest) -> AuthResponse:
    existing = await auth_repo.get_user_by_email(db, payload.email)
    if existing:
        raise ConflictError("A user with this email already exists", field="email")
    hashed = hash_password(payload.password)
    # The get_user_by_email check above is not atomic with the insert below:
    # two concurrent registrations for the same email can both pass it and
    # both reach create_user, in which case the users.email unique
    # constraint raises IntegrityError for whichever commits second. Catch
    # it here and surface it as the same graceful ConflictError, rather than
    # letting a raw IntegrityError bubble up as an unhandled 500.
    try:
        user = await auth_repo.create_user(db, payload.email, hashed)
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise ConflictError("A user with this email already exists", field="email") from None
    log.info("register_user", user_id=str(user.id), email=user.email)
    await _send_verification_email(db, user)
    response = await issue_tokens(db, user)
    await db.commit()
    return response


async def login(db: AsyncSession, payload: LoginRequest) -> AuthResponse:
    user = await auth_repo.get_user_by_email(db, payload.email)
    if not user:
        raise UnauthorizedError("Invalid credentials")
    if not verify_password(payload.password, user.password_hash):
        raise UnauthorizedError("Invalid credentials")
    if not user.is_active:
        raise UnauthorizedError("Account inactive")
    response = await issue_tokens(db, user)
    await db.commit()
    return response


async def refresh(db: AsyncSession, raw_refresh_token: str) -> AuthResponse:
    """
    Exchange a refresh token for a new access/refresh pair (rotation). Presenting a token that
    was already rotated means it leaked, so every session of that user is revoked.
    """
    token = await auth_repo.get_auth_token(db, REFRESH, hash_token(raw_refresh_token))
    if token is None or _aware(token.expires_at) <= _now():
        raise TokenInvalidError("Invalid or expired token")
    user = await auth_repo.get_user_by_id(db, token.user_id)
    if user is None or not user.is_active:
        raise UnauthorizedError("User not found or inactive")
    if token.used_at is not None:
        log.warning("refresh_token_reuse_detected", user_id=str(user.id))
        await revoke_all_sessions(db, user)
        # Persist the revocation even though this request fails.
        await db.commit()
        raise TokenInvalidError("Invalid or expired token")
    token.used_at = _now()
    await db.flush()
    response = await issue_tokens(db, user)
    await db.commit()
    return response


async def revoke_all_sessions(db: AsyncSession, user: User) -> None:
    await auth_repo.bump_token_version(db, user)
    await auth_repo.revoke_user_tokens(db, user.id, REFRESH)


async def logout(db: AsyncSession, user: User) -> None:
    await revoke_all_sessions(db, user)
    await db.commit()
    log.info("logout", user_id=str(user.id))


async def change_password(
    db: AsyncSession, user: User, current_password: str, new_password: str
) -> AuthResponse:
    if not verify_password(current_password, user.password_hash):
        raise UnauthorizedError("Current password is incorrect")
    user.password_hash = hash_password(new_password)
    await revoke_all_sessions(db, user)
    log.info("password_changed", user_id=str(user.id))
    # Every older token is now invalid; hand back a fresh pair for this session.
    response = await issue_tokens(db, user)
    await db.commit()
    return response


async def forgot_password(db: AsyncSession, email: str) -> MessageResponse:
    user = await auth_repo.get_user_by_email(db, email)
    if user is not None and user.is_active:
        settings = get_settings()
        await auth_repo.revoke_user_tokens(db, user.id, PASSWORD_RESET)
        raw = await _issue_secret(
            db, user, PASSWORD_RESET, timedelta(minutes=settings.RESET_TOKEN_EXPIRES_MINUTES)
        )
        await get_mail_backend().send(
            Message(
                to=user.email,
                subject="Reset your Sidewalk password",
                body=f"Choose a new password: {action_link('reset-password', raw)}",
            )
        )
    await db.commit()
    # Same answer whether or not the account exists.
    return MessageResponse(message=GENERIC_FORGOT_PASSWORD)


async def reset_password(db: AsyncSession, raw_token: str, new_password: str) -> MessageResponse:
    token = await _consume_secret(db, PASSWORD_RESET, raw_token)
    user = await auth_repo.get_user_by_id(db, token.user_id, raise_if_not_found=True)
    assert user is not None
    user.password_hash = hash_password(new_password)
    await revoke_all_sessions(db, user)
    await db.commit()
    log.info("password_reset", user_id=str(user.id))
    return MessageResponse(message="Password updated. Please sign in again.")


async def verify_email(db: AsyncSession, raw_token: str) -> MessageResponse:
    token = await _consume_secret(db, EMAIL_VERIFY, raw_token)
    user = await auth_repo.get_user_by_id(db, token.user_id, raise_if_not_found=True)
    assert user is not None
    user.email_verified = True
    await db.commit()
    return MessageResponse(message="Email verified.")


async def request_email_change(
    db: AsyncSession, user: User, new_email: str, current_password: str | None
) -> None:
    """Start an email change: nothing changes until the new address confirms the link."""
    if not current_password or not verify_password(current_password, user.password_hash):
        raise ForbiddenError("Current password is required to change email")
    existing = await auth_repo.get_user_by_email(db, new_email)
    if existing and existing.id != user.id:
        raise ConflictError("A user with this email already exists", field="email")
    settings = get_settings()
    await auth_repo.revoke_user_tokens(db, user.id, EMAIL_CHANGE)
    raw = await _issue_secret(
        db,
        user,
        EMAIL_CHANGE,
        timedelta(hours=settings.EMAIL_TOKEN_EXPIRES_HOURS),
        extra=new_email,
    )
    user.pending_email = new_email
    await db.commit()
    await get_mail_backend().send(
        Message(
            to=new_email,
            subject="Confirm your new Sidewalk email",
            body=f"Confirm this address: {action_link('confirm-email-change', raw)}",
        )
    )


async def confirm_email_change(db: AsyncSession, raw_token: str) -> MessageResponse:
    token = await _consume_secret(db, EMAIL_CHANGE, raw_token)
    user = await auth_repo.get_user_by_id(db, token.user_id, raise_if_not_found=True)
    assert user is not None and token.extra
    existing = await auth_repo.get_user_by_email(db, token.extra)
    if existing and existing.id != user.id:
        raise ConflictError("A user with this email already exists", field="email")
    user.email = token.extra
    user.pending_email = None
    user.email_verified = True
    await db.commit()
    return MessageResponse(message="Email updated.")


__all__ = [
    "change_password",
    "confirm_email_change",
    "forgot_password",
    "login",
    "logout",
    "refresh",
    "register",
    "request_email_change",
    "reset_password",
    "verify_email",
]
