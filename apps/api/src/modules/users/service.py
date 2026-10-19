import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import ConflictError
from src.modules.auth import repository as user_repository
from src.modules.auth import service as auth_service
from src.modules.auth.models import User
from src.modules.auth.schemas import AuthResponse
from src.modules.users.schemas import (
    ChangePasswordRequest,
    UpdateProfileRequest,
    UserProfileResponse,
)

log = structlog.get_logger(__name__)


async def update_profile(
    db: AsyncSession, user: User, payload: UpdateProfileRequest
) -> UserProfileResponse:
    """
    Email changes are never applied directly: the caller must prove knowledge of the current
    password, and the new address stays in ``pending_email`` until its owner follows the
    confirmation link (``POST /auth/confirm-email-change``).
    """
    if payload.email is not None and payload.email != user.email:
        existing = await user_repository.get_user_by_email(db, payload.email)
        if existing and existing.id != user.id:
            raise ConflictError("A user with this email already exists", field="email")
        await auth_service.request_email_change(
            db, user, str(payload.email), payload.current_password
        )
        log.info("email_change_requested", user_id=str(user.id))
    return UserProfileResponse.model_validate(user)


async def change_password(
    db: AsyncSession, user: User, payload: ChangePasswordRequest
) -> AuthResponse:
    return await auth_service.change_password(
        db, user, payload.current_password, payload.new_password
    )
