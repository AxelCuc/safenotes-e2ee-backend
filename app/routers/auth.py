"""Registro, login, sesión actual y logout."""
import logging
import math
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import COOKIE_NAME, get_current_user, user_from_cookie
from ..models import User, utcnow
from ..ratelimit import rate_limit
from ..schemas import LoginIn, MessageOut, RegisterIn, SessionOut, UserOut
from ..security import (
    DUMMY_HASH,
    create_access_token,
    hash_password,
    needs_rehash,
    new_kdf_salt,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
audit = logging.getLogger("safenotes.audit")

INVALID_CREDENTIALS = "Correo o contraseña incorrectos."


def _session_out(user: User, csrf: str) -> SessionOut:
    return SessionOut(
        user=UserOut.model_validate(user),
        kdf_salt=user.kdf_salt,
        kdf_iterations=user.kdf_iterations,
        csrf_token=csrf,
    )


@router.post(
    "/register",
    response_model=MessageOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("register", 10, 600))],
)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    user = User(
        email=data.email,
        display_name=data.display_name,
        password_hash=hash_password(data.password),  # Argon2id
        kdf_salt=new_kdf_salt(),
        kdf_iterations=settings.kdf_iterations,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Ese correo ya está registrado.")
    audit.info("registro: usuario creado (%s)", data.email)
    return MessageOut(message="Cuenta creada. Ya puedes iniciar sesión.")


@router.post(
    "/login",
    response_model=SessionOut,
    dependencies=[Depends(rate_limit("login", 10, 60))],
)
def login(data: LoginIn, response: Response, db: Session = Depends(get_db)):
    now = utcnow()
    user = db.scalar(select(User).where(User.email == data.email))

    if user is None:
        verify_password(DUMMY_HASH, data.password)  # gasta el mismo tiempo que un login real
        audit.warning("login fallido: correo inexistente (%s)", data.email)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    # Cuenta bloqueada: ni siquiera se revisa la contraseña.
    if user.locked_until and user.locked_until > now:
        minutes = math.ceil((user.locked_until - now).total_seconds() / 60)
        raise HTTPException(
            status.HTTP_423_LOCKED,
            f"Cuenta bloqueada por demasiados intentos fallidos. Intenta de nuevo en {minutes} minuto(s).",
        )

    if not verify_password(user.password_hash, data.password):
        user.failed_attempts += 1
        if user.failed_attempts >= settings.max_failed_attempts:
            user.locked_until = now + timedelta(minutes=settings.lock_minutes)
            user.failed_attempts = 0
            db.commit()
            audit.warning("cuenta BLOQUEADA (%s) por %s intentos fallidos", data.email, settings.max_failed_attempts)
            raise HTTPException(
                status.HTTP_423_LOCKED,
                f"Cuenta bloqueada por {settings.lock_minutes} minutos tras {settings.max_failed_attempts} intentos fallidos.",
            )
        db.commit()
        audit.warning("login fallido: contraseña incorrecta (%s)", data.email)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    # Login correcto
    user.failed_attempts = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):  # actualiza el hash si cambiaron los parámetros
        user.password_hash = hash_password(data.password)
    db.commit()

    token, csrf = create_access_token(user.id, user.token_version)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=settings.access_token_minutes * 60,
        httponly=True,                  # JavaScript no puede leer la cookie (anti-XSS)
        secure=settings.cookie_secure,  # True cuando se usa HTTPS
        samesite="lax",                 # no se envía en peticiones cruzadas (anti-CSRF)
        path="/",
    )
    audit.info("login correcto (%s)", data.email)
    return _session_out(user, csrf)


@router.get("/me", response_model=SessionOut)
def me(request: Request, user: User = Depends(get_current_user)):
    return _session_out(user, request.state.csrf)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, db: Session = Depends(get_db)):
    found = user_from_cookie(request, db)
    if found is not None:
        user, _payload = found
        user.token_version += 1  # invalida TODOS los JWT emitidos antes
        db.commit()
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(
        COOKIE_NAME, path="/", secure=settings.cookie_secure, httponly=True, samesite="lax"
    )
    return response
