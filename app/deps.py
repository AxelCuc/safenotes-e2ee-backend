"""Dependencias compartidas: usuario actual a partir de la cookie JWT + verificación CSRF."""
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .database import get_db
from .models import User
from .security import decode_access_token

COOKIE_NAME = "sn_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def user_from_cookie(request: Request, db: Session) -> Optional[tuple]:
    """Devuelve (usuario, datos_del_jwt) o None si no hay sesión válida."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    payload = decode_access_token(token)
    if payload is None:
        return None
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        return None
    user = db.get(User, user_id)
    # Si el usuario ya no existe o hizo logout (token_version cambió), el token no sirve.
    if user is None or payload.get("ver") != user.token_version:
        return None
    return user, payload


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    found = user_from_cookie(request, db)
    if found is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión no válida o expirada.")
    user, payload = found
    csrf = str(payload.get("csrf", ""))

    # Protección CSRF: toda petición que modifica datos debe traer el token en una cabecera.
    if request.method not in SAFE_METHODS:
        sent = request.headers.get("x-csrf-token", "")
        if not sent or not secrets.compare_digest(sent.encode(), csrf.encode()):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Token CSRF inválido o ausente.")

    request.state.csrf = csrf
    return user
