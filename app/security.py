"""Hash de contraseñas (Argon2id), sal del KDF y tokens JWT."""
import base64
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from .config import settings

# PasswordHasher() usa Argon2id con los parámetros recomendados por la librería.
_hasher = PasswordHasher()

# Hash falso: se verifica cuando el correo no existe, para que el tiempo de
# respuesta sea parecido y no se pueda adivinar qué correos están registrados.
DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def new_kdf_salt() -> str:
    """Sal aleatoria de 16 bytes (en base64) para PBKDF2 en el navegador."""
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


def create_access_token(user_id: int, token_version: int) -> tuple:
    """Devuelve (jwt, csrf_token). El csrf viaja dentro del JWT y también al frontend."""
    now = datetime.now(timezone.utc)
    csrf = secrets.token_urlsafe(32)
    payload = {
        "sub": str(user_id),
        "ver": token_version,
        "csrf": csrf,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM), csrf


def decode_access_token(token: str) -> Optional[dict]:
    """Devuelve los datos del JWT o None si es inválido/expirado/manipulado."""
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[JWT_ALGORITHM],  # lista fija: evita el ataque alg=none
            options={"require": ["exp", "iat", "sub", "ver", "csrf"]},
        )
    except jwt.PyJWTError:
        return None
