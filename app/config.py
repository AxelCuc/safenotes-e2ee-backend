"""Configuración central.

Todo tiene un valor por defecto que funciona en desarrollo local.
Para producción se cambia con variables de entorno (ver README).
"""
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

# Carpeta "backend/" (un nivel arriba de "app/")
BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "si", "sí"}


def _load_secret_key() -> str:
    """Clave para firmar los JWT.

    1. Si existe la variable de entorno SECRET_KEY, se usa esa.
    2. Si no, se genera una aleatoria y se guarda en backend/.secret_key
       (así las sesiones sobreviven a reinicios y no hay que configurar nada).
    """
    from_env = os.environ.get("SECRET_KEY")
    if from_env:
        if len(from_env) < 32:
            raise RuntimeError("SECRET_KEY debe tener al menos 32 caracteres.")
        return from_env

    key_file = BASE_DIR / ".secret_key"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()

    key = secrets.token_urlsafe(64)
    key_file.write_text(key, encoding="utf-8")
    try:
        os.chmod(key_file, 0o600)  # solo el dueño (en Windows no tiene efecto)
    except OSError:
        pass
    return key


@dataclass(frozen=True)
class Settings:
    app_name: str
    database_url: str
    secret_key: str
    cors_origins: list
    cookie_secure: bool
    enable_docs: bool
    # --- Parámetros de seguridad ---
    access_token_minutes: int = 30      # duración de la sesión (JWT)
    max_failed_attempts: int = 5        # intentos fallidos antes de bloquear
    lock_minutes: int = 15              # duración del bloqueo
    kdf_iterations: int = 600_000       # PBKDF2-HMAC-SHA256 (recomendación OWASP)
    max_notes_per_user: int = 500
    max_body_bytes: int = 262_144       # 256 KB por petición


def load_settings() -> Settings:
    default_db = f"sqlite:///{(BASE_DIR / 'safenotes.db').as_posix()}"
    origins = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    return Settings(
        app_name="SafeNotes E2EE",
        database_url=os.environ.get("DATABASE_URL", default_db),
        secret_key=_load_secret_key(),
        cors_origins=[o.strip() for o in origins.split(",") if o.strip()],
        cookie_secure=_env_bool("COOKIE_SECURE", False),  # True cuando uses HTTPS
        enable_docs=_env_bool("ENABLE_DOCS", True),
    )


settings = load_settings()
