"""Tablas de la base de datos.

Zero-Knowledge: la tabla `notes` NO tiene columnas "title" ni "body".
Solo guarda `ciphertext` + `iv`, que para el servidor es ruido aleatorio.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    """Fecha/hora UTC sin zona horaria (SQLite no guarda zonas)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(40), nullable=False)

    # Hash Argon2id de la contraseña (nunca la contraseña en claro)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Parámetros PÚBLICOS para que el navegador derive la clave maestra con PBKDF2.
    # La sal no es secreta; lo secreto es la contraseña, y la clave derivada nunca llega aquí.
    kdf_salt: Mapped[str] = mapped_column(String(32), nullable=False)  # base64 de 16 bytes
    kdf_iterations: Mapped[int] = mapped_column(Integer, nullable=False)

    # Bloqueo de cuenta
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Subir este número invalida todos los JWT anteriores (logout real)
    token_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    notes: Mapped[list["Note"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )


class Note(Base):
    __tablename__ = "notes"

    # UUID aleatorio: no se puede adivinar ni enumerar (1, 2, 3...) -> ayuda contra IDOR
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )

    # AES-GCM(256): texto cifrado en base64 (el título y el cuerpo viajan dentro, cifrados)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    # Vector de inicialización de 12 bytes en base64 (16 caracteres)
    iv: Mapped[str] = mapped_column(String(16), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )

    owner: Mapped["User"] = relationship(back_populates="notes")
