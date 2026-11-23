"""Esquemas Pydantic: validan CADA campo que entra y sale de la API.

Regla general: lista blanca de caracteres (solo se permite lo que se espera)
y `extra="forbid"` para rechazar campos desconocidos.
"""
import base64
import binascii
import re
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

# ---------- Expresiones regulares (listas blancas) ----------
EMAIL_RE = re.compile(
    r"^[a-z0-9._%+\-]{1,64}@(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
)
NAME_RE = re.compile(r"^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ][A-Za-zÁÉÍÓÚÜÑáéíóúüñ0-9 ._\-]{1,39}$")
PASSWORD_CHARS_RE = re.compile(r"^[\x21-\x7E]+$")  # ASCII visible, sin espacios
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

MAX_CIPHERTEXT_CHARS = 140_000  # ~100 KB de texto original ya cifrado y en base64
IV_BYTES = 12                   # tamaño estándar de IV para AES-GCM
GCM_TAG_BYTES = 16


class StrictModel(BaseModel):
    """Base: rechaza campos que no estén definidos."""

    model_config = ConfigDict(extra="forbid")


# ---------- Campos reutilizables ----------
def _clean_email(value):
    if not isinstance(value, str):
        return value
    value = value.strip().lower()
    if len(value) > 254 or not EMAIL_RE.fullmatch(value) or ".." in value:
        raise ValueError("Correo electrónico inválido.")
    return value


# ---------- Autenticación ----------
class RegisterIn(StrictModel):
    email: str = Field(max_length=254)
    display_name: str = Field(max_length=40)
    password: str = Field(max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, v):
        return _clean_email(v)

    @field_validator("display_name", mode="before")
    @classmethod
    def validate_name(cls, v):
        if not isinstance(v, str):
            return v
        v = v.strip()
        if not NAME_RE.fullmatch(v):
            raise ValueError(
                "El nombre debe tener de 2 a 40 caracteres: letras, números, espacio, punto, guion o guion bajo."
            )
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not (12 <= len(v) <= 128):
            raise ValueError("La contraseña debe tener entre 12 y 128 caracteres.")
        if not PASSWORD_CHARS_RE.fullmatch(v):
            raise ValueError("La contraseña solo puede usar caracteres ASCII visibles, sin espacios.")
        if not re.search(r"[a-z]", v):
            raise ValueError("La contraseña debe incluir una minúscula.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("La contraseña debe incluir una mayúscula.")
        if not re.search(r"\d", v):
            raise ValueError("La contraseña debe incluir un número.")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("La contraseña debe incluir un símbolo (por ejemplo ! # $ %).")
        return v


class LoginIn(StrictModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, v):
        return _clean_email(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        # En el login solo revisamos formato y longitud; la política de complejidad aplica al registrarse.
        if not (1 <= len(v) <= 128) or not PASSWORD_CHARS_RE.fullmatch(v):
            raise ValueError("Formato de contraseña inválido.")
        return v


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    display_name: str


class SessionOut(BaseModel):
    """Respuesta de login y de /me.

    kdf_salt y kdf_iterations son PÚBLICOS: el navegador los usa para derivar la
    clave maestra con PBKDF2. La clave derivada jamás se envía de vuelta.
    """

    user: UserOut
    kdf_salt: str
    kdf_iterations: int
    csrf_token: str


class MessageOut(BaseModel):
    message: str


# ---------- Notas (solo texto cifrado) ----------
class NoteIn(StrictModel):
    ciphertext: str = Field(max_length=MAX_CIPHERTEXT_CHARS)
    iv: str = Field(max_length=16)

    @field_validator("iv")
    @classmethod
    def validate_iv(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9+/]{16}", v):
            raise ValueError("IV inválido: debe ser base64 de 12 bytes (16 caracteres).")
        if len(base64.b64decode(v)) != IV_BYTES:
            raise ValueError("IV inválido: debe medir 12 bytes.")
        return v

    @field_validator("ciphertext")
    @classmethod
    def validate_ciphertext(cls, v: str) -> str:
        if len(v) % 4 != 0 or not BASE64_RE.fullmatch(v):
            raise ValueError("El texto cifrado debe estar en base64 válido.")
        try:
            raw = base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("El texto cifrado debe estar en base64 válido.")
        if len(raw) < GCM_TAG_BYTES + 1:
            raise ValueError("El texto cifrado es demasiado corto para ser AES-GCM.")
        return v


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    ciphertext: str
    iv: str
    created_at: datetime
    updated_at: datetime

    @field_serializer("created_at", "updated_at")
    def _as_utc_iso(self, value: datetime) -> str:
        # La BD guarda UTC "ingenuo"; se envía con zona para que JavaScript lo interprete bien.
        return value.replace(tzinfo=timezone.utc).isoformat()
