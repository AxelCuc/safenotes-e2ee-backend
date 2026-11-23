"""Punto de entrada de la API.  Arranque:  uvicorn app.main:app --reload --port 8000"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import models  # noqa: F401  (registra las tablas antes de crearlas)
from .config import settings
from .database import Base, engine
from .routers import auth, notes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)  # crea safenotes.db y las tablas si no existen
    yield


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="API Zero-Knowledge: solo almacena texto cifrado (AES-GCM) generado en el navegador.",
    lifespan=lifespan,
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

# ---------- Cabeceras de seguridad (incluye CSP) ----------
# La API solo devuelve JSON, así que su CSP es lo más restrictivo posible.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# La página /docs (Swagger) necesita cargar scripts de un CDN, por eso lleva una CSP más abierta.
DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'"
)
DOCS_PATHS = {"/docs", "/docs/oauth2-redirect", "/openapi.json"}


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    response = None

    # Límite de tamaño del cuerpo de la petición
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > settings.max_body_bytes:
                response = JSONResponse(status_code=413, content={"detail": "La petición es demasiado grande."})
        except ValueError:
            response = JSONResponse(status_code=400, content={"detail": "Content-Length inválido."})

    if response is None:
        response = await call_next(request)

    headers = response.headers
    headers["X-Content-Type-Options"] = "nosniff"
    headers["X-Frame-Options"] = "DENY"
    headers["Referrer-Policy"] = "no-referrer"
    headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.url.path in DOCS_PATHS:
        headers["Content-Security-Policy"] = DOCS_CSP
    else:
        headers["Content-Security-Policy"] = API_CSP
        headers["Cache-Control"] = "no-store"  # nunca cachear respuestas de la API
    if settings.cookie_secure:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ---------- CORS ----------
# Se agrega DESPUÉS del middleware anterior para que quede como capa más externa.
# Orígenes explícitos (nunca "*") porque usamos cookies (credentials).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
    max_age=600,
)


# ---------- Errores de validación sin eco de datos ----------
# Por defecto FastAPI devuelve el valor enviado (¡incluida la contraseña!). Aquí solo
# devolvemos el campo y el mensaje.
@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        campo = ".".join(str(p) for p in err.get("loc", ()) if p not in ("body", "query", "path"))
        mensaje = str(err.get("msg", "Dato inválido")).removeprefix("Value error, ")
        errors.append({"campo": campo, "mensaje": mensaje})
    return JSONResponse(status_code=422, content={"detail": "Datos inválidos.", "errors": errors})


app.include_router(auth.router)
app.include_router(notes.router)


@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok"}
