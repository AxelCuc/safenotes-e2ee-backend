# SafeNotes E2EE — Backend (FastAPI + SQLite)

API Zero-Knowledge: **solo guarda texto cifrado (`ciphertext`) y el vector de inicialización (`iv`)**.
Todo el cifrado AES-GCM ocurre en el navegador; el servidor nunca ve títulos ni contenido.

## 1. Requisitos

- **Python 3.12 o 3.13** (descarga en https://www.python.org/downloads/ — en Windows marca **"Add python.exe to PATH"**).

## 2. Instalación (una sola vez)

Abre una terminal **dentro de la carpeta `backend`**.

**Windows (CMD o PowerShell):**

```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

> Si PowerShell dice "la ejecución de scripts está deshabilitada", ejecuta primero:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` y vuelve a activar el entorno.
> (O usa CMD en lugar de PowerShell.)

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Sabrás que el entorno está activo porque la terminal muestra `(.venv)` al inicio.

## 3. Arrancar el servidor

Con el entorno activado, dentro de `backend`:

```bash
uvicorn app.main:app --reload --port 8000
```

- API: http://127.0.0.1:8000/api/health  (debe responder `{"status":"ok"}`)
- Documentación interactiva (Swagger): http://127.0.0.1:8000/docs
- Se crea automáticamente `safenotes.db` (SQLite) y `.secret_key` (clave para firmar JWT). **No subas estos archivos a GitHub.**

## 4. Pruebas automáticas (opcional pero recomendado)

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

Verifican: bloqueo tras 5 intentos, rate limiting, IDOR, CSRF, validación, CORS, cabeceras y que la API rechaza texto plano.

## 5. Ver qué guarda realmente el servidor (demostración)

```bash
python scripts/ver_base_de_datos.py
```

Muestra la contraseña como hash Argon2id y las notas como ruido cifrado.

## 6. Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| GET | `/api/health` | no | Estado del servidor |
| POST | `/api/auth/register` | no | Crea cuenta (`email`, `display_name`, `password`) |
| POST | `/api/auth/login` | no | Inicia sesión; devuelve `kdf_salt`, `kdf_iterations`, `csrf_token` y pone la cookie HttpOnly |
| GET | `/api/auth/me` | cookie | Datos de la sesión actual |
| POST | `/api/auth/logout` | cookie | Cierra sesión e invalida los JWT anteriores |
| GET | `/api/notes` | cookie | Lista las notas **del usuario** (`?limit=&offset=`) |
| POST | `/api/notes` | cookie + CSRF | Crea nota (`ciphertext`, `iv`) |
| GET | `/api/notes/{id}` | cookie | Una nota (id = UUID) |
| PUT | `/api/notes/{id}` | cookie + CSRF | Reemplaza `ciphertext` e `iv` |
| DELETE | `/api/notes/{id}` | cookie + CSRF | Borra la nota |

Las peticiones que modifican datos (POST/PUT/DELETE de notas) llevan la cabecera `X-CSRF-Token` con el valor recibido en el login.

## 7. Mapa de requisitos de seguridad (para tu reporte)

| Requisito de la materia | Dónde está |
|---|---|
| Contraseñas con Argon2id | `app/security.py` (`PasswordHasher`) |
| Validación de cada campo con Pydantic | `app/schemas.py` (listas blancas con regex, `extra="forbid"`) |
| JWT en cookie HttpOnly | `app/security.py` + `app/routers/auth.py` (`httponly`, `samesite=lax`, `secure` configurable) |
| Logout real (revocación) | `token_version` en `User` + `app/deps.py` |
| Rate limiting | `app/ratelimit.py` (login 10/min, registro 10/10 min, notas 120/min por IP) |
| Bloqueo tras 5 intentos | `app/routers/auth.py` (15 min, HTTP 423) |
| Cabeceras de seguridad y CSP | `app/main.py` (`security_middleware`) |
| CORS restringido | `app/main.py` (orígenes explícitos, nunca `*`) |
| CSRF | `app/deps.py` (token en cabecera comparado contra el del JWT) |
| Prevención de IDOR | `app/routers/notes.py` (filtro `owner_id` + ids UUID + 404) |
| Zero-Knowledge | `app/models.py` / `app/schemas.py`: no existen columnas ni campos de texto plano |
| Errores sin filtrar datos | `app/main.py` (`validation_error_handler`) |
| Enumeración de usuarios | Mismo mensaje y mismo tiempo (hash falso) si el correo no existe |

## 8. Limitaciones que conviene mencionar en tu defensa

- **El servidor recibe la contraseña al iniciar sesión** (para compararla con el hash Argon2id), igual que en cualquier login. La *clave maestra* PBKDF2 se deriva en el navegador y nunca se envía, pero en producción **es obligatorio usar HTTPS** para proteger la contraseña en tránsito. Una mejora avanzada: derivar en el navegador una segunda clave independiente solo para autenticarse (como hacen Bitwarden y similares), de modo que la contraseña real nunca salga del navegador.
- **Si el usuario olvida su contraseña, sus notas no se pueden recuperar** (es la consecuencia natural del cifrado de extremo a extremo).
- El rate limiter vive en memoria: se reinicia al reiniciar el servidor y no sirve con varias instancias (para eso se usaría Redis).

## 9. Variables de entorno (opcionales)

| Variable | Por defecto | Uso |
|---|---|---|
| `SECRET_KEY` | se genera en `.secret_key` | Clave de firma de JWT (mínimo 32 caracteres) |
| `DATABASE_URL` | `sqlite:///.../safenotes.db` | Ubicación de la base de datos |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Orígenes permitidos, separados por coma |
| `COOKIE_SECURE` | `false` | Poner `true` cuando uses HTTPS |
| `ENABLE_DOCS` | `true` | Poner `false` para ocultar `/docs` en producción |
