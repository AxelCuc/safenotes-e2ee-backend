"""Pruebas de seguridad de la API.  Ejecutar:  python -m pytest -v"""
import base64
import os
import uuid

PASSWORD = "Str0ng!Passw0rd#"


# ---------- Utilidades ----------
def new_email() -> str:
    return f"user_{uuid.uuid4().hex[:10]}@example.com"


def register(client, email=None, password=PASSWORD, name="Usuario Prueba"):
    email = email or new_email()
    response = client.post(
        "/api/auth/register",
        json={"email": email, "display_name": name, "password": password},
    )
    return email, response


def logged_in_client(make_client):
    client = make_client()
    email, response = register(client)
    assert response.status_code == 201, response.text
    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    client.headers.update({"X-CSRF-Token": response.json()["csrf_token"]})
    return client, email


def fake_encrypted_note() -> dict:
    """Simula lo que enviaría el navegador: bytes aleatorios en base64 (no hay texto legible)."""
    return {
        "ciphertext": base64.b64encode(os.urandom(48)).decode(),
        "iv": base64.b64encode(os.urandom(12)).decode(),
    }


# ---------- Registro y validación ----------
def test_register_and_login_flow(make_client):
    client = make_client()
    email, response = register(client)
    assert response.status_code == 201

    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == email
    assert body["kdf_iterations"] >= 600_000
    assert len(body["kdf_salt"]) == 24
    assert body["csrf_token"]

    set_cookie = response.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie

    assert client.get("/api/auth/me").status_code == 200


def test_duplicate_email_rejected(make_client):
    client = make_client()
    email, _ = register(client)
    _, response = register(client, email=email)
    assert response.status_code == 409


def test_weak_password_rejected_and_not_echoed(make_client):
    client = make_client()
    weak = "Aa1!short"
    _, response = register(client, password=weak)
    assert response.status_code == 422
    assert weak not in response.text  # la API no devuelve la contraseña enviada


def test_invalid_fields_rejected(make_client):
    client = make_client()
    base = {"email": new_email(), "display_name": "Ana", "password": PASSWORD}

    for bad in [
        {**base, "email": "no-es-un-correo"},
        {**base, "email": "a<script>@example.com"},
        {**base, "display_name": "<script>alert(1)</script>"},
        {**base, "display_name": "'; DROP TABLE users;--"},
        {**base, "is_admin": True},  # campo desconocido
    ]:
        assert client.post("/api/auth/register", json=bad).status_code == 422, bad


# ---------- Bloqueo de cuenta y rate limiting ----------
def test_account_locks_after_5_failed_attempts(make_client):
    client = make_client()
    email, _ = register(client)
    wrong = {"email": email, "password": "Incorrecta!123abc"}

    for _ in range(4):
        assert client.post("/api/auth/login", json=wrong).status_code == 401
    assert client.post("/api/auth/login", json=wrong).status_code == 423  # 5.º intento

    # Aun con la contraseña correcta, la cuenta sigue bloqueada
    correct = {"email": email, "password": PASSWORD}
    assert client.post("/api/auth/login", json=correct).status_code == 423


def test_unknown_email_gets_generic_error(make_client):
    client = make_client()
    response = client.post(
        "/api/auth/login", json={"email": new_email(), "password": "Whatever!12345"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Correo o contraseña incorrectos."


def test_login_rate_limit(make_client):
    client = make_client()
    payload = {"email": new_email(), "password": "Whatever!12345"}
    codes = [client.post("/api/auth/login", json=payload).status_code for _ in range(11)]
    assert codes[:10] == [401] * 10
    assert codes[10] == 429


# ---------- Sesión, JWT y CSRF ----------
def test_notes_require_session(make_client):
    client = make_client()
    assert client.get("/api/notes").status_code == 401


def test_post_without_csrf_token_is_rejected(make_client):
    client, _ = logged_in_client(make_client)
    client.headers.pop("X-CSRF-Token")
    assert client.post("/api/notes", json=fake_encrypted_note()).status_code == 403

    client.headers["X-CSRF-Token"] = "token-falso"
    assert client.post("/api/notes", json=fake_encrypted_note()).status_code == 403


def test_logout_revokes_old_token(make_client):
    client, _ = logged_in_client(make_client)
    old_token = client.cookies.get("sn_session")
    assert old_token

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401

    # Aunque alguien conserve el JWT viejo, ya no sirve
    response = client.get("/api/auth/me", headers={"Cookie": f"sn_session={old_token}"})
    assert response.status_code == 401


# ---------- Notas cifradas e IDOR ----------
def test_notes_crud(make_client):
    client, _ = logged_in_client(make_client)
    note = fake_encrypted_note()

    created = client.post("/api/notes", json=note)
    assert created.status_code == 201
    note_id = created.json()["id"]
    assert created.json()["ciphertext"] == note["ciphertext"]
    assert created.json()["iv"] == note["iv"]

    assert client.get(f"/api/notes/{note_id}").status_code == 200
    assert [n["id"] for n in client.get("/api/notes").json()] == [note_id]

    updated = fake_encrypted_note()
    assert client.put(f"/api/notes/{note_id}", json=updated).json()["ciphertext"] == updated["ciphertext"]

    assert client.delete(f"/api/notes/{note_id}").status_code == 204
    assert client.get(f"/api/notes/{note_id}").status_code == 404


def test_plaintext_is_rejected_by_the_api(make_client):
    client, _ = logged_in_client(make_client)
    good_iv = base64.b64encode(os.urandom(12)).decode()
    for bad in [
        {"ciphertext": "Mi contraseña del banco es 1234", "iv": good_iv},
        {"ciphertext": base64.b64encode(os.urandom(48)).decode(), "iv": "corto"},
        {"ciphertext": base64.b64encode(b"abc").decode(), "iv": good_iv},  # demasiado corto
        {**fake_encrypted_note(), "title": "texto plano"},  # campo extra
    ]:
        assert client.post("/api/notes", json=bad).status_code == 422, bad


def test_idor_user_cannot_touch_other_users_notes(make_client):
    client_a, _ = logged_in_client(make_client)
    client_b, _ = logged_in_client(make_client)

    note_id = client_a.post("/api/notes", json=fake_encrypted_note()).json()["id"]

    # B intenta leer, modificar y borrar la nota de A -> 404 (no revela que existe)
    assert client_b.get(f"/api/notes/{note_id}").status_code == 404
    assert client_b.put(f"/api/notes/{note_id}", json=fake_encrypted_note()).status_code == 404
    assert client_b.delete(f"/api/notes/{note_id}").status_code == 404
    assert client_b.get("/api/notes").json() == []

    # La nota de A sigue intacta
    assert client_a.get(f"/api/notes/{note_id}").status_code == 200


def test_note_id_must_be_uuid(make_client):
    client, _ = logged_in_client(make_client)
    assert client.get("/api/notes/1").status_code == 422
    assert client.get("/api/notes/1%20OR%201=1").status_code == 422


# ---------- Cabeceras ----------
def test_security_headers_present(make_client):
    client = make_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


def test_cors_only_allows_listed_origins(make_client):
    client = make_client()
    ok = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert ok.headers.get("access-control-allow-credentials") == "true"

    evil = client.get("/api/health", headers={"Origin": "http://sitio-malicioso.com"})
    assert "access-control-allow-origin" not in evil.headers
