"""Muestra lo que el servidor REALMENTE guarda (ideal para la demostración Zero-Knowledge).

Uso (desde la carpeta backend, con o sin el entorno virtual activado):
    python scripts/ver_base_de_datos.py
"""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "safenotes.db"

if not DB_PATH.exists():
    raise SystemExit("Todavía no existe safenotes.db. Arranca el servidor y crea una cuenta primero.")

con = sqlite3.connect(DB_PATH)
con.row_factory = sqlite3.Row

print("=== USUARIOS (la contraseña es un hash Argon2id, no el texto real) ===")
for row in con.execute(
    "SELECT id, email, display_name, substr(password_hash, 1, 32) || '...' AS password_hash, "
    "kdf_salt, kdf_iterations, failed_attempts, locked_until FROM users"
):
    print(dict(row))

print()
print("=== NOTAS (solo ruido cifrado: no hay título ni contenido legible) ===")
for row in con.execute(
    "SELECT id, owner_id, substr(ciphertext, 1, 64) || '...' AS ciphertext, "
    "length(ciphertext) AS largo, iv, created_at FROM notes"
):
    print(dict(row))

con.close()
