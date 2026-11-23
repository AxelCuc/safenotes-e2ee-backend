"""Configuración de las pruebas: usan una base de datos temporal, nunca la real."""
import os
import tempfile
from contextlib import ExitStack

# IMPORTANTE: estas variables se definen ANTES de importar la app.
_TMP_DIR = tempfile.mkdtemp(prefix="safenotes_test_")
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(_TMP_DIR, "test.db").replace("\\", "/")
os.environ["SECRET_KEY"] = "clave-solo-para-pruebas-" + "x" * 40

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.ratelimit import limiter  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    limiter.reset()
    yield


@pytest.fixture()
def make_client():
    """Fábrica de clientes HTTP; cada uno tiene su propia cookie (como un navegador distinto)."""
    with ExitStack() as stack:

        def _make():
            return stack.enter_context(TestClient(app))

        yield _make
