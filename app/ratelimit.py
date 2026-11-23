"""Rate limiting en memoria (ventana deslizante) por IP y por "scope".

Es suficiente para un servidor local / de una sola instancia. En producción con
varias instancias se usaría Redis.
"""
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window: int) -> int:
        """Registra un intento. Devuelve 0 si se permite, o los segundos de espera si no."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:
                self._purge(now)
            queue = self._hits[key]
            while queue and queue[0] <= now - window:
                queue.popleft()
            if len(queue) >= limit:
                return max(1, int(queue[0] + window - now) + 1)
            queue.append(now)
            return 0

    def _purge(self, now: float) -> None:
        for key in [k for k, q in self._hits.items() if not q or q[-1] < now - 3600]:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def rate_limit(scope: str, limit: int, window: int):
    """Crea una dependencia de FastAPI: `limit` peticiones cada `window` segundos."""

    def dependency(request: Request) -> None:
        # Solo confiamos en la IP real de la conexión (X-Forwarded-For se puede falsificar).
        ip = request.client.host if request.client else "desconocida"
        wait = limiter.check(f"{scope}:{ip}", limit, window)
        if wait:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Demasiadas peticiones. Intenta de nuevo en {wait} segundos.",
                headers={"Retry-After": str(wait)},
            )

    return dependency
