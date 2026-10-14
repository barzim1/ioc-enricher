from __future__ import annotations

import time
from typing import Callable


class RateLimiter:
    """Wymusza minimalny odstęp między zapytaniami (np. 4/min => 15 s)."""

    def __init__(self, per_minute: float,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        if per_minute <= 0:
            raise ValueError("per_minute musi być > 0")
        self.min_interval = 60.0 / per_minute
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    def wait(self) -> float:
        """Blokuje do momentu, gdy wolno wysłać kolejne zapytanie. Zwraca czas oczekiwania."""
        waited = 0.0
        now = self._clock()
        if self._last is not None:
            remaining = self.min_interval - (now - self._last)
            if remaining > 0:
                self._sleep(remaining)
                waited = remaining
        self._last = self._clock() if waited == 0 else self._last + self.min_interval
        return waited
