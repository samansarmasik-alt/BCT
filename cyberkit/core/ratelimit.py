"""Token-bucket rate limiter shared by all network modules.

Smoothing traffic matters for two reasons: the target does not collapse under
load, and a third-party rate limiter in front of it does not start dropping
requests. Async-native so one instance covers every task.
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Allows ``rate`` operations per second, bursting up to ``burst``."""

    __slots__ = ("_lock", "_sleep", "_tokens", "_updated", "burst", "rate")

    def __init__(self, rate: float, burst: int | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0 to use a limiter")
        self.rate = rate
        self.burst = burst if burst is not None else max(1, int(rate))
        self._tokens = float(self.burst)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()
        self._sleep = asyncio.sleep

    async def acquire(self, amount: float = 1.0) -> None:
        """Block until ``amount`` tokens are available."""
        if amount > self.burst:
            amount = self.burst
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                if self._tokens >= amount:
                    self._tokens -= amount
                    return
                wait_for = (amount - self._tokens) / self.rate
            await self._sleep(wait_for)

    async def __aenter__(self) -> RateLimiter:
        await self.acquire()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None
