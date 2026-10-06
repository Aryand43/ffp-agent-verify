"""Off-hot-path event emission: buffer in memory, flush to a Redis Stream in batches."""

import asyncio
import logging

import orjson
import redis.asyncio as aioredis

log = logging.getLogger(__name__)


class EventBuffer:
    def __init__(self, redis: aioredis.Redis, stream: str, maxlen: int, flush_interval_s: float = 0.02,
                 max_batch: int = 500, max_pending: int = 100_000):
        self.redis = redis
        self.stream = stream
        self.maxlen = maxlen
        self.flush_interval_s = flush_interval_s
        self.max_batch = max_batch
        self.max_pending = max_pending
        self._pending: list[dict] = []
        self._task: asyncio.Task | None = None
        self.dropped = 0

    def emit(self, event: dict) -> None:
        if len(self._pending) >= self.max_pending:
            self.dropped += 1  # shed analytics, never block verification
            return
        self._pending.append(event)

    def drain(self) -> list[dict]:
        """Take all pending events (used by the simulator to feed the worker directly)."""
        out, self._pending = self._pending, []
        return out

    async def flush(self) -> None:
        while self._pending:
            batch, self._pending = self._pending[: self.max_batch], self._pending[self.max_batch:]
            pipe = self.redis.pipeline(transaction=False)
            for e in batch:
                pipe.xadd(self.stream, {"e": orjson.dumps(e)}, maxlen=self.maxlen, approximate=True)
            try:
                await pipe.execute()
            except Exception:
                log.exception("failed to flush %d events", len(batch))
                self.dropped += len(batch)

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval_s)
            await self.flush()

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        await self.flush()
