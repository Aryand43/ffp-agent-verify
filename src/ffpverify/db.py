import json
import logging
from pathlib import Path

import asyncpg

log = logging.getLogger(__name__)

SCHEMA = (Path(__file__).parent / "schema.sql").read_text()


async def _init_conn(conn: asyncpg.Connection) -> None:
    # Binary jsonb (version byte + text) so COPY works too. Pass Python objects, never pre-dumped strings.
    await conn.set_type_codec("jsonb", schema="pg_catalog", format="binary",
                              encoder=lambda v: b"\x01" + json.dumps(v).encode(),
                              decoder=lambda b: json.loads(b[1:]))


async def create_pool(dsn: str, min_size: int = 2, max_size: int = 10) -> asyncpg.Pool:
    return await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size, init=_init_conn)


async def migrate(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        # Serialize concurrent startups (several replicas / workers).
        await conn.execute("SELECT pg_advisory_lock(424242)")
        try:
            await conn.execute(SCHEMA)
            try:
                await conn.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
                await conn.execute(
                    "SELECT create_hypertable('search_requests', 'ts', if_not_exists => TRUE, migrate_data => TRUE)"
                )
            except asyncpg.PostgresError as e:
                log.warning("TimescaleDB unavailable, search_requests stays a plain table: %s", e)
        finally:
            await conn.execute("SELECT pg_advisory_unlock(424242)")
