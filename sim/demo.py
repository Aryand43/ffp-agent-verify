"""Seed the local dev stack with simulated traffic so the /ui dashboards have data.

    uv run python -m sim.demo

WARNING: wipes the dev database (ffpv) and Redis db 0, then writes airline API keys and tool
management tokens to reports/demo-credentials.json.
"""

import asyncio
import json
from pathlib import Path

from ffpverify.config import Settings
from ffpverify.db import create_pool

from .harness import ADMIN_KEY
from .inventory import seed as seed_inventory
from .run import simulate


def main():
    settings = Settings(database_url="postgresql://ffpv:ffpv@localhost:5432/ffpv",
                        redis_url="redis://localhost:6379/0", admin_key=ADMIN_KEY)
    # Start the simulated clock in the past so the traffic lands in the dashboards' "last 24h" window.
    r = asyncio.run(simulate(minutes=15, scale=0.5, seed=11, persist=True, settings=settings,
                             start_offset_s=-4 * 3600))
    Path("reports").mkdir(exist_ok=True)
    Path("reports/demo-credentials.json").write_text(json.dumps(r["credentials"], indent=2))
    inv = asyncio.run(_seed_inventory(settings.database_url, list(r["credentials"]["airlines"])))
    s = r["summary"]
    print(f"Seeded {s['requests']:,} verifications and {inv:,} redemption inventory rows. "
          f"Credentials: reports/demo-credentials.json")
    print("Open http://localhost:8000/ui and sign in with an airline key or a tool token from that file.")


async def _seed_inventory(dsn: str, airlines: list[str]) -> int:
    pool = await create_pool(dsn)
    try:
        return sum(v["rows"] for v in (await seed_inventory(pool, airlines)).values())
    finally:
        await pool.close()


if __name__ == "__main__":
    main()
