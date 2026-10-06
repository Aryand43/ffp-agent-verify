"""Simulated redemption inventory, so the catalog and dashboards have realistic data before any real feed exists.

    uv run python -m sim.inventory            # seed the dev DB for every airline already registered there

Shape follows how award space is usually released:
- X (economy) 4-6 seats, I (business) ~2, O (first / suites) 1 and only on some long-haul flights;
- far-out dates are more open, close-in space is mostly gone;
- partner / alliance space is a view of the *operating* carrier's release, so an SQ flight shows the same
  (or fewer) seats through Aeroplan as through KrisFlyer.

This is synthetic data, not scraped from any airline.
"""

import argparse
import asyncio
import hashlib
import random
from datetime import date, datetime, timedelta, timezone

from ffpverify import inventory
from ffpverify.db import create_pool, migrate
from ffpverify.inventory import InventoryRow, InventoryUpload

HUBS = {"AC": ["YVR", "YYZ"], "SQ": ["SIN"], "EK": ["DXB"], "QF": ["SYD", "MEL"], "AS": ["SEA"], "QR": ["DOH"],
        "NH": ["HND"], "TK": ["IST"], "BA": ["LHR"], "JL": ["HND"]}
DESTS = {"AC": ["NRT", "LHR", "HKG", "FRA", "CDG", "SYD"], "SQ": ["LHR", "NRT", "SYD", "FRA", "JFK", "ZRH"],
         "EK": ["LHR", "SYD", "JFK", "BKK", "MLE", "CDG"], "QF": ["LHR", "LAX", "SIN", "HND", "JFK"],
         "AS": ["ANC", "HNL", "JFK", "LAX"], "QR": ["LHR", "SYD", "JFK", "CDG", "BKK", "MLE"],
         "NH": ["LAX", "LHR", "SIN"], "TK": ["JFK", "SIN", "NRT"], "BA": ["JFK", "SIN", "DOH"],
         "JL": ["LAX", "SEA", "SYD"]}
FIRST_CLASS = {"SQ", "EK", "QF", "QR", "NH", "BA", "JL"}  # carriers that still sell first / suites
SHORT_HAUL = {("AS", "ANC"), ("QR", "BKK"), ("BA", "DOH")}

# Which operating carriers' award space each program can book (alliance or bilateral partners).
PARTNERS = {"AC": ["SQ", "NH", "TK"], "SQ": ["AC", "NH", "TK"], "QF": ["AS", "QR", "JL"], "AS": ["QF", "QR", "JL"],
            "QR": ["QF", "AS", "BA"], "EK": ["QF"]}


def _rng(*parts) -> random.Random:
    return random.Random(int(hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()[:16], 16))


def flights(carrier: str) -> list[tuple[str, str, str, str]]:
    """(flight_number, origin, destination, departs_at) for one carrier's long-haul schedule."""
    out = []
    for hub in HUBS.get(carrier, []):
        for i, dest in enumerate(DESTS.get(carrier, [])):
            if dest == hub:
                continue
            r = _rng(carrier, hub, dest)
            num = f"{carrier}{r.randrange(1, 999):03d}" if carrier != "AS" else f"AS{r.randrange(1, 99)}"
            out.append((num, hub, dest, f"{r.randrange(24):02d}:{r.choice(['05', '20', '35', '50'])}"))
    return out


def release(carrier: str, flight: str, dest: str, day: date, today: date, cls: str,
            taken_since: int = 0) -> tuple[int, int] | None:
    """(available, total) the operating carrier releases for one award class, or None if not offered."""
    r = _rng(carrier, flight, day, cls)
    if cls == "X":
        total = r.choice([4, 4, 6, 6, 6]) if (carrier, dest) not in SHORT_HAUL else 6
    elif cls == "I":
        total = r.choice([2, 2, 2, 4])
    else:
        if carrier not in FIRST_CLASS or (carrier, dest) in SHORT_HAUL or r.random() < 0.4:
            return None
        total = 1
    days_out = (day - today).days
    openness = min(1.0, 0.25 + days_out / 45)  # far out is more open
    available = sum(r.random() < openness for _ in range(total))
    available = max(0, available - taken_since)
    return available, total


def snapshot(program: str, start: date, days: int, today: date, taken_since: int = 0) -> list[InventoryRow]:
    """`taken_since` seats get booked on ~15% of flights/classes (same flights for every program's view)."""
    rows = []
    carriers = [program, *PARTNERS.get(program, [])]
    for carrier in carriers:
        for flight, o, d, dep in flights(carrier):
            for k in range(days):
                day = start + timedelta(days=k)
                for cls, cabin in inventory.DEFAULT_AWARD_CLASSES.items():
                    taken = taken_since if _rng("taken", carrier, flight, day, cls).random() < 0.15 else 0
                    rel = release(carrier, flight, d, day, today, cls, taken)
                    if rel is None:
                        continue
                    avail, total = rel
                    if carrier != program:  # partners usually see a subset of the operator's own release
                        avail = min(avail, 2 if cls == "X" else 1)
                    rows.append(InventoryRow(operating_carrier=carrier, flight_number=flight, origin=o, destination=d,
                                             travel_date=day, departs_at=dep, cabin=cabin, award_class=cls,
                                             seats_available=avail, seats_total=total))
    return rows


async def seed(pool, airline_ids: list[str], days: int = 21) -> dict[str, dict]:
    """Two snapshots per program, two hours apart: the second shows some seats taken, so history has changes."""
    today = datetime.now(timezone.utc).date()
    now = datetime.now(timezone.utc)
    out = {}
    for a in airline_ids:
        first = snapshot(a, today + timedelta(days=1), days, today)
        second = snapshot(a, today + timedelta(days=1), days, today, taken_since=1)
        r1 = r2 = None
        for i in range(0, len(first), 5000):
            r1 = await inventory.ingest(pool, a, InventoryUpload(observed_at=now - timedelta(hours=2),
                                                                 rows=first[i:i + 5000]), "airline_feed")
        for i in range(0, len(second), 5000):
            r2 = await inventory.ingest(pool, a, InventoryUpload(observed_at=now, rows=second[i:i + 5000]),
                                        "airline_feed")
        out[a] = {"rows": len(second), "first": r1.model_dump() if r1 else None,
                  "second": r2.model_dump() if r2 else None}
    return out


async def _main(dsn: str, days: int):
    pool = await create_pool(dsn)
    try:
        await migrate(pool)
        airlines = [r["airline_id"] for r in await pool.fetch("SELECT airline_id FROM airlines ORDER BY 1")]
        if not airlines:
            raise SystemExit("No airlines registered yet; run `make demo` first.")
        for a, r in (await seed(pool, airlines, days)).items():
            print(f"{a}: {r['rows']:,} award rows (partner space included)")
    finally:
        await pool.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", default="postgresql://ffpv:ffpv@localhost:5432/ffpv")
    ap.add_argument("--days", type=int, default=21)
    args = ap.parse_args()
    asyncio.run(_main(args.dsn, args.days))
