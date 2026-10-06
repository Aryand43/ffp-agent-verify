"""Redemption (award) seat inventory: what each FFP program has open, per flight, date and award class.

Only redemption space is tracked. Commercial fares are published to third-party sites already;
award space is not, which is why it needs its own pipeline.

Two sources write to the same table:
- `airline_feed`: an airline pushes its own inventory, with seats_total (the airline knows the cap).
- `tool:<tool_id>`: an authorized tool reports what an award search showed it. Tools usually see how many
  seats are open but not the cap, so seats_total may be missing; we keep the last known cap.

A newer observation always wins; every change in seat counts is appended to award_inventory_history.
"""

from datetime import date, datetime, timezone

import asyncpg
from pydantic import BaseModel, Field, model_validator

# Typical redemption booking classes. Airlines differ; send `cabin` explicitly for anything else.
DEFAULT_AWARD_CLASSES = {"X": "economy", "I": "business", "O": "first"}

# Partner space bookable across programs. Bilateral partnerships (e.g. EK-QF) aren't listed here;
# any operating carrier is accepted, this only annotates rows.
ALLIANCES = {
    "star_alliance": {"AC", "SQ", "NH", "LH", "UA", "TK", "NZ", "OS", "LX", "TG", "BR", "OZ", "SA", "ET", "CA", "AI"},
    "oneworld": {"QF", "AS", "QR", "BA", "CX", "JL", "AA", "IB", "AY", "MH", "RJ", "UL", "FJ"},
    "skyteam": {"AF", "KL", "DL", "KE", "VN", "AM", "SV", "MU", "CI", "GA", "VS"},
}


def alliance_of(carrier: str) -> str | None:
    return next((name for name, members in ALLIANCES.items() if carrier in members), None)


class InventoryRow(BaseModel):
    operating_carrier: str | None = Field(None, pattern=r"^[A-Z0-9]{2}$",
                                          description="Defaults to the program's own airline (own metal)")
    flight_number: str = Field(pattern=r"^[A-Z0-9]{2}\d{1,4}[A-Z]?$", examples=["SQ322"])
    origin: str = Field(pattern=r"^[A-Z]{3}$", examples=["SIN"])
    destination: str = Field(pattern=r"^[A-Z]{3}$", examples=["LHR"])
    travel_date: date
    departs_at: str | None = Field(None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$", examples=["23:35"])
    cabin: str | None = Field(None, pattern=r"^(economy|premium_economy|business|first)$",
                              description="Inferred from award_class (X/I/O) when omitted")
    award_class: str = Field(pattern=r"^[A-Z]$", examples=["I"])
    seats_available: int = Field(ge=0, le=99)
    seats_total: int | None = Field(None, ge=0, le=99, description="Redemption cap for this class on this flight")

    @model_validator(mode="after")
    def _check(self):
        if self.cabin is None:
            self.cabin = DEFAULT_AWARD_CLASSES.get(self.award_class)
            if self.cabin is None:
                raise ValueError(f"award class {self.award_class} is not X/I/O; send cabin explicitly")
        if self.origin == self.destination:
            raise ValueError("origin and destination must differ")
        if self.seats_total is not None and self.seats_total < self.seats_available:
            raise ValueError("seats_available cannot exceed seats_total")
        return self


class InventoryUpload(BaseModel):
    observed_at: datetime | None = Field(None, description="When this snapshot was taken; defaults to now")
    rows: list[InventoryRow] = Field(min_length=1, max_length=5000)


class InventoryIngested(BaseModel):
    received: int
    new: int = Field(description="Rows not seen before")
    changed: int = Field(description="Seat counts changed")
    unchanged: int
    stale: int = Field(description="Ignored because a newer observation already exists")


_KEY = ("operating_carrier", "flight_number", "travel_date", "award_class")


async def ingest(pool: asyncpg.Pool, airline_id: str, upload: InventoryUpload, source: str) -> InventoryIngested:
    observed = upload.observed_at or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    rows: dict[tuple, InventoryRow] = {}
    for r in upload.rows:  # last row wins for duplicate keys within one upload
        r.operating_carrier = r.operating_carrier or airline_id
        rows[tuple(getattr(r, k) for k in _KEY)] = r
    keys = list(rows)
    counts = dict(new=0, changed=0, unchanged=0, stale=0)
    async with pool.acquire() as conn, conn.transaction():
        current = {
            (c["operating_carrier"], c["flight_number"], c["travel_date"], c["award_class"]): c
            for c in await conn.fetch(
                "SELECT i.operating_carrier, i.flight_number, i.travel_date, i.award_class, i.seats_available, "
                "i.seats_total, i.observed_at FROM award_inventory i "
                "JOIN unnest($2::text[], $3::text[], $4::date[], $5::text[]) AS k(oc, fn, d, cls) "
                "ON i.operating_carrier = k.oc AND i.flight_number = k.fn AND i.travel_date = k.d "
                "AND i.award_class = k.cls WHERE i.airline_id = $1",
                airline_id, *[[k[i] for k in keys] for i in range(4)])
        }
        upserts, history = [], []
        for key, r in rows.items():
            cur = current.get(key)
            if cur is not None and cur["observed_at"] > observed:
                counts["stale"] += 1
                continue
            total = r.seats_total
            if total is None and cur is not None and (cur["seats_total"] or 0) >= r.seats_available:
                total = cur["seats_total"]  # tools rarely see the cap; keep the last known one
            upserts.append((airline_id, *key, r, total))  # unchanged rows still refresh observed_at
            if cur is not None and (cur["seats_available"], cur["seats_total"]) == (r.seats_available, total):
                counts["unchanged"] += 1
                continue
            counts["new" if cur is None else "changed"] += 1
            history.append((observed, airline_id, *key, r.seats_available, total, source))
        await conn.executemany(
            "INSERT INTO award_inventory (airline_id, operating_carrier, flight_number, travel_date, award_class, "
            "origin, destination, departs_at, cabin, seats_available, seats_total, source, observed_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) "
            "ON CONFLICT (airline_id, operating_carrier, flight_number, travel_date, award_class) DO UPDATE SET "
            "origin = EXCLUDED.origin, destination = EXCLUDED.destination, departs_at = EXCLUDED.departs_at, "
            "cabin = EXCLUDED.cabin, seats_available = EXCLUDED.seats_available, seats_total = EXCLUDED.seats_total, "
            "source = EXCLUDED.source, observed_at = EXCLUDED.observed_at, updated_at = now()",
            [(a, oc, fn, d, cls, r.origin, r.destination, r.departs_at, r.cabin, r.seats_available, total, source,
              observed) for a, oc, fn, d, cls, r, total in upserts])
        if history:
            await conn.executemany(
                "INSERT INTO award_inventory_history (observed_at, airline_id, operating_carrier, flight_number, "
                "travel_date, award_class, seats_available, seats_total, source) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", history)
    return InventoryIngested(received=len(upload.rows), **counts)


async def query(pool: asyncpg.Pool, airline_id: str, *, origin: str | None = None, destination: str | None = None,
                date_from: date | None = None, date_to: date | None = None, cabin: str | None = None,
                award_class: str | None = None, operating_carrier: str | None = None, partner_only: bool = False,
                available_only: bool = False, limit: int = 500) -> dict:
    where, args = ["airline_id = $1"], [airline_id]

    def add(cond: str, value):
        args.append(value)
        where.append(cond.format(f"${len(args)}"))

    if origin:
        add("origin = {}", origin.upper())
    if destination:
        add("destination = {}", destination.upper())
    if date_from:
        add("travel_date >= {}", date_from)
    if date_to:
        add("travel_date <= {}", date_to)
    if cabin:
        add("cabin = {}", cabin)
    if award_class:
        add("award_class = {}", award_class.upper())
    if operating_carrier:
        add("operating_carrier = {}", operating_carrier.upper())
    if partner_only:
        where.append("operating_carrier <> airline_id")
    if available_only:
        where.append("seats_available > 0")
    cond = " AND ".join(where)
    rows = await pool.fetch(
        f"SELECT operating_carrier, flight_number, origin, destination, travel_date, departs_at, cabin, award_class, "
        f"seats_available, seats_total, source, observed_at FROM award_inventory WHERE {cond} "
        f"ORDER BY travel_date, origin, destination, departs_at NULLS LAST, flight_number, cabin "
        f"LIMIT {int(limit)}", *args)
    summary = await pool.fetch(
        f"SELECT cabin, award_class, count(*) flights, count(*) FILTER (WHERE seats_available > 0) flights_open, "
        f"sum(seats_available) seats_available, sum(seats_total) seats_total, "
        f"count(*) FILTER (WHERE operating_carrier <> airline_id) partner_flights "
        f"FROM award_inventory WHERE {cond} GROUP BY 1, 2 ORDER BY 1, 2", *args)
    total = await pool.fetchval(f"SELECT count(*) FROM award_inventory WHERE {cond}", *args)
    return {
        "airline_id": airline_id,
        "alliance": alliance_of(airline_id),
        "total_rows": total,
        "summary": [dict(s) for s in summary],
        "rows": [{**dict(r), "partner": r["operating_carrier"] != airline_id,
                  "operating_alliance": alliance_of(r["operating_carrier"]),
                  "seats_taken": (r["seats_total"] - r["seats_available"]) if r["seats_total"] is not None else None}
                 for r in rows],
    }
