"""What redemption inventory do we have, and what's missing? One page per program.

    uv run python -m sim.inventory_report      # -> reports/inventory-coverage.md

Reads whatever is in award_inventory (synthetic today, real feeds / tool observations later) and answers:
- per award class (X / I / O): flights, flights with open seats, seats open vs. the cap, % taken;
- own metal vs. partner space, and which alliance partners show *no* space at all;
- data gaps: missing caps (tool observations), stale rows, date range covered;
- seats taken in the last 24 h, from award_inventory_history.
"""

import argparse
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from ffpverify.db import create_pool
from ffpverify.inventory import ALLIANCES, DEFAULT_AWARD_CLASSES, alliance_of


def _pct(a, b) -> str:
    return f"{100 * a / b:.0f}%" if b else "–"


async def build(pool) -> str:
    programs = [r["airline_id"] for r in await pool.fetch(
        "SELECT DISTINCT airline_id FROM award_inventory ORDER BY 1")]
    now = datetime.now(timezone.utc)
    out = [f"# Redemption inventory coverage\n\nGenerated {now:%Y-%m-%d %H:%M} UTC from `award_inventory`. "
           "X = economy, I = business, O = first / suites. For partner space, 'cap' is the operating carrier's "
           "cap; partners usually see only part of it, so partner 'taken' overstates how full the flight is.\n"]
    if not programs:
        return out[0] + "\nNo inventory yet. Run `make inventory`.\n"

    totals = await pool.fetch(
        "SELECT airline_id, count(*) n, count(*) FILTER (WHERE operating_carrier <> airline_id) partner, "
        "count(DISTINCT operating_carrier) carriers, count(DISTINCT (origin, destination)) routes, "
        "min(travel_date) d0, max(travel_date) d1, sum(seats_available) open, sum(seats_total) cap "
        "FROM award_inventory GROUP BY 1 ORDER BY 1")
    out.append("## Overview\n\n| Program | Alliance | Rows | Partner rows | Carriers | Routes | Dates | "
               "Seats open / cap |\n|---|---|---|---|---|---|---|---|")
    for t in totals:
        out.append(f"| {t['airline_id']} | {alliance_of(t['airline_id']) or 'none'} | {t['n']:,} | {t['partner']:,} | "
                   f"{t['carriers']} | {t['routes']} | {t['d0']} → {t['d1']} | {t['open']:,} / {t['cap'] or 0:,} "
                   f"({_pct((t['cap'] or 0) - t['open'], t['cap'])} taken) |")

    for a in programs:
        out.append(f"\n## {a}\n")
        classes = await pool.fetch(
            "SELECT award_class, operating_carrier = airline_id own, count(*) flights, "
            "count(*) FILTER (WHERE seats_available > 0) open_flights, sum(seats_available) open, "
            "sum(seats_total) cap FROM award_inventory WHERE airline_id = $1 GROUP BY 1, 2 ORDER BY 1, 2 DESC", a)
        out.append("| Class | Space | Flights | With open seats | Seats open / cap | Taken |\n|---|---|---|---|---|---|")
        for c in classes:
            cap = c["cap"] or 0
            out.append(f"| {c['award_class']} ({DEFAULT_AWARD_CLASSES.get(c['award_class'], '?')}) | "
                       f"{'own' if c['own'] else 'partner'} | {c['flights']:,} | {c['open_flights']:,} "
                       f"({_pct(c['open_flights'], c['flights'])}) | {c['open']:,} / {cap:,} | "
                       f"{_pct(cap - c['open'], cap)} |")

        seen_classes = {c["award_class"] for c in classes}
        missing_classes = [k for k in DEFAULT_AWARD_CLASSES if k not in seen_classes]
        carriers = await pool.fetch(
            "SELECT operating_carrier, count(*) n, count(*) FILTER (WHERE seats_available > 0) open "
            "FROM award_inventory WHERE airline_id = $1 GROUP BY 1 ORDER BY 1", a)
        seen = {c["operating_carrier"] for c in carriers}
        alliance = alliance_of(a)
        unseen = sorted(ALLIANCES.get(alliance, set()) - seen - {a}) if alliance else []
        gaps = await pool.fetchrow(
            "SELECT count(*) FILTER (WHERE seats_total IS NULL) no_cap, "
            "count(*) FILTER (WHERE observed_at < now() - interval '24 hours') stale, "
            "count(*) FILTER (WHERE source LIKE 'tool:%') from_tools FROM award_inventory WHERE airline_id = $1", a)
        moved = await pool.fetchrow(
            "SELECT count(*) FILTER (WHERE prev IS NOT NULL AND seats_available <> prev) changes, "
            "coalesce(sum(prev - seats_available) FILTER (WHERE seats_available < prev), 0) taken, "
            "coalesce(sum(seats_available - prev) FILTER (WHERE seats_available > prev), 0) released "
            "FROM (SELECT observed_at, seats_available, lag(seats_available) OVER (PARTITION BY operating_carrier, "
            "flight_number, travel_date, award_class ORDER BY observed_at) prev FROM award_inventory_history "
            "WHERE airline_id = $1) h WHERE observed_at > now() - interval '24 hours'", a)

        out.append("\n**Available**")
        out.append("- Carriers with space: " + ", ".join(
            f"{c['operating_carrier']}{' (own)' if c['operating_carrier'] == a else ''} "
            f"{c['open']:,}/{c['n']:,} open" for c in carriers))
        out.append(f"- Last 24 h: {moved['changes']:,} seat-count changes, {moved['taken']:,} seats taken, "
                   f"{moved['released']:,} released")
        out.append("\n**Not available / gaps**")
        if missing_classes:
            out.append(f"- No {', '.join(missing_classes)} space at all (class not offered on these flights)")
        if alliance:
            out.append(f"- {alliance.replace('_', ' ').title()} partners with no visible space: "
                       f"{', '.join(unseen) or 'none'}")
        else:
            out.append("- Not in an alliance: only bilateral partner space is possible")
        out.append(f"- Rows without a redemption cap (tool observations): {gaps['no_cap']:,}; "
                   f"rows older than 24 h: {gaps['stale']:,}; rows from tools: {gaps['from_tools']:,}")
    return "\n".join(out) + "\n"


async def _main(dsn: str, path: str):
    pool = await create_pool(dsn)
    try:
        md = await build(pool)
    finally:
        await pool.close()
    Path(path).parent.mkdir(exist_ok=True)
    Path(path).write_text(md)
    print(f"Wrote {path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", default="postgresql://ffpv:ffpv@localhost:5432/ffpv")
    ap.add_argument("--out", default="reports/inventory-coverage.md")
    args = ap.parse_args()
    asyncio.run(_main(args.dsn, args.out))
