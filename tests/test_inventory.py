from datetime import date, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from ffpverify.inventory import InventoryRow, alliance_of
from sim.inventory import snapshot

ROW = dict(flight_number="SQ322", origin="SIN", destination="LHR", travel_date="2026-12-01", award_class="I",
           seats_available=1, seats_total=2)


def test_cabin_inferred_from_award_class():
    assert InventoryRow(**ROW).cabin == "business"
    assert InventoryRow(**{**ROW, "award_class": "X"}).cabin == "economy"
    assert InventoryRow(**{**ROW, "award_class": "O", "seats_total": 1}).cabin == "first"


@pytest.mark.parametrize("bad", [
    {"seats_available": 3},                    # more open than the cap
    {"award_class": "Z"},                      # unknown class without an explicit cabin
    {"destination": "SIN"},                    # same airport
    {"flight_number": "SQ-322"},
    {"origin": "sin"},
])
def test_invalid_rows_rejected(bad):
    with pytest.raises(ValidationError):
        InventoryRow(**{**ROW, **bad})


def test_other_classes_allowed_with_explicit_cabin():
    assert InventoryRow(**{**ROW, "award_class": "Z", "cabin": "premium_economy"}).cabin == "premium_economy"


def test_alliances():
    assert alliance_of("SQ") == alliance_of("AC") == "star_alliance"
    assert alliance_of("QR") == "oneworld" and alliance_of("EK") is None


def test_simulated_inventory_shape():
    today = date(2026, 10, 1)
    rows = snapshot("AC", today + timedelta(days=1), 14, today)
    by_class = {}
    for r in rows:
        by_class.setdefault(r.award_class, set()).add(r.seats_total)
        assert 0 <= r.seats_available <= r.seats_total
    assert by_class["X"] <= {4, 6} and by_class["I"] <= {2, 4} and by_class["O"] == {1}
    assert {r.operating_carrier for r in rows} == {"AC", "SQ", "NH", "TK"}
    assert not any(r.award_class == "O" and r.operating_carrier == "AC" for r in rows)  # AC sells no first


def test_partner_view_never_exceeds_operator_release():
    today = date(2026, 10, 1)
    own = {(r.flight_number, r.travel_date, r.award_class): r.seats_available
           for r in snapshot("SQ", today + timedelta(days=1), 7, today)}
    for r in snapshot("AC", today + timedelta(days=1), 7, today):
        if r.operating_carrier == "SQ":
            assert r.seats_available <= own[(r.flight_number, r.travel_date, r.award_class)]


def test_seats_get_taken_between_snapshots():
    today = date(2026, 10, 1)
    a = snapshot("QF", today + timedelta(days=1), 14, today)
    b = snapshot("QF", today + timedelta(days=1), 14, today, taken_since=1)
    assert sum(r.seats_available for r in b) < sum(r.seats_available for r in a)
    assert all(y.seats_available <= x.seats_available for x, y in zip(a, b))


# --- end to end through the API ---------------------------------------------------------------

def body(rows, observed_at=None):
    return {"observed_at": observed_at, "rows": rows}


@pytest.mark.integration
async def test_inventory_feed_query_and_history(env):
    key = {"X-Api-Key": env.airlines["AC"].api_key}
    url = f"{env.verify_url}/v1/airlines/AC/inventory"
    now = datetime.now(timezone.utc)
    rows = [{**ROW, "flight_number": "AC003", "origin": "YVR", "destination": "NRT", "award_class": c,
             "seats_available": a, "seats_total": t} for c, a, t in (("X", 4, 6), ("I", 2, 2))]
    rows.append({**ROW, "operating_carrier": "SQ"})  # partner space
    r = await env.http.put(url, json=body(rows, (now - timedelta(hours=1)).isoformat()), headers=key)
    assert r.status_code == 200, r.text
    assert r.json() == {"received": 3, "new": 3, "changed": 0, "unchanged": 0, "stale": 0}

    # an I seat gets taken; an older snapshot arriving late is ignored
    rows[1]["seats_available"] = 1
    r = await env.http.put(url, json=body(rows, now.isoformat()), headers=key)
    assert r.json()["changed"] == 1 and r.json()["unchanged"] == 2
    r = await env.http.put(url, json=body(rows[:1], (now - timedelta(hours=3)).isoformat()), headers=key)
    assert r.json()["stale"] == 1

    inv = (await env.http.get(url, params={"origin": "YVR"}, headers=key)).json()
    i_row = next(x for x in inv["rows"] if x["award_class"] == "I")
    assert (i_row["seats_available"], i_row["seats_total"], i_row["seats_taken"]) == (1, 2, 1)
    partner = (await env.http.get(url, params={"partner_only": "true"}, headers=key)).json()
    assert [x["operating_carrier"] for x in partner["rows"]] == ["SQ"] and partner["rows"][0]["partner"]
    assert partner["alliance"] == "star_alliance"
    hist = await env.state.pool.fetchval("SELECT count(*) FROM award_inventory_history WHERE airline_id = 'AC'")
    assert hist == 4  # 3 new + 1 change

    # airlines can't read or write each other's inventory
    other = {"X-Api-Key": env.airlines["SQ"].api_key}
    assert (await env.http.get(url, headers=other)).status_code == 401
    assert (await env.http.put(url, json=body(rows), headers=other)).status_code == 401


@pytest.mark.integration
async def test_tool_reports_need_an_active_authorization(env):
    tool = await env.register_tool("SeatWatch")
    url = f"{env.verify_url}/v1/tools/{tool.client.tool_id}/inventory/AC"
    h = {"X-Tool-Token": tool.management_token}
    obs = body([{**ROW, "seats_total": None, "seats_available": 2, "award_class": "X"}])
    assert (await env.http.post(url, json=obs, headers=h)).status_code == 403
    tokens = await env.authorize(tool, "AC", "100200300")
    await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", "104.131.20.7"), "AC")
    await env.tick()  # the worker records the grant from the verified search
    r = await env.http.post(url, json=obs, headers=h)
    assert r.status_code == 200 and r.json()["new"] == 1
    inv = (await env.http.get(f"{env.verify_url}/v1/airlines/AC/inventory",
                              headers={"X-Api-Key": env.airlines["AC"].api_key})).json()
    assert inv["rows"][0]["source"] == f"tool:{tool.client.tool_id}" and inv["rows"][0]["seats_total"] is None


@pytest.mark.integration
async def test_coverage_report_lists_available_and_missing_space(env):
    from sim.inventory import seed
    from sim.inventory_report import build
    await seed(env.state.pool, ["AC"], days=3)
    md = await build(env.state.pool)
    assert "## AC" in md and "SQ (own)" not in md and "AC (own)" in md
    assert "Star Alliance partners with no visible space" in md and "No O" not in md
    assert "seats taken" in md
