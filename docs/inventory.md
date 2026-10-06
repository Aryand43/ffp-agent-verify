# Redemption inventory

A catalog of each FFP program's **award (redemption) seats**: open seats vs. the redemption cap, per flight, date and award class. Commercial fares aren't tracked. Third-party sites already publish them, but nothing publishes award space.

## The table

| Column | Example | Notes |
|---|---|---|
| `origin` / `destination` | `SIN` / `LHR` | IATA airport codes |
| `travel_date` | `2026-12-01` | |
| `flight_number`, `departs_at` | `SQ322`, `23:35` | Award space is released per flight |
| `cabin` | `business` | economy, premium_economy, business, first |
| `award_class` | `I` | Inferred cabin: **X** economy, **I** business, **O** first / suites. Other letters are accepted with an explicit `cabin`. |
| `seats_available` / `seats_total` | `1` / `2` | Open seats vs. the redemption cap. `seats_taken` = total − available. |
| `operating_carrier` | `SQ` | Differs from the program for **partner / alliance space**, e.g. an SQ flight bookable with Aeroplan (AC) miles |
| `source`, `observed_at` | `airline_feed` | Who reported it, and when |

Typical caps are 4–6 X seats, about 2 I seats and 1 O seat per flight. Postgres tables: `award_inventory` holds the latest state per flight, date and class. `award_inventory_history` holds every change in seat counts, which shows when seats open up or get taken.

## Where the data comes from

| Source | Endpoint | Has the cap? |
|---|---|---|
| **Airline feed.** The airline pushes its own inventory, including partner space | `PUT /v1/airlines/{airline_id}/inventory` (airline API key) | Yes |
| **Tool observations.** An authorized tool reports what its award searches returned | `POST /v1/tools/{tool_id}/inventory/{airline_id}` (tool token; the tool needs an active member authorization at that airline) | Usually not. The last known cap is kept. |

How writes are reconciled:
- Writes upsert by (operating carrier, flight, date, award class), and a newer observation always wins.
- A late-arriving older snapshot is counted as `stale` and ignored.
- Each upload reports `new` / `changed` / `unchanged` / `stale`.

## Reading it

`GET /v1/airlines/{airline_id}/inventory` takes these filters:
- `origin`, `destination`
- `date_from`, `date_to`
- `cabin`, `award_class`
- `operating_carrier`
- `partner_only`, `available_only`

It returns:
- `rows`, each annotated with `partner`, `operating_alliance` and `seats_taken`;
- a `summary` per award class (flights, flights with open seats, seats open vs. total, partner flights);
- the program's alliance.

The **Redemption inventory** tab in `/ui` shows the same data. It reuses the airline sign-in.

## Simulated data

Until a real feed exists, `make inventory` (and `make demo`) seed **synthetic** inventory for the six demo programs. It covers about three weeks of long-haul flights, plus Star Alliance, oneworld and bilateral partner space. Far-out dates are more open. A second snapshot two hours later shows some seats taken, so history has changes. Partner views never show more than the operating carrier's own release. See `sim/inventory.py`.

## What's available and what isn't

`make inventory-report` writes `reports/inventory-coverage.md`, with one section per program:
- Seats open vs. cap per award class, split into own and partner space.
- Seats taken and released in the last 24 h.
- Gaps:
  - classes with no space;
  - alliance partners with no visible space;
  - rows missing a cap;
  - stale rows.

Run it again whenever a real feed or tool observations land, to see what each source actually covers.

## Not done yet

- **Real sourcing.** Decide per airline between a sanctioned feed and tool observations.
- **Alliance visibility.** Partner space is modelled and seeded, but whether each program actually *shows* partner space (some do, some don't) needs checking airline by airline.
- **Multi-IP searching.** Sharveen flagged this as required before going live: if one airline blocks an egress IP, a popular tool degrades for everyone. It needs a design discussion. It interacts with the `ip_churn` and `ip_concurrency` signals, which deliberately penalize fast rotation.
