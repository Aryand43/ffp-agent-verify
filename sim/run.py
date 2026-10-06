"""Run a mixed-traffic simulation and report false-positive / false-negative rates.

    uv run python -m sim.run --minutes 30 --scale 1.0 --seed 7

Simulated time runs as fast as the verifier + worker can go; nothing is mocked except
the clock and the event transport (see harness.py).
"""

import argparse
import asyncio
import heapq
import json
import random
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

from .actors import (AIRLINES, CredentialFanout, Forger, HighVelocityScraper, Human, RouteScopeAbuser,
                     StealthScraper, TokenThief, ToolWorker, Turncoat, residential_ip)
from .harness import SimClock, environment

DECISIONS = ("allow", "flag", "challenge", "throttle", "block")


async def build(env, rng: random.Random, minutes: float, scale: float):
    actors, notes = [], {}

    # --- authorized tools: authorize everything, then age the grants ------------------------
    tools = [await env.register_tool(f"SeatAlert{i}") for i in range(3)]
    workers = []
    members = [f"7{n:08d}" for n in range(int(6 * scale))]
    for ti, tool in enumerate(tools):
        for mi, member in enumerate(members):
            if ti > 0 and mi % 3 != 0:
                member = f"{member}{ti}"  # most members use one tool; every third uses all three
            for airline in AIRLINES:
                await env.authorize(tool, airline, member)
                workers.append(ToolWorker(rng, tool, airline, member, per_min=rng.uniform(8, 20),
                                          rotate_s=(180, 900)))
    aggressive = await env.register_tool("FastAlert")
    for m in range(3):
        for airline in AIRLINES[:3]:
            await env.authorize(aggressive, airline, f"8{m:08d}")
            workers.append(ToolWorker(rng, aggressive, airline, f"8{m:08d}", per_min=32, rotate_s=(120, 300),
                                      kind="authorized_near_quota"))
    actors += workers

    # Adversaries that need real grants.
    reseller = await env.register_tool("ResaleBot")
    await env.authorize(reseller, "AC", "900000001")
    actors.append(CredentialFanout(rng, reseller, "AC", "900000001"))

    turncoat_tool = await env.register_tool("GoodThenBad")
    await env.authorize(turncoat_tool, "QF", "900000002")

    thief = await env.register_tool("Thief")
    victim_worker = next(w for w in workers if w.tool is tools[0] and w.airline == "AC" and w.member == members[0])
    actors.append(TokenThief(rng, thief, tools[0], ("AC", members[0]), victim_worker))
    actors.append(Forger(rng, tools[1], ("SQ", members[0])))
    notes["victims"] = [tools[0].client.tool_id, tools[1].client.tool_id]

    scoped = await env.register_tool("Scoped")
    await env.authorize(scoped, "AC", "900000003", routes=["YVR-NRT", "YVR-HND"])
    actors.append(RouteScopeAbuser(rng, scoped, "AC", "900000003", {"YVR-NRT", "YVR-HND"}))

    for i in range(6):  # one member account authorizing many "different" tools: a credential farm
        farm_tool = await env.register_tool(f"Farm{i}")
        await env.authorize(farm_tool, "EK", "900000004")
        actors.append(ToolWorker(rng, farm_tool, "EK", "900000004", per_min=12, rotate_s=(120, 300),
                                 kind="sybil_member", label="adversarial"))

    env.clock.advance(2 * 3600)  # grants are now older than min_grant_age_s
    start = env.clock()
    duration = minutes * 60

    # A tool whose members only just signed up (reduced quota for the first hour).
    newbie = await env.register_tool("BrandNew")
    for m in range(3):
        await env.authorize(newbie, "AS", f"6{m:08d}")
        actors.append(ToolWorker(rng, newbie, "AS", f"6{m:08d}", per_min=12, rotate_s=(300, 900),
                                 kind="authorized_new_grant"))

    turn_at = start + duration * 0.4
    actors.append(Turncoat(rng, turncoat_tool, "QF", "900000002", turn_at))
    notes["turn_at"] = turn_at

    # --- humans ---------------------------------------------------------------------------------------
    for _ in range(int(150 * scale)):
        r = rng.random()
        kind, vpn, mobile = ("human_vpn", True, False) if r < 0.08 else \
            ("human_mobile", False, True) if r < 0.2 else ("human", False, False)
        actors.append(Human(rng, start + rng.uniform(0, duration * 0.9), kind=kind, vpn=vpn, mobile=mobile))
    office_ip = residential_ip(rng)
    for _ in range(12):  # an office / carrier NAT: many humans, one IP
        actors.append(Human(rng, start + rng.uniform(0, duration * 0.5), ip=office_ip, kind="human_shared_ip"))

    # --- credential-less adversaries -------------------------------------------------------------------
    actors += [HighVelocityScraper(rng, headless=False), HighVelocityScraper(rng, headless=True),
               StealthScraper(rng), StealthScraper(rng)]
    return actors, start, duration, notes


async def simulate(minutes: float, scale: float, seed: int, persist: bool, settings=None,
                   start_offset_s: float = 0) -> dict:
    rng = random.Random(seed)
    clock = SimClock(time.time() + start_offset_s)
    async with environment(clock=clock, persist=persist, settings=settings) as env:
        t_setup = time.perf_counter()
        actors, start, duration, notes = await build(env, rng, minutes, scale)
        setup_s = time.perf_counter() - t_setup
        heap, seq = [], 0
        for a in actors:
            t = await a.start(env)
            t = start + t if t < start else t
            heapq.heappush(heap, (t, seq, a))
            seq += 1
        end = start + duration
        next_tick = start + 1
        wall = time.perf_counter()
        n = 0
        while heap:
            t, _, a = heapq.heappop(heap)
            if t > end:
                continue
            while next_tick <= t:
                clock.now = next_tick
                await env.tick()
                next_tick += 1
            clock.now = max(clock.now, t)
            delay = await a.step(env)
            n += 1
            if delay is not None:
                heapq.heappush(heap, (t + delay, seq, a))
                seq += 1
        await env.tick()
        wall = time.perf_counter() - wall
        out = report(actors, notes, start, duration, wall, setup_s)
        tools = {}
        for a in actors:
            for t in (getattr(a, "tool", None), getattr(a, "own", None), getattr(a, "victim", None)):
                if t is not None:
                    tools[t.client.tool_id] = {"name": t.name, "management_token": t.management_token}
        out["credentials"] = {"airlines": {c: a.api_key for c, a in env.airlines.items()}, "tools": tools}
        return out


def _pct(xs, p):
    if not xs:
        return 0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100 * len(xs)))]


def report(actors, notes, start, duration, wall_s, setup_s) -> dict:
    by_label: dict[str, Counter] = defaultdict(Counter)
    by_kind: dict[str, Counter] = defaultdict(Counter)
    kind_reasons: dict[str, Counter] = defaultdict(Counter)
    latencies = []
    detection = defaultdict(list)  # adversarial kind -> seconds from first request to first block
    actors_detected = defaultdict(lambda: [0, 0])
    victims = Counter()
    for a in actors:
        first_t = first_block = None
        for o in a.outcomes:
            by_label[o.label][o.decision] += 1
            kind = a.kind
            if a.kind == "turncoat":
                kind = "turncoat (after turn)" if o.label == "adversarial" else "turncoat (before turn)"
            by_kind[(o.label, kind)][o.decision] += 1
            if o.decision != "allow":
                kind_reasons[kind].update(o.reasons[:1])
            latencies.append(o.latency_us)
            if o.label == "adversarial":
                first_t = first_t if first_t is not None else o.t
                if first_block is None and o.decision == "block":
                    first_block = o.t
        if any(o.label == "adversarial" for o in a.outcomes):
            k = "turncoat (after turn)" if a.kind == "turncoat" else a.kind
            actors_detected[k][1] += 1
            if first_block is not None:
                actors_detected[k][0] += 1
                detection[k].append(first_block - (notes["turn_at"] if a.kind == "turncoat" else first_t))
        if isinstance(a, ToolWorker) and a.label == "authorized" and a.tool.client.tool_id in notes["victims"]:
            for o in a.outcomes:
                victims[o.decision] += 1

    def rate(c: Counter, *ds):
        total = sum(c.values())
        return sum(c[d] for d in ds) / total if total else 0.0

    h, t, adv = by_label["human"], by_label["authorized"], by_label["adversarial"]
    summary = {
        "requests": sum(sum(c.values()) for c in by_label.values()),
        "simulated_minutes": duration / 60, "wall_seconds": round(wall_s, 1), "setup_seconds": round(setup_s, 1),
        "human_block_rate": rate(h, "block"),
        "human_friction_rate": rate(h, "challenge", "throttle"),
        "authorized_block_rate": rate(t, "block"),
        "authorized_throttle_rate": rate(t, "throttle"),
        "authorized_flag_rate": rate(t, "flag"),
        "adversarial_leak_rate": rate(adv, "allow", "flag"),
        "victim_tool_block_rate": rate(victims, "block"),
        "latency_us": {"p50": _pct(latencies, 50), "p95": _pct(latencies, 95), "p99": _pct(latencies, 99),
                       "max": max(latencies) if latencies else 0},
    }
    kinds = []
    for (label, kind), c in sorted(by_kind.items()):
        n = sum(c.values())
        row = {"label": label, "kind": kind, "n": n, **{d: c[d] / n for d in DECISIONS},
               "top_reasons": [r for r, _ in kind_reasons[kind].most_common(3)]}
        if label == "adversarial":
            det, tot = actors_detected[kind]
            row["actors_blocked"] = f"{det}/{tot}"
            row["median_s_to_first_block"] = round(statistics.median(detection[kind]), 1) if detection[kind] else None
        kinds.append(row)
    return {"summary": summary, "by_kind": kinds}


def to_markdown(r: dict) -> str:
    s = r["summary"]
    lines = [
        "# Simulation report", "",
        f"{s['requests']:,} verifications over {s['simulated_minutes']:.0f} simulated minutes "
        f"({s['wall_seconds']}s wall clock).", "",
        "| Metric | Value |", "|---|---|",
        f"| Human hard-block rate (FP) | {s['human_block_rate']:.2%} |",
        f"| Human friction (challenge + throttle) | {s['human_friction_rate']:.2%} |",
        f"| Authorized-tool block rate (FP) | {s['authorized_block_rate']:.2%} |",
        f"| Authorized-tool throttle rate (quota enforcement) | {s['authorized_throttle_rate']:.2%} |",
        f"| Authorized-tool flag rate | {s['authorized_flag_rate']:.2%} |",
        f"| Adversarial requests that got data (FN) | {s['adversarial_leak_rate']:.2%} |",
        f"| Victim tools (stolen token / forged keyid) blocked | {s['victim_tool_block_rate']:.2%} |",
        f"| Verify latency p50 / p99 / max (in-process) | {s['latency_us']['p50']/1000:.2f} / "
        f"{s['latency_us']['p99']/1000:.2f} / {s['latency_us']['max']/1000:.2f} ms |",
        "", "## By scenario", "",
        "| Class | Scenario | Requests | Allow | Flag | Challenge | Throttle | Block | Actors blocked | "
        "Median s to block | Top reasons (non-allow) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|---:|---|",
    ]
    for k in r["by_kind"]:
        lines.append(f"| {k['label']} | {k['kind']} | {k['n']:,} | " +
                     " | ".join(f"{k[d]:.1%}" for d in DECISIONS) +
                     f" | {k.get('actors_blocked', '')} | {k.get('median_s_to_first_block') or ''} | "
                     f"{', '.join(k['top_reasons'])} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--no-persist", action="store_true", help="skip Postgres writes (faster)")
    ap.add_argument("--out", default="reports")
    args = ap.parse_args()
    r = asyncio.run(simulate(args.minutes, args.scale, args.seed, not args.no_persist))
    out = Path(args.out)
    out.mkdir(exist_ok=True)
    r.pop("credentials", None)
    (out / "sim-report.json").write_text(json.dumps(r, indent=2))
    md = to_markdown(r)
    (out / "sim-report.md").write_text(md)
    print(md)


if __name__ == "__main__":
    main()
