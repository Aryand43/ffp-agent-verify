"""Load test: real uvicorn server (N workers) + risk worker + multi-process aiohttp clients.

    uv run python -m loadtest.run --mode closed --concurrency 1000 --duration 30
    uv run python -m loadtest.run --mode open --rps 3000 --concurrency 1000 --duration 30

closed: `concurrency` virtual clients each send back-to-back -> max throughput; latency there is
        mostly queueing (Little's law: latency ~= concurrency / throughput).
open:   requests arrive at a fixed `rps` regardless of responses (up to `concurrency` in flight)
        -> latency at a given load, which is what the <50ms p99 SLA is about.

Traffic mix: 70% valid signed agent searches, 20% browser (unauthenticated), 10% attacks
(bad signature, replay, scripting UA). Uses its own Postgres DB / Redis DB.
"""

import argparse
import asyncio
import json
import multiprocessing as mp
import os
import random
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

import asyncpg
import httpx
import jwt

from ffpverify.crypto import (generate_private_key, jwk_thumbprint, private_key_from_pem, private_key_to_pem,
                              public_jwk)
from ffpverify.sdk.tool import ToolClient

DB = "ffpv_load"
REDIS_DB = 14
ADMIN = "load-admin-key"
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
AIRLINES = ("AC", "SQ")
CHROME = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/129.0.0.0 Safari/537.36", "Accept": "text/html", "Accept-Language": "en-CA",
          "Sec-CH-UA": '"Chromium";v="129"'}


def server_env() -> dict:
    return {**os.environ, "FFPV_DATABASE_URL": f"postgresql://ffpv:ffpv@localhost:5432/{DB}",
            "FFPV_REDIS_URL": f"redis://localhost:6379/{REDIS_DB}", "FFPV_ADMIN_KEY": ADMIN}


async def reset() -> None:
    admin = await asyncpg.connect("postgresql://ffpv:ffpv@localhost:5432/ffpv")
    await admin.execute(f'DROP DATABASE IF EXISTS "{DB}" WITH (FORCE)')
    await admin.execute(f'CREATE DATABASE "{DB}"')
    await admin.close()
    import redis.asyncio as aioredis
    r = aioredis.from_url(f"redis://localhost:6379/{REDIS_DB}")
    await r.flushdb()
    await r.aclose()


async def setup(n_tools: int, n_grants: int) -> dict:
    """Register airlines + tools through the API; mint access tokens as the airlines' AS would."""
    fixture = {"airlines": {}, "grants": []}
    async with httpx.AsyncClient(base_url=BASE, timeout=30) as http:
        as_keys = {}
        for code in AIRLINES:
            k = generate_private_key()
            as_keys[code] = k
            jwk = {**public_jwk(k), "kid": "as1"}
            r = await http.post("/v1/airlines", headers={"X-Admin-Key": ADMIN}, json={
                "airline_id": code, "name": code, "issuer": f"https://auth.{code.lower()}.example",
                "jwks": {"keys": [jwk]}})
            r.raise_for_status()
            api_key = r.json()["api_key"]
            # Latency test, not a quota test: lift limits so most requests take the full allow path.
            r = await http.patch(f"/v1/airlines/{code}/policy", headers={"X-Api-Key": api_key}, json={
                "max_searches_per_min_per_credential": 100000, "max_searches_per_min_per_tool": 10000000,
                "max_searches_per_min_per_ip_unauthenticated": 100000, "min_grant_age_s": 0})
            r.raise_for_status()
            fixture["airlines"][code] = api_key
        tools = []
        for i in range(n_tools):
            key = generate_private_key()
            reg = await ToolClient.register(http, BASE, f"LoadTool{i}", "ops@example.com", [], key)
            tools.append((reg["tool_id"], key))
        now = int(time.time())
        for g in range(n_grants):
            tool_id, key = tools[g % n_tools]
            airline = AIRLINES[g % len(AIRLINES)]
            token = jwt.encode({"iss": f"https://auth.{airline.lower()}.example", "aud": "ffp-agent-verify",
                                "sub": f"member-{g}", "client_id": tool_id, "scope": "award:search",
                                "cnf": {"jkt": jwk_thumbprint(public_jwk(key))}, "iat": now, "exp": now + 900,
                                "jti": secrets.token_urlsafe(12), "auth_time": now - 86400},
                               as_keys[airline], algorithm="EdDSA", headers={"kid": "as1"})
            fixture["grants"].append({"tool_id": tool_id, "key": private_key_to_pem(key), "airline": airline,
                                      "token": token})
    return fixture


def make_request(rng: random.Random, grants, tools, replay_pool) -> tuple[str, dict]:
    r = rng.random()
    if r < 0.8:
        gi = rng.randrange(len(grants))
        g = grants[gi]
        url = (f"https://api.{g['airline'].lower()}.example/award/search?from=YVR&to="
               f"{rng.choice(['NRT', 'HND', 'LHR', 'SIN'])}&date=2026-12-0{rng.randint(1, 9)}")
        client = tools[g["tool_id"]]
        headers = client.sign("GET", url, {"Accept": "application/json"}, g["token"])
        kind = "agent"
        if r >= 0.75:  # attacks
            if r < 0.77:
                headers["Signature"] = "sig1=:" + "A" * 86 + "==:"
                kind = "attack_bad_sig"
            elif r < 0.79 and replay_pool:
                return "attack_replay", replay_pool[rng.randrange(len(replay_pool))]
        body = {"request": {"method": "GET", "url": url, "headers": headers},
                "client_ip": f"104.131.{gi // 250 % 256}.{gi % 250 + 1}",  # stable egress per grant, like a real tool
                "search": {"origin": "YVR", "destination": url.split("to=")[1][:3]}}
        return kind, {"airline": g["airline"], "body": body}
    airline = rng.choice(AIRLINES)
    ua = {"User-Agent": "python-requests/2.32"} if r > 0.97 else CHROME
    return ("attack_script" if r > 0.97 else "browser"), {"airline": airline, "body": {
        "request": {"method": "GET", "url": f"https://www.{airline.lower()}.example/award?from=YVR&to=NRT",
                    "headers": ua},
        "client_ip": f"{rng.choice([24, 66, 99])}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}",
        "client_signals": {"device_id": f"d{rng.getrandbits(40)}"}}}


def client_proc(idx: int, fixture: dict, mode: str, concurrency: int, rps: float, duration: float, q) -> None:
    import aiohttp
    import uvloop

    async def main():
        rng = random.Random(idx)
        tools = {}
        for g in fixture["grants"]:
            if g["tool_id"] not in tools:
                tools[g["tool_id"]] = ToolClient(g["tool_id"], private_key_from_pem(g["key"]))
        grants = fixture["grants"]
        replay_pool: list = []
        lat, server_lat, decisions, errors = [], [], {}, 0
        conn = aiohttp.TCPConnector(limit=concurrency, keepalive_timeout=30)
        stop_at = time.perf_counter() + duration
        sem = asyncio.Semaphore(concurrency)

        async with aiohttp.ClientSession(connector=conn) as s:
            async def one():
                nonlocal errors
                kind, item = make_request(rng, grants, tools, replay_pool)
                t0 = time.perf_counter()
                try:
                    async with s.post(f"{BASE}/v1/search/verify", json=item["body"],
                                      headers={"X-Api-Key": fixture["airlines"][item["airline"]]}) as resp:
                        data = await resp.json()
                        if resp.status != 200:
                            errors += 1
                            return
                except Exception:
                    errors += 1
                    return
                lat.append(time.perf_counter() - t0)
                if kind == "agent" and len(replay_pool) < 200:
                    replay_pool.append(item)  # only requests the server has already seen can be replays
                server_lat.append(data["latency_us"])
                key = f"{kind}:{data['decision']}" + (":degraded" if data.get("degraded") else "")
                decisions[key] = decisions.get(key, 0) + 1

            if mode == "closed":
                async def vu():
                    while time.perf_counter() < stop_at:
                        await one()
                await asyncio.gather(*(vu() for _ in range(concurrency)))
            else:
                tasks, interval, nxt = set(), 1.0 / rps, time.perf_counter()
                dropped = 0

                async def guarded():
                    async with sem:
                        await one()
                while time.perf_counter() < stop_at:
                    nxt += interval
                    delay = nxt - time.perf_counter()
                    if delay > 0:
                        await asyncio.sleep(delay)
                    if sem.locked():
                        dropped += 1  # all `concurrency` slots busy: the server is saturated
                        continue
                    t = asyncio.create_task(guarded())
                    tasks.add(t)
                    t.add_done_callback(tasks.discard)
                await asyncio.gather(*tasks)
                errors += dropped
        q.put({"lat": lat, "server": server_lat, "decisions": decisions, "errors": errors})

    uvloop.run(main())


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100 * len(xs)))] if xs else 0


def wait_healthy(timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if httpx.get(f"{BASE}/healthz", timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise RuntimeError("server did not become healthy")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["closed", "open"], default="closed")
    ap.add_argument("--concurrency", type=int, default=1000)
    ap.add_argument("--rps", type=float, default=2000)
    ap.add_argument("--duration", type=float, default=30)
    ap.add_argument("--server-workers", type=int, default=6)
    ap.add_argument("--client-procs", type=int, default=4)
    ap.add_argument("--tools", type=int, default=20)
    ap.add_argument("--grants", type=int, default=2000)
    ap.add_argument("--out", default="reports")
    args = ap.parse_args()

    asyncio.run(reset())
    env = server_env()
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "ffpverify.api.app:app", "--port", str(PORT),
                               "--workers", str(args.server_workers), "--loop", "uvloop", "--http", "httptools",
                               "--no-access-log", "--log-level", "warning", "--backlog", "4096"], env=env)
    worker = subprocess.Popen([sys.executable, "-m", "ffpverify.risk.worker"], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_healthy()
        fixture = asyncio.run(setup(args.tools, args.grants))
        time.sleep(2)  # let every server worker pick up the new tools via pub/sub
        q = mp.Queue()
        per = max(1, args.concurrency // args.client_procs)
        procs = [mp.Process(target=client_proc, args=(i, fixture, args.mode, per, args.rps / args.client_procs,
                                                       args.duration, q)) for i in range(args.client_procs)]
        t0 = time.perf_counter()
        for p in procs:
            p.start()
        results = [q.get() for _ in procs]
        wall = time.perf_counter() - t0
        for p in procs:
            p.join()
    finally:
        for p in (server, worker):
            p.send_signal(signal.SIGINT)
        for p in (server, worker):
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()

    lat = [x for r in results for x in r["lat"]]
    srv = [x for r in results for x in r["server"]]
    decisions: dict = {}
    for r in results:
        for k, v in r["decisions"].items():
            decisions[k] = decisions.get(k, 0) + v
    errors = sum(r["errors"] for r in results)
    report = {
        "mode": args.mode, "concurrency": args.concurrency, "target_rps": args.rps if args.mode == "open" else None,
        "server_workers": args.server_workers, "duration_s": args.duration,
        "completed": len(lat), "errors_or_dropped": errors, "throughput_rps": round(len(lat) / wall, 1),
        "client_ms": {p: round(pct(lat, p) * 1000, 2) for p in (50, 90, 99, 99.9)} | {"max": round(max(lat) * 1000, 2)},
        "server_verify_ms": {p: round(pct(srv, p) / 1000, 3) for p in (50, 90, 99, 99.9)} | {"max": round(max(srv) / 1000, 3)},
        "decisions": dict(sorted(decisions.items())),
    }
    Path(args.out).mkdir(exist_ok=True)
    (Path(args.out) / f"load-{args.mode}.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
