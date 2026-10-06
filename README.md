# ffp-agent-verify

Verification and risk scoring for automated **frequent-flyer award search** traffic. It lets airlines tell three kinds of traffic apart:

- **Humans** searching by hand.
- **Authorized monitoring tools** that members explicitly approved. These run 24/7 across many airlines on rotating cloud IPs, which is fine.
- **Adversarial bots** with no authorization: quota abusers, credential resellers, token thieves.

It does this in under 50 ms, and it tells the tool *why* when it says no.

Every decision is broken down along three layers, following the framework in [docs/framework.md](docs/framework.md):

| Layer | Question | Signals today |
|---|---|---|
| **Safety** | Is this request an attack on the network? | signatures, replay, unknown keys, automation headers, edge bot score, IP churn |
| **Trust** | How much do we rely on this actor? | grant age, credential sharing, origin (datacenter/VPN), revocations |
| **Verifiability** | Does the behavior match what the member authorized? | key/client binding, route scope, quota velocity, one-credential-one-place |

`/v1/search/verify` returns the combined `score` plus `pillars`, the same score split across the three layers. Each reason is tagged with its layer.

```
 member ──consent──► Airline OAuth server ──10-min JWT, cnf.jkt = tool key──► Tool
                                                                           │ Ed25519 RFC 9421 signature
                                                                           ▼  on every search
                         ┌──────────── Airline search API ◄────────────────┘
                         │  POST /v1/search/verify  (~1 ms)
                         ▼
   ffp-agent-verify: signature → token → key binding → scope → policy ─┐
                     one Redis Lua call: nonce · revocation · quotas · cached risk score
                         │                                              │
                         ▼                                              ▼
              allow / flag / challenge / throttle / block      event stream → risk worker
              + reasons the tool can act on                    (velocity, IP churn & concurrency,
                                                                credential sharing, coverage) → Redis/Postgres
```

## Results

| | Value |
|---|---|
| Authorized-tool requests blocked in a 30-min mixed simulation | **0%** of ~55k |
| Human requests blocked | **0%** (VPN users are challenged, not blocked, under the default policy) |
| Authenticated attacks blocked | **≥99%** of requests for every scenario: stolen token, replay, forged keyid, credential fan-out (2.4 s to block), turncoat tool (~9 s after turning), route-scope abuse, credential farm |
| Credential-less scrapers blocked (scripting / headless) | **100%** |
| Verify latency at 2,000 req/s with 1,000 in flight | server **p99 3.9 ms**, client **p99 11.8 ms** |

**Known gap:** stealth scrapers that spoof full browser headers and use a fresh residential IP per request currently pass. Catching them needs edge signals, such as a forwarded CDN bot score or server-issued device ids. Details, methodology and the full tables are in [docs/results.md](docs/results.md).

## Quick start

```bash
make up        # Postgres/TimescaleDB + Redis (docker compose)
make install   # uv sync
make test      # unit + integration tests
make sim       # FP/FN report → reports/sim-report.md
make load      # latency / throughput → reports/load-*.json
make serve     # API + Swagger UI at http://localhost:8000/docs
make demo      # wipe the dev DB, seed traffic + redemption inventory, print UI credentials
make inventory # re-seed synthetic redemption inventory only
make inventory-report  # what award space is available / missing -> reports/inventory-coverage.md
uv run python -m sim.manual_check   # 4 hand-checkable cases, printed in full
```

## Docs

- [Framework](docs/framework.md): the safety / trust / verifiability decomposition, Cloudflare baseline, gaps, stress-test plan and roadmap
- [Redemption inventory](docs/inventory.md): award seats per flight, date and X/I/O class, available vs. total, partner space
- [Architecture](docs/architecture.md): data flow, latency budget, failure modes, design-question answers
- [Risk scoring](docs/risk-scoring.md): every signal, the formula, policy knobs, how tools keep a clean score
- [Airline integration guide](docs/integration-airlines.md): authorization server requirements, `/verify`, acting on decisions
- [Tool developer integration guide](docs/integration-tools.md): registration, OAuth, request signing, reason codes
- [Setup and deployment](docs/setup.md): local dev, Kubernetes, metrics and alerts
- [Results](docs/results.md): simulation and load-test numbers, known gaps, next steps
- [OpenAPI spec](docs/openapi.json), also served live at `/docs`

## Layout

```
src/ffpverify/
  api/app.py            REST API (verify, airlines/policy, tools, analytics, feedback)
  verify.py             hot path
  httpsig.py            RFC 9421 HTTP Message Signatures (Ed25519)
  tokens.py             airline JWT verification (cached, key-bound)
  store.py              Redis keys + hot-path Lua scripts
  policy.py             per-airline policy model
  inventory.py          redemption inventory: validation, ingest (feed + tool observations), catalog query
  risk/scorer.py        signals → score + reasons (pure functions)
  risk/pillars.py       signal → safety / trust / verifiability, per-layer score breakdown
  risk/worker.py        event stream → windowed features → scores, auto-revocation, persistence
  registry.py           in-memory airlines/policies/tool keys, live-reloaded via pub/sub
  reference_as/         reference airline OAuth server (PKCE, private_key_jwt, dpop_jkt)
  sdk/tool.py           tool-side SDK: register, OAuth, sign
  schema.sql            Postgres / TimescaleDB schema
sim/                    in-process harness + traffic simulator (humans, tools, 9 attack types),
                        synthetic redemption inventory (inventory.py), hand-checkable cases (manual_check.py)
loadtest/               multi-process load generator against a real uvicorn server
tests/                  unit (signing, tokens, scoring) + integration (end to end)
deploy/k8s/             Deployment/HPA/PDB for the API, Deployment for the worker
```
