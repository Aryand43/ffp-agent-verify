# Setup

## Local development

Requirements: Docker, [uv](https://docs.astral.sh/uv/), and Python 3.12 (uv installs it if needed).

```bash
make up            # Postgres (TimescaleDB) + Redis via docker compose
make install       # uv sync
make test          # 64 unit + integration tests (~5 s)
make serve         # API on :8000, OpenAPI UI at http://localhost:8000/docs
make worker        # risk worker (second terminal)
```

Configuration is through environment variables prefixed `FFPV_` (see `.env.example` and `src/ffpverify/config.py`):

| Variable | Default | Notes |
|---|---|---|
| `FFPV_DATABASE_URL` | `postgresql://ffpv:ffpv@localhost:5432/ffpv` | |
| `FFPV_REDIS_URL` | `redis://localhost:6379/0` | |
| `FFPV_ADMIN_KEY` | `dev-admin-key` | **Change in production.** Used only to create airlines and for admin overrides. |
| `FFPV_REDIS_TIMEOUT_MS` | 20 | Hot-path Redis budget before the airline's `fail_mode` applies |
| `FFPV_MAX_SIGNATURE_AGE_S` | 60 | |
| `FFPV_CLOCK_SKEW_S` | 30 | |
| `FFPV_MAX_TOKEN_LIFETIME_S` | 900 | Tokens with `exp − iat` above this are rejected |

Try the whole flow by hand: run the integration tests, or read `sim/harness.py`. It wires the API, a reference airline AS per airline, and the worker together in one process.

## Simulation and load tests

```bash
make sim    # 30 simulated minutes, humans + authorized tools + 9 attack types → reports/sim-report.md
make load   # open-loop 2000 rps and closed-loop 1000 concurrent clients → reports/load-*.json
```

The simulator runs on a simulated clock (30 min of traffic in about 1 min). The load test runs a real multi-worker uvicorn server and the risk worker against Postgres and Redis.

## Production deployment

```bash
docker build -t ffp-agent-verify:latest .
kubectl create secret generic ffpv-secrets \
  --from-literal=FFPV_DATABASE_URL=... --from-literal=FFPV_REDIS_URL=... --from-literal=FFPV_ADMIN_KEY=...
kubectl apply -f deploy/k8s/
```

- **Verify API** (`deploy/k8s/verify.yaml`): one uvicorn process per pod, starting at 4 replicas. The HPA targets 50% CPU, because queueing, not verification, is what breaks the p99. Probes hit `/healthz` and Prometheus scrapes `/metrics`.
- **Risk worker** (`deploy/k8s/worker.yaml`): 2+ replicas in one Redis consumer group.
- **Redis:** managed Redis with a replica (ElastiCache, Memorystore). Disable eviction for `rv:*` (revocation) keys, or use `noeviction`. Revocations are also re-asserted from Postgres on every API startup.
- **Postgres:** a TimescaleDB-capable Postgres (Timescale Cloud, or self-managed). Without the extension, `search_requests` stays a plain table and everything still works. Add retention, for example `SELECT add_retention_policy('search_requests', INTERVAL '90 days')`.
- **Placement:** run in the same region or VPC as each airline's search API. For multi-region, run a Redis per region. Revocations and policy changes propagate through Postgres plus a periodic reload (60 s); add cross-region pub/sub if you need faster.
- **Serverless:** the API is stateless apart from Redis and Postgres, so Cloud Run and Lambda (via Mangum) both work. The in-process token cache and registry warm up per instance, so keep minimum instances above 0.

### Metrics to alert on

| Metric | Meaning |
|---|---|
| `ffpv_verify_latency_seconds` (histogram, by lane) | Alert on p99 > 20 ms. |
| `ffpv_decisions_total{airline,lane,decision}` | Sudden block-rate change for an airline means a policy mistake or an attack. |
| `ffpv_degraded_total` / `ffpv_redis_over_budget_total` | Any sustained value means Redis is slow or the pods are CPU-saturated. Scale out. |
| Stream lag | `XINFO GROUPS ffpv:events` → `lag`. The worker is falling behind, so scores are stale. |
| `/healthz` `events_dropped` | Event buffer shed analytics under overload. |
