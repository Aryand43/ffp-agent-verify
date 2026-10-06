# Risk scoring

Audience: airlines tuning policy and tool developers who want to stay out of trouble.

## Decision order

The checks below run in order, and the first one that fails decides the request.

**Authenticated lane:**

1. Hard checks:
   - signature present and valid;
   - key registered and not revoked;
   - token valid for *this* airline;
   - token bound to the signing key (`cnf.jkt`) and issued to this tool (`client_id`);
   - route inside `ffp_routes`;
   - airline accepts agents at all;
   - VPN policy.

   Any failure is a **block**, with a specific reason code.
2. Replay (nonce reuse) or a revoked grant/tool: **block**.
3. Quota (token buckets per credential, and per tool per airline): **throttle**, with `retry_after_s`.
4. Behavioral score from the risk worker, combined with request-local evidence, then compared with the airline's thresholds:

   | Score | Decision |
   |---|---|
   | ≥ `block` | **block** |
   | ≥ `throttle` | **throttle** |
   | ≥ `challenge` | **flag** (allowed, logged for review) |
   | ≥ `revoke` | The worker also auto-revokes the grant. |

**Unauthenticated lane:** hard VPN rule, then per-client rate limits, then the score, which maps to challenge / throttle / block.

## How signals combine

Each signal produces a strength `s` in [0, 1):

| Strength | Meaning |
|---|---|
| 0 | normal |
| ~0.5 | clearly past the airline's tolerance |
| → 1 | unambiguous abuse |

Strengths combine as independent evidence:

```
score = 100 × (1 − exp(−Σ wᵢ · −ln(1 − sᵢ)))
```

- **One strong signal is enough to act on.** A weighted average would dilute it.
- **Several weak signals compound.** Three minor issues together can reach flag or throttle, even though none would alone.
- **A weight of 0 disables a signal.** Weights are per airline (`weights_authenticated`, `weights_unauthenticated`).
- **Each signal's share of the score is reported** as `points` in the reasons.

## Per-layer breakdown

Every signal and hard-check code belongs to one layer: **safety**, **trust** or **verifiability** (mapping in `risk/pillars.py`, rationale in [framework.md](framework.md)). The response's `pillars` field splits the combined score across the three layers in proportion to each layer's evidence, so the three values sum to `score`. A failed hard check puts 100 on its own layer. The breakdown is explanatory only: decisions still use the combined score against the airline's thresholds.

## Authenticated signals (defaults)

| Signal | Weight | Strength | What it catches |
|---|---|---|---|
| `velocity` | 3 | `(searches_60s / quota − 1) / 2` | Ignoring quotas (counts attempts, including throttled ones) |
| `ip_churn` | 2 | `(ip_changes_5m / (300 / min_ip_rotation_interval_s) − 1) / 4` | Rotating IPs every few seconds instead of every few minutes |
| `ip_concurrency` | 3 | `(distinct_ips_60s − max) / (2 · max)` | One credential driven from many places (resale, fan-out) |
| `grant_age` | 1 | `0.3 · (1 − age / min_grant_age_s)` | Brand-new authorizations; mild on its own |
| `credential_sharing` | 2 | `(tools_for_member − max) / (2 · max)` | One member authorizing many tools (credential farm) |
| `verification_failures` | 3 | `1 − exp(−failures_5m / 5)` | Only *attributable* failures, ones that needed the private key: key/client mismatch, out-of-scope route, wrong airline, expired token. Bad signatures and replays are **not** attributable, because anyone can put your keyid on garbage or resend your request. |
| `vpn` | 0 | 0.5 if datacenter egress | Off by default for agents, since tools legitimately run in clouds |

**Not scored for agents:** 24/7 activity, number of airlines, booking conversion, and route repetition. Those describe what a monitoring tool *is*. Route and time patterns are stored in `search_requests` for analytics.

## Unauthenticated signals (defaults)

| Signal | Weight | Notes |
|---|---|---|
| `automation_headers` | 3 | Scripting/headless UA, `navigator.webdriver`, missing browser headers, failed challenge. Computed per request, so it works even if Redis is down. |
| `velocity` | 3 | Per device when the airline forwards a first-party `device_id`, else per IP. The per-IP allowance scales with distinct devices seen behind the IP (up to `max_devices_per_ip`), so offices and carrier NAT aren't punished. |
| `ip_churn` | 2 | Only with a device id: the same device hopping IPs. |
| `airline_coverage` | 2 | Same IP across many airlines in 10 min, using the shared network's cross-airline view. Halved when keyed by IP. When the airline sends device ids, IP-level evidence counts at 25%, since it may belong to other people behind the same address. |
| `vpn` | 1 | Datacenter egress. With `vpn_tolerance: authenticated_only`, an otherwise-clean VPN user gets a **challenge**, never a block. |
| `external_bot_score` | 2 | Pass your CDN's bot score (0 = human, 1 = bot) as `client_signals.bot_score`. |

## Policy knobs (per airline)

`PUT` or `PATCH /v1/airlines/{id}/policy` takes effect on every replica within about a second, with no redeploy. Every version is kept.

```json
{
  "authorized_agents_allowed": true,
  "max_searches_per_min_per_credential": 30,
  "max_searches_per_min_per_tool": 600,
  "max_searches_per_min_per_ip_unauthenticated": 20,
  "max_devices_per_ip": 10,
  "burst_multiplier": 1.5,
  "min_ip_rotation_interval_s": 60,
  "max_concurrent_ips_per_credential": 2,
  "min_grant_age_s": 3600,
  "new_grant_rate_factor": 0.5,
  "max_tools_per_member": 3,
  "vpn_tolerance": "authenticated_only",
  "unauthenticated_mode": "score",
  "weights_authenticated": {"velocity": 3, "ip_churn": 2, "ip_concurrency": 3, "grant_age": 1,
                            "credential_sharing": 2, "verification_failures": 3, "vpn": 0},
  "thresholds": {"challenge": 40, "throttle": 60, "block": 80, "revoke": 95},
  "fail_mode": "open"
}
```

Typical airline postures:

| Posture | Settings |
|---|---|
| **Zero automation** | `authorized_agents_allowed: false` (agents get a clear `agents_not_permitted` block, not a mysterious failure) |
| **No VPNs at all** | `vpn_tolerance: "block"` |
| **Strict** | Lower `thresholds.block` to 70, raise `verification_failures` to 5, `fail_mode: "closed"` |
| **Disable auto-revocation** | `thresholds.revoke: 100` |

## For tool developers: how to keep a clean score

1. **Stay under quota and honor `Retry-After`.** Quotas are listed in `GET /v1/tools/{id}/analytics` under `airline_quotas`. Spread polling evenly instead of bursting.
2. **One egress IP per user credential**, held for at least `min_ip_rotation_interval_s` (default 60 s). Rotating every few *minutes* is fine. Rotating every few *seconds* reads as evasion.
3. **Don't fan one member's credential across workers.** Shard by member instead: one member's searches come from one place.
4. **New authorizations start at half quota** for the first hour. Plan for it.
5. **Fresh nonce per request; sign with the current token; refresh before expiry.**
6. **Search only routes the member authorized** if the airline scoped the credential.
7. **Read `reasons`.** Every non-allow decision says which signal fired, its share of the score, and what to change.
