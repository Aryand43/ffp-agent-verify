# Integration guide: airlines

You do three things:

1. Issue key-bound access tokens from your OAuth server.
2. Call `/v1/search/verify` for every award search.
3. Act on the decision.

## 1. Onboarding

An ffp-agent-verify admin creates your airline with your authorization server's issuer and signing keys. You receive an API key once.

```bash
curl -X POST $FFPV/v1/airlines -H "X-Admin-Key: $ADMIN" -H 'content-type: application/json' -d '{
  "airline_id": "AC", "name": "Air Canada Aeroplan",
  "issuer": "https://auth.example-airline.com",
  "jwks_uri": "https://auth.example-airline.com/.well-known/jwks.json"
}'
# → {"airline_id": "AC", "api_key": "ffpv_ak_..."}
```

To rotate signing keys, use `PUT /v1/airlines/AC/jwks`. Either `jwks` (inline) or `jwks_uri` works.

## 2. Your authorization server

[`reference_as/app.py`](../src/ffpverify/reference_as/app.py) is a working ~200-line template. The tests and simulator run against it. Your production AS must do the following.

**Authorization endpoint:**
- Accept the authorization code flow with **PKCE S256**.
- Accept a **`dpop_jkt`** parameter (RFC 9449 §10).
- Check that `dpop_jkt` equals the tool's registered key thumbprint, and that `redirect_uri` is registered. Both come from `GET /v1/tools/{client_id}/jwks`, which is public.
- Show the member which tool is asking and which routes (optional `ffp_routes`). Grant search only; no booking or balance access.

**Token endpoint:**
- Authenticate the tool with **`private_key_jwt`** (RFC 7523), verified against that same JWKS.
- Issue access tokens shaped like this:

```json
{
  "iss": "https://auth.example-airline.com",
  "aud": "ffp-agent-verify",
  "sub": "<pairwise member id - not the FFP number>",
  "client_id": "tool_…",
  "scope": "award:search",
  "cnf": {"jkt": "<tool key thumbprint>"},
  "iat": 1790000000, "exp": 1790000600,
  "jti": "<unique>",
  "auth_time": 1789990000,
  "ffp_routes": ["YVR-NRT", "YVR-HND"]
}
```

| Claim | Rules |
|---|---|
| Algorithm | `EdDSA` or `ES256`; a `kid` in the header must match your JWKS |
| `exp − iat` | At most 900 s (we reject longer) |
| `cnf.jkt` | **Mandatory**. Unbound bearer tokens are rejected. |
| `auth_time` | When the member consented. Drives the young-grant quota. |
| `ffp_routes` | Optional. Makes the credential search-specific. |

**Refresh tokens:**
- Rotate them on every use (single-use).
- Let members revoke the tool from their account page. Also call `POST /v1/airlines/{id}/grants/{grant_id}/revoke` so revocation is immediate rather than waiting out token expiry.

## 3. Verify every search

```http
POST /v1/search/verify
X-Api-Key: ffpv_ak_...
Content-Type: application/json

{
  "request": {
    "method": "GET",
    "url": "https://api.example-airline.com/award/search?from=YVR&to=NRT&date=2026-12-01",
    "headers": { "...all request headers, verbatim..." }
  },
  "client_ip": "203.0.113.7",
  "search": {"origin": "YVR", "destination": "NRT", "date": "2026-12-01", "cabin": "business"},
  "client_signals": {"device_id": "<your first-party session id>", "webdriver": false, "bot_score": 0.12}
}
```

How to build the request:

- **`url`:** the exact URL the client requested (scheme, host, path, query), because the signature covers it. If a proxy rewrites the host, send the original.
- **`headers`:** forward them all. `Authorization`, `Signature-Input` and `Signature` are required for agents. `User-Agent`, `Accept*` and `Sec-CH-*` feed the human/bot heuristics.
- **`client_signals`:** all fields are optional, and each one makes the unauthenticated lane more accurate.
  - `device_id` should be a **server-issued, signed** first-party session id. Unverified client-supplied ids would let a scraper claim a fresh "device" per request.
  - `bot_score` is your CDN's bot-management score normalized to 0 = human, 1 = bot.

Response:

```json
{
  "request_id": "6c1f…",
  "decision": "throttle",
  "lane": "authenticated",
  "score": 12.0,
  "reasons": [{"signal": "rate_credential", "detail": "credential rate limit of 30/min reached",
               "advice": "Retry after 2s; spread searches evenly."}],
  "tool_id": "tool_…",
  "retry_after_s": 2,
  "policy_version": 4,
  "degraded": false,
  "latency_us": 640
}
```

## 4. Act on the decision

| decision | What to do |
|---|---|
| `allow` | Serve the search. |
| `flag` | Serve it. It's logged for review; consider sampling these. |
| `challenge` | Unauthenticated only: serve a CAPTCHA or interstitial, then send `client_signals.captcha` on the retry. |
| `throttle` | `429` with `Retry-After: retry_after_s`. |
| `block` | `403`. For agents, return `reasons` in the body. Tools need them to fix their behavior, and this is how false positives get reported instead of silently churning users. |

**Timeouts.** Give the verify call a client timeout of about 50 ms. If it fails, apply your own fail-open or fail-closed choice, mirroring `fail_mode` in your policy.

## 5. Policy and feedback

```bash
# Tighten quotas live (no redeploy). Partial updates merge into the current policy.
curl -X PATCH $FFPV/v1/airlines/AC/policy -H "X-Api-Key: $KEY" -d '{"max_searches_per_min_per_credential": 20}'

# Label outcomes; this is the ground truth used to tune weights and thresholds.
curl -X POST $FFPV/v1/feedback -H "X-Api-Key: $KEY" \
  -d '{"label": "false_positive", "request_id": "6c1f…", "notes": "customer complaint, legit SeatWatch user"}'
```

Labels are `false_positive`, `false_negative`, `confirmed_abuse` and `confirmed_legitimate`.

See [risk-scoring.md](risk-scoring.md) for every knob.
