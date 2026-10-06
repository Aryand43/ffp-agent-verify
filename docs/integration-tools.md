# Integration guide: FFP monitoring tool developers

The Python SDK is in [`sdk/tool.py`](../src/ffpverify/sdk/tool.py). Every step below is also plain HTTP, so you can implement it in any language.

## 1. Generate a key and register once

```python
from ffpverify.crypto import generate_private_key, private_key_to_pem
from ffpverify.sdk.tool import ToolClient

key = generate_private_key()                     # Ed25519. Keep it in your secret store.
reg = await ToolClient.register(http, "https://verify.example", name="SeatWatch",
                                contact="security@seatwatch.example",
                                redirect_uris=["https://seatwatch.example/oauth/callback"], key=key)
# reg = {"tool_id": "tool_…", "jkt": "<key thumbprint>", "management_token": "ffpv_tt_…"}  (token shown once)
tool = ToolClient(reg["tool_id"], key)
```

Registration includes a signature proving you hold the private key, so nobody can register your public key as theirs. If the key leaks, revoke it immediately with `POST /v1/tools/{id}/revoke` and the `X-Tool-Token` header, then register a new one.

## 2. Get each member's authorization at each airline

```python
url, state, verifier = tool.authorization_url("https://auth.example-airline.com",
                                              "https://seatwatch.example/oauth/callback",
                                              routes=["YVR-NRT", "YVR-HND"])   # optional route scoping
# Redirect the member to `url`. They log in at the airline and approve.
# The airline redirects back with ?code=…&state=…
tokens = await tool.exchange_code("https://auth.example-airline.com", code, verifier, redirect_uri)
```

- The authorization request carries your key thumbprint (`dpop_jkt`). The access token is bound to that key, so it's worthless to anyone without your private key.
- Access tokens last 5–15 minutes. Refresh before expiry with `await tool.refresh(as_base, tokens.refresh_token)`.
- Refresh tokens are **single-use**: store the new one every time.

## 3. Sign every search

```python
headers = tool.sign("GET", search_url, {"Accept": "application/json"}, tokens.access_token)
resp = await http.get(search_url, headers=headers)
```

`sign()` adds:

```
Authorization: Bearer eyJ…
Signature-Input: sig1=("@method" "@authority" "@path" "@query" "authorization");created=1790000000;
                 expires=1790000030;nonce="…";keyid="<jkt>";alg="ed25519";tag="ffp-agent-verify"
Signature: sig1=:…base64…:
```

To implement it yourself, follow RFC 9421 with Ed25519, and make sure that:

- the covered components include at least `@method @authority @path @query authorization`, or use `@target-uri` in place of the first four;
- every request gets a **fresh nonce** of at least 16 characters (nonces are single-use);
- `created` is within 30 s of real time and the signature is at most 60 s old;
- for POST bodies you add `Content-Digest` and cover `content-digest`.

Signing costs about 50 µs.

## 4. Handle responses

| Airline returns | Meaning | Do |
|---|---|---|
| 200 | allowed | – |
| 429 + `Retry-After` | quota | Wait that long. Hammering through 429s raises your `velocity` signal. |
| 403 + reasons | blocked | Read `reasons[].signal` / `detail` / `advice`. |

Common block reasons:

| `signal` | Fix |
|---|---|
| `replay` | Reused nonce: generate one per request. |
| `key_mismatch` | Token was issued for a different key. Re-authorize with your current key. |
| `token_expired` | Refresh earlier (the SDK's `needs_refresh()` uses a 60 s margin). |
| `route_not_authorized` | The member scoped the credential; only search those routes. |
| `grant_revoked` | The member, the airline, or auto-revocation removed this authorization. `detail` says why. |
| `agents_not_permitted` | This airline doesn't accept automated searches. |
| `ip_churn` / `ip_concurrency` | See [risk-scoring.md](risk-scoring.md#for-tool-developers-how-to-keep-a-clean-score). |

## 5. Watch your own risk profile

```bash
curl $FFPV/v1/tools/$TOOL_ID/analytics?hours=24 -H "X-Tool-Token: $TOKEN"
```

The response contains:

- decisions per airline, with p99 verify latency;
- top reason codes;
- your riskiest grants, with their live reasons;
- each airline's quotas and tolerances.

Check it after every deploy.
