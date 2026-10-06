# Framework: Safety, Trust, Verifiability

> **Problem statement.** How do we let agents talk to other agents, and to the platforms they act on, in a way that is **safe**, **trusted** and **verifiable**?

The FFP award-search network is the first vertical we're building this for. It already has the three actors every agent-to-agent system has:

- **Principals.** Members who delegate.
- **Agents.** Monitoring tools acting for those members.
- **Relying platforms.** Airlines whose APIs the agents call.

This doc breaks the problem into three layers. For each layer it sets out what's built today, what the existing baseline (mostly Cloudflare) already covers, the gap, and the end goal. It's backend-first. The UI is deliberately out of scope until the engine is right.

```
                       ┌───────────────────────────────────────────────┐
  request ──► SAFETY ──► TRUST ──► VERIFIABILITY ──► decision + reasons │
              "is this    "how much   "does what it does match          │
               an attack?" do we rely  what it was authorized and       │
                           on it?"     declared to do?"                 │
                       └───────────────────────────────────────────────┘
       each layer emits its own evidence → combined score, and a per-layer breakdown in every response
```

The three layers are separate questions. An agent can be cryptographically genuine (safe) and long-standing (trusted) yet still do something its principal never asked for (unverifiable). Collapsing them into one bot score is exactly why existing tools mistreat legitimate automation.

---

## 1. Safety: is this request an attack on the network?

**Scope.** Detecting adversarial agents and protecting the relying platform's network: forgery, replay, impersonation, scraping without authorization, evasion such as IP rotation and headless spoofing, and degraded-mode behavior.

**Built today**

| Mechanism | Where |
|---|---|
| Ed25519 RFC 9421 request signatures, the same scheme as Web Bot Auth | `httpsig.py` |
| Single-use nonces (replay), key revocation, unknown-key rejection | `store.py` Lua, `verify.py` |
| Automation and headless detection for unauthenticated traffic | `risk/scorer.py: automation_strength` |
| IP churn, datacenter egress, forwarded edge bot score | `risk/scorer.py`, `ipintel.py` |
| Attributable vs. non-attributable failures, so a third party can't frame a tool by spraying its keyid | `verify.py: ATTRIBUTABLE` |
| Fail-open / fail-closed per airline. Crypto checks still apply when Redis is down | `verify.py: _degraded` |

**Baseline: what Cloudflare already does**

- **Bot Management.** A per-request ML bot score (1–99), JA3/JA4 TLS fingerprints, JS detections and Turnstile challenges.
- **Verified Bots and Signed Agents.** Web Bot Auth (RFC 9421 + Ed25519, keys published at a well-known URL). As of mid-2026 Cloudflare validates the signature and exposes a "Verified AI Agent" identity to its rules. The launch list covered the major AI browsers.
- **WAF, rate limiting and DDoS protection** at the edge.

**Gap.** Cloudflare answers "which *operator* sent this?" and "does this *look* like a bot?" It doesn't answer:

- which *user* the agent is acting for;
- whether that user delegated this specific action;
- whether a verified operator's individual credential is being resold or fanned out.

Its bot score also treats all automation as suspicious unless it's on the verified list. That is exactly the false positive a legitimate monitoring tool hits.

**End goal.** Safety becomes an *input* we consume, not a thing we rebuild. Planned steps:

- Accept the Cloudflare or other CDN bot score and Web Bot Auth identity as signals. This is partly done via `client_signals.bot_score`.
- Spend our own effort on what the edge can't see: per-credential behavior, delegation abuse, and agent-to-agent attacks. The last covers prompt-injected agents relaying malicious instructions, and confused-deputy calls where agent A uses agent B's authority.

**Open R&D**

- Stealth scrapers with full browser headers and a fresh residential IP per request. This is our known gap; see the README.
- Detecting a *compromised* agent, meaning a valid key whose behavior is driven by injected instructions, from request patterns alone.

---

## 2. Trust: how much should we rely on this actor?

**Scope.** A trust score for the agent, its principal and the delegation between them. It's built from:

- **Behavior now.** The current window.
- **History.** This grant, this tool, and this member across airlines.
- **External reputation.** Other networks and registries.
- **Origin.** ASN, hosting type and geography.

**Built today**

| Signal | What it captures |
|---|---|
| `grant_age` and the reduced quota for new grants | Trust is earned over time |
| `credential_sharing` | One member authorizing many tools looks like an account farm |
| `vpn` (datacenter egress) | Origin. Weighted 0 for agents by default, because tools legitimately run in clouds |
| Cached grant and tool scores folded into every decision | Recent history, over a few minutes |

**Baseline.** Cloudflare's verified list is binary: on the list or not. IP reputation feeds such as MaxMind, IPinfo and Spur give origin only. Social platforms (X, Meta) run rich account-trust models, but they're closed and can't be carried across platforms.

**Gap.** Nothing today gives an *agent* or a *delegation* a portable, history-based trust level that a second platform can use. Our own history is minutes long, from the sliding windows. There is no long-term reputation yet.

**End goal**

- **Long-horizon reputation per tool, member and grant.** A decayed score over days and weeks, backed by the `search_requests` and `risk_events` tables that already exist. A good record should *earn* higher quotas, not only avoid penalties.
- **Cross-airline trust.** Abuse at airline A lowers trust at airline B. The shared network already sees all airlines, which is the moat.
- **Origin priors.** ASN, country and hosting type as a *weak* prior that behavior can override. Example: Singapore egress is frequently flagged because of VPN transit traffic, so geography alone must never block.
- **External attestations.** Operator verification (KYC'd developer, Web Bot Auth directory listing) as a trust bump.

**Open R&D**

- Making trust *hard to farm*. A sleeper builds a clean history and then defects. The `Turncoat` simulation catches this within seconds today, but only because the defection is loud.
- How fast trust should decay, and how much one incident should cost.

---

## 3. Verifiability: does the behavior match the authorization and the declared intent?

**Scope.** Once a request is known to be genuine and from a trusted actor, check that *this action* is something the principal actually delegated, and that the agent behaves as its declared purpose implies.

**Built today**

| Check | Kind |
|---|---|
| Token bound to the signing key (`cnf.jkt`) and issued to this tool (`client_id`) for this airline | Hard |
| Route scope (`ffp_routes`): only routes the member authorized | Hard |
| Airline-level permission (`authorized_agents_allowed`) | Hard |
| `velocity` against the delegated quota | Behavioral |
| `ip_concurrency`: one credential should behave like one agent | Behavioral |
| `airline_coverage` for unauthenticated clients | Behavioral |

**Baseline.** OAuth scopes and RFC 9449/7523 key binding prove *what was granted*. Nothing in the Cloudflare stack checks behavior against intent. A verified agent is trusted for anything.

**Gap.** Scopes are coarse. "Search award space" doesn't say how often, for which routes, or for which trip. Nothing checks that the *pattern* of actions matches the purpose the user consented to.

**End goal**

- **Declared intent in the grant.** A tool registers a purpose profile, for example "monitor these 5 routes, at most N searches per hour, for this member". The engine scores *deviation from the declared profile*. Route-scope abuse is the first, binary version of this.
- **Signed, auditable decisions.** Every allow/block, with its reasons, goes to a verifiable log. A member, airline or auditor can then check after the fact what an agent did in their name.
- **Agent-to-agent delegation chains.** When agent A calls agent B for user U, the token carries the chain (OAuth token exchange, RFC 8693 `act` claim). Each hop is verified against the original user's consent.

---

## Cross-cutting: network security

Sharveen flagged this as a large part of the product. A CTO evaluating it will ask what it touches in their network. The current posture:

- **No inbound path.** The verifier is a sidecar the airline calls (`POST /v1/search/verify`). It never sits in front of airline systems and never proxies traffic.
- **No secrets leave the airline.** We store `member_ref = sha256(airline:sub)`, never FFP numbers. Tokens are verified against the airline's JWKS.
- **Bounded blast radius.** It's latency-capped (`redis_timeout_ms`), with explicit fail-open or fail-closed, per-airline API keys, and policy versioning with rollback.

Still to do before a security review:

- A threat model for the verifier itself, with STRIDE per component.
- mTLS between airline and verifier, and secret rotation.
- Network-segmentation guidance for co-located deployment.
- Rules for what crosses the airline boundary when agent-to-agent calls leave for other platforms.

---

## Stress testing: borrow the social-media bot playbook

X and Meta face the most mature bot adversaries. Their attack classes map directly onto agents:

| Social-media attack | Agent-network analogue | Simulated today? |
|---|---|---|
| Account farms / Sybils | Credential farm: many fake members, each authorizing one tool | Yes (`credential farm`) |
| Account takeover | Stolen token or stolen key | Yes (`TokenThief`, `Forger`) |
| Credential / account resale | Credential fan-out across workers | Yes (`CredentialFanout`) |
| Sleeper accounts that build reputation and then defect | Turncoat tool | Yes, but only *loud* defection (`Turncoat`) |
| Coordinated inauthentic behavior: many accounts, each under thresholds | Low-and-slow swarm: N grants, each at 90% of quota, jointly covering a route set | **No** |
| Residential-proxy scraping farms | Stealth scraper with a fresh residential IP per request | Yes, and it **passes** (known gap) |
| LLM-driven accounts that mimic human cadence | Agent that randomizes timing and routes to look human | **No** |
| Spam relayed via compromised accounts | Prompt-injected agent relaying malicious calls to other agents | **No** |

The next simulator work is the three **No** rows. They test the layers that today are thinnest: cross-entity trust, and intent verification.

---

## Roadmap (proposed order)

1. **Make the three layers explicit in the engine.** *Done in this change.* Every signal is tagged with a layer. `/v1/search/verify` returns a per-layer breakdown (`pillars`) next to the combined score, so each layer can be measured and tuned on its own.
2. **Trust: long-horizon reputation.** A decayed per-tool, per-member and per-grant score from Postgres, refreshed by the worker, plus cross-airline propagation.
3. **Verifiability: declared-intent profiles.** Purpose profiles at registration, and a deviation score against them.
4. **Stress tests.** Low-and-slow swarm, human-mimicking agent, prompt-injected relay.
5. **Safety: edge integration.** Ingest the Cloudflare bot score and Web Bot Auth identity, and close the residential-proxy gap with edge signals.
6. **Network-security review pack.** Threat model, mTLS, deployment guide.
7. **Multi-IP searching (before go-live).** If one airline bans an egress IP, a popular tool degrades for everyone. This needs a design that coexists with the `ip_churn` / `ip_concurrency` signals. See [inventory.md](inventory.md#not-done-yet).

## Questions for the next review

- Which layer first, after the engine refactor: trust (reputation) or verifiability (intent profiles)? The proposal is trust, because it compounds with every other signal.
- Is FFP the right first vertical to prove the framework, or should we also pick a second domain (e.g. agentic commerce) early, to keep the engine general?
- Which external reputation sources are realistic for a pilot?
