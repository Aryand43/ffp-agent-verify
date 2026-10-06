"""The three layers every decision is broken into (see docs/framework.md).

- safety:        is this request an attack on the network? (forgery, replay, evasion, automation)
- trust:         how much do we rely on this actor? (history, delegation hygiene, origin)
- verifiability: does the behavior match what the principal authorized and the agent declared?

Pure functions, no I/O. Signals and hard-check codes map to exactly one pillar so each layer
can be measured and tuned on its own while the combined score stays unchanged.
"""

from collections import defaultdict
from enum import Enum

from .scorer import evidence_from_score


class Pillar(str, Enum):
    safety = "safety"
    trust = "trust"
    verifiability = "verifiability"


_SAFETY = {
    # behavioral / request-local
    "automation_headers", "external_bot_score", "ip_churn", "verification_failures",
    # hard checks: anyone could send these, they say nothing about the delegation
    "replay", "unknown_key", "missing_signature", "missing_token",
}
_TRUST = {
    "grant_age", "credential_sharing", "vpn", "vpn_not_permitted", "tool_revoked", "grant_revoked",
}
_VERIFIABILITY = {
    "velocity", "ip_concurrency", "airline_coverage",
    "rate_credential", "rate_tool", "rate_client", "rate_ip",
    "key_mismatch", "client_mismatch", "route_not_authorized", "wrong_airline", "bad_audience",
    "insufficient_scope", "unbound_token", "token_expired", "agents_not_permitted",
}
_NONE = {"degraded"}

SIGNAL_PILLAR: dict[str, Pillar] = {
    **{s: Pillar.safety for s in _SAFETY},
    **{s: Pillar.trust for s in _TRUST},
    **{s: Pillar.verifiability for s in _VERIFIABILITY},
}


def pillar_of(signal: str) -> Pillar | None:
    """Unlisted codes are signature / token-forgery failures from httpsig and tokens: safety."""
    if signal in _NONE:
        return None
    return SIGNAL_PILLAR.get(signal, Pillar.safety)


def tag(reasons: list[dict]) -> list[dict]:
    for r in reasons:
        p = pillar_of(r["signal"])
        r["pillar"] = p.value if p else None
    return reasons


def breakdown(score: float, groups: list[tuple[float, list[dict]]]) -> dict[str, float]:
    """Split a combined score across pillars.

    `groups` are independent evidence sources folded into `score`: (evidence, reasons) pairs, where
    each group's reason `points` say how its own evidence divides between signals (e.g. a cached grant
    score and its reasons). The result sums to `score`.
    """
    per: dict[Pillar, float] = defaultdict(float)
    for ev, reasons in groups:
        pts = [(pillar_of(r["signal"]), r.get("points") or 0.0) for r in reasons]
        tot = sum(p for _, p in pts)
        if ev <= 0 or tot <= 0:
            continue
        for pil, p in pts:
            if pil is not None:
                per[pil] += ev * p / tot
    total = sum(per.values())
    return {p.value: round(score * per[p] / total, 1) if total > 0 else 0.0 for p in Pillar}


def hard_block(signal: str) -> dict[str, float]:
    """A failed hard check is decided entirely by its own pillar."""
    p = pillar_of(signal)
    return {q.value: (100.0 if q is p else 0.0) for q in Pillar}


def from_cached(score_raw, reasons: list[dict]) -> tuple[float, list[dict]]:
    return (evidence_from_score(float(score_raw)) if score_raw else 0.0, reasons)
