"""Risk scoring: features -> per-signal strength -> combined 0-100 score with reasons.

Pure functions, no I/O. Used by the async worker (behavioral signals over time windows)
and by the hot path (signals that only need the current request).
"""

import math
import re
from dataclasses import dataclass, field

from ..policy import AirlinePolicy

MAX_STRENGTH = 0.99


def _clamp(x: float) -> float:
    return max(0.0, min(MAX_STRENGTH, x))


def evidence(weight: float, strength: float) -> float:
    return weight * -math.log(1 - _clamp(strength))


def score_from_evidence(total: float) -> float:
    return 100 * (1 - math.exp(-total))


def evidence_from_score(score: float) -> float:
    return -math.log(1 - min(score, 99.99) / 100)


@dataclass
class Contribution:
    signal: str
    strength: float
    evidence: float
    detail: str
    advice: str
    points: float = 0.0  # share of the final score attributable to this signal

    def as_dict(self) -> dict:
        return {"signal": self.signal, "strength": round(self.strength, 3), "points": round(self.points, 1),
                "detail": self.detail, "advice": self.advice}


@dataclass
class RiskResult:
    score: float
    contributions: list[Contribution] = field(default_factory=list)

    @property
    def total_evidence(self) -> float:
        return sum(c.evidence for c in self.contributions)

    def reasons(self, min_points: float = 1.0) -> list[dict]:
        return [c.as_dict() for c in self.contributions if c.points >= min_points]

    def reason_codes(self, min_points: float = 1.0) -> list[str]:
        return [c.signal for c in self.contributions if c.points >= min_points]


def combine(contributions: list[Contribution], extra_evidence: float = 0.0) -> RiskResult:
    """Combine signal evidence; `extra_evidence` folds in a previously cached score."""
    total = sum(c.evidence for c in contributions) + extra_evidence
    score = score_from_evidence(total)
    for c in contributions:
        c.points = score * c.evidence / total if total > 0 else 0.0
    contributions.sort(key=lambda c: c.points, reverse=True)
    return RiskResult(score=score, contributions=contributions)


# --- features ----------------------------------------------------------------

@dataclass
class AuthFeatures:
    """Behavior of one grant (tool x member x airline). None = not measured."""
    searches_last_60s: int | None = None
    effective_limit_per_min: float | None = None
    ip_changes_5m: int | None = None
    distinct_ips_60s: int | None = None
    grant_age_s: float | None = None
    tools_for_member: int | None = None
    attributable_failures_5m: int | None = None
    is_datacenter: bool | None = None


@dataclass
class UnauthFeatures:
    """Behavior of one unauthenticated client (device id if the airline sends one, else IP)."""
    searches_last_60s: int | None = None
    limit_per_min: float | None = None
    ip_changes_5m: int | None = None       # only meaningful with a device id
    airlines_10m: int | None = None
    airlines_keyed_by: str = "ip"          # 'device' or 'ip'
    is_datacenter: bool | None = None
    automation: tuple[float, str] | None = None  # (strength, detail) from header heuristics
    external_bot_score: float | None = None      # 0 = human, 1 = bot


def _add(out: list[Contribution], weights: dict[str, float], signal: str, strength: float, detail: str, advice: str):
    w = weights.get(signal, 0.0)
    if w > 0 and strength > 0:
        out.append(Contribution(signal, _clamp(strength), evidence(w, strength), detail, advice))


def _velocity_strength(count: int, limit: float) -> float:
    return (count / max(limit, 1e-9) - 1) / 2  # 0 at quota, 0.5 at 2x, ~1 at 3x


def _ip_churn_strength(changes: int, min_interval_s: int) -> float:
    if min_interval_s <= 0:
        return 0.0
    allowed = max(1.0, 300 / min_interval_s)
    return (changes / allowed - 1) / 4  # every 5s against a 60s policy -> ~1


def score_authenticated(f: AuthFeatures, p: AirlinePolicy) -> RiskResult:
    w = p.weights_authenticated
    out: list[Contribution] = []
    if f.searches_last_60s is not None and f.effective_limit_per_min:
        _add(out, w, "velocity", _velocity_strength(f.searches_last_60s, f.effective_limit_per_min),
             f"{f.searches_last_60s} searches in the last 60s against a quota of {f.effective_limit_per_min:g}/min",
             "Spread searches evenly and stay under the per-credential quota; honour Retry-After on 429s.")
    if f.ip_changes_5m is not None:
        _add(out, w, "ip_churn", _ip_churn_strength(f.ip_changes_5m, p.min_ip_rotation_interval_s),
             f"egress IP changed {f.ip_changes_5m} times in 5 min (policy: at most once per "
             f"{p.min_ip_rotation_interval_s}s)",
             f"Keep one egress IP per user session for at least {p.min_ip_rotation_interval_s}s.")
    if f.distinct_ips_60s is not None:
        m = p.max_concurrent_ips_per_credential
        _add(out, w, "ip_concurrency", (f.distinct_ips_60s - m) / (2 * m),
             f"{f.distinct_ips_60s} distinct IPs used by one credential within 60s (policy max {m})",
             "Don't fan one user's credential out across workers; one credential should come from one place.")
    if f.grant_age_s is not None and p.min_grant_age_s > 0 and f.grant_age_s < p.min_grant_age_s:
        _add(out, w, "grant_age", 0.3 * (1 - f.grant_age_s / p.min_grant_age_s),
             f"user authorization is {int(f.grant_age_s)}s old (full trust after {p.min_grant_age_s}s)",
             "New authorizations start on a reduced quota; this resolves on its own.")
    if f.tools_for_member is not None:
        m = p.max_tools_per_member
        _add(out, w, "credential_sharing", (f.tools_for_member - m) / (2 * m),
             f"this member has authorized {f.tools_for_member} different tools (policy max {m})",
             "Members authorizing many tools looks like account resale; ask users to revoke unused tools.")
    if f.attributable_failures_5m:
        _add(out, w, "verification_failures", 1 - math.exp(-f.attributable_failures_5m / 5),
             f"{f.attributable_failures_5m} replayed or out-of-scope signed requests in 5 min",
             "Use a fresh nonce per request and only search routes the user authorized.")
    if f.is_datacenter:
        _add(out, w, "vpn", 0.5, "request came from a datacenter / VPN range",
             "This airline scores datacenter egress; prefer stable egress IPs.")
    return combine(out)


_SCRIPT_UA = re.compile(r"python-requests|aiohttp|httpx|python-urllib|curl/|wget/|go-http-client|okhttp|node-fetch|"
                        r"axios/|undici|scrapy|java/|libwww|httpclient|postmanruntime", re.I)
_HEADLESS_UA = re.compile(r"headlesschrome|phantomjs|selenium|puppeteer|playwright|electron/", re.I)


def automation_strength(headers: dict[str, str], client_signals: dict) -> tuple[float, str]:
    """Header / client-side automation evidence for one request. Headers must be lowercased."""
    hits: list[tuple[float, str]] = []
    ua = headers.get("user-agent", "")
    if client_signals.get("webdriver"):
        hits.append((0.95, "navigator.webdriver is set"))
    if not ua:
        hits.append((0.8, "no User-Agent"))
    elif _SCRIPT_UA.search(ua):
        hits.append((0.9, "scripting-library User-Agent"))
    elif _HEADLESS_UA.search(ua):
        hits.append((0.9, "headless-browser User-Agent"))
    else:
        if "accept-language" not in headers:
            hits.append((0.4, "browser UA without Accept-Language"))
        if re.search(r"Chrome/(\d+)", ua) and "sec-ch-ua" not in headers and "Edg/" not in ua:
            hits.append((0.3, "Chrome UA without client hints"))
        if "accept" not in headers:
            hits.append((0.2, "no Accept header"))
    if client_signals.get("captcha") == "failed":
        hits.append((0.6, "failed the last challenge"))
    if not hits:
        return 0.0, ""
    s = 1 - math.prod(1 - h for h, _ in hits)
    return s, "; ".join(d for _, d in hits)


def score_unauthenticated(f: UnauthFeatures, p: AirlinePolicy) -> RiskResult:
    w = p.weights_unauthenticated
    out: list[Contribution] = []
    if f.automation is not None and f.automation[0] > 0:
        _add(out, w, "automation_headers", f.automation[0], f.automation[1],
             "Automated clients should register and use signed, authorized requests.")
    if f.searches_last_60s is not None and f.limit_per_min:
        _add(out, w, "velocity", _velocity_strength(f.searches_last_60s, f.limit_per_min),
             f"{f.searches_last_60s} searches in 60s (limit {f.limit_per_min:g}/min)", "Slow down.")
    if f.ip_changes_5m is not None:
        _add(out, w, "ip_churn", _ip_churn_strength(f.ip_changes_5m, p.min_ip_rotation_interval_s),
             f"same device changed IP {f.ip_changes_5m} times in 5 min", "")
    if f.airlines_10m is not None:
        s = (f.airlines_10m - 2) / 4
        if f.airlines_keyed_by == "ip":
            s *= 0.5  # shared IPs (carrier NAT, offices) make per-IP coverage much weaker evidence
        _add(out, w, "airline_coverage", s,
             f"{f.airlines_10m} airlines searched from the same {f.airlines_keyed_by} in 10 min", "")
    if f.is_datacenter:
        _add(out, w, "vpn", 0.5, "unauthenticated request from a datacenter / VPN range", "")
    if f.external_bot_score is not None:
        _add(out, w, "external_bot_score", f.external_bot_score,
             f"edge bot-management score {f.external_bot_score:.2f}", "")
    return combine(out)
