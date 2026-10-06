from ffpverify.policy import AirlinePolicy
from ffpverify.risk import pillars
from ffpverify.risk.pillars import Pillar, pillar_of
from ffpverify.risk.scorer import AuthFeatures, score_authenticated
from ffpverify.verify import ATTRIBUTABLE, BLOCK_MESSAGES

P = AirlinePolicy()


def test_every_scored_signal_has_a_pillar():
    signals = set(P.weights_authenticated) | set(P.weights_unauthenticated) | set(BLOCK_MESSAGES) | ATTRIBUTABLE
    assert signals <= set(pillars.SIGNAL_PILLAR)


def test_unknown_codes_fall_back_to_safety_and_degraded_has_none():
    assert pillar_of("bad_signature") is Pillar.safety
    assert pillar_of("degraded") is None


def test_breakdown_sums_to_score_and_follows_signals():
    r = score_authenticated(AuthFeatures(searches_last_60s=90, effective_limit_per_min=30,
                                         tools_for_member=6, grant_age_s=0), P)
    b = pillars.breakdown(r.score, [(r.total_evidence, r.reasons())])
    assert abs(sum(b.values()) - r.score) < 0.5
    assert b["verifiability"] > b["trust"] > 0 and b["safety"] == 0


def test_breakdown_weights_groups_by_evidence():
    # a cached grant score (verifiability-heavy) plus fresh trust evidence
    cached = [{"signal": "velocity", "points": 60.0}]
    b = pillars.breakdown(70.0, [pillars.from_cached("60", cached), (0.1, [{"signal": "vpn", "points": 3.0}])])
    assert b["verifiability"] > 60 and 0 < b["trust"] < 10 and abs(sum(b.values()) - 70) < 0.2


def test_hard_block_lands_on_one_pillar():
    assert pillars.hard_block("route_not_authorized") == {"safety": 0.0, "trust": 0.0, "verifiability": 100.0}
    assert pillars.hard_block("replay")["safety"] == 100.0
