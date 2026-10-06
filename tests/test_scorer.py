import pytest
from pydantic import ValidationError

from ffpverify.models import Decision, Lane
from ffpverify.policy import AirlinePolicy
from ffpverify.risk.scorer import (AuthFeatures, UnauthFeatures, automation_strength, score_authenticated,
                                   score_unauthenticated)
from ffpverify.verify import decide

P = AirlinePolicy()
CHROME = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/129.0.0.0 Safari/537.36")


def well_behaved_tool(**over) -> AuthFeatures:
    f = dict(searches_last_60s=20, effective_limit_per_min=30, ip_changes_5m=1, distinct_ips_60s=1,
             grant_age_s=86400, tools_for_member=1, attributable_failures_5m=0, is_datacenter=True)
    f.update(over)
    return AuthFeatures(**f)


def test_well_behaved_tool_scores_zero():
    """24/7, datacenter egress, many airlines: none of that is penalized for an authorized tool."""
    r = score_authenticated(well_behaved_tool(), P)
    assert r.score == 0 and decide(r.score, Lane.authenticated, P.thresholds) is Decision.allow


def test_rotation_within_policy_is_fine():
    # rotating every 60s = 5 changes / 5 min = exactly the policy
    assert score_authenticated(well_behaved_tool(ip_changes_5m=5, distinct_ips_60s=2), P).score == 0


def test_fast_rotation_blocks():
    # every ~5s, as an adversarial bot does
    r = score_authenticated(well_behaved_tool(ip_changes_5m=60, distinct_ips_60s=12), P)
    assert decide(r.score, Lane.authenticated, P.thresholds) is Decision.block
    assert r.contributions[0].signal in {"ip_churn", "ip_concurrency"}
    assert r.contributions[0].advice


def test_one_strong_signal_is_enough():
    r = score_authenticated(well_behaved_tool(searches_last_60s=120), P)  # 4x quota
    assert r.score >= P.thresholds.block


def test_weak_signals_compound():
    alone = [score_authenticated(well_behaved_tool(**kw), P).score for kw in
             ({"searches_last_60s": 36}, {"ip_changes_5m": 7}, {"tools_for_member": 4})]
    together = score_authenticated(well_behaved_tool(searches_last_60s=36, ip_changes_5m=7, tools_for_member=4), P)
    assert all(a < P.thresholds.challenge for a in alone)
    assert together.score >= P.thresholds.challenge > max(alone)
    assert abs(sum(c.points for c in together.contributions) - together.score) < 1e-6


def test_new_grant_is_mild_on_its_own():
    r = score_authenticated(well_behaved_tool(grant_age_s=0), P)
    assert 0 < r.score < P.thresholds.challenge


def test_monotonic_in_velocity():
    scores = [score_authenticated(well_behaved_tool(searches_last_60s=n), P).score for n in range(0, 200, 10)]
    assert scores == sorted(scores)


def test_zero_weight_disables_signal():
    p = AirlinePolicy(weights_authenticated={"velocity": 0})
    assert score_authenticated(well_behaved_tool(searches_last_60s=500), p).score == 0


def test_vpn_weight_is_airline_choice():
    p = AirlinePolicy(weights_authenticated={**P.weights_authenticated, "vpn": 1})
    assert score_authenticated(well_behaved_tool(), p).score > 0


@pytest.mark.parametrize("ua,headers,expect_high", [
    (CHROME, {"accept-language": "en-CA", "accept": "text/html", "sec-ch-ua": '"Chromium";v="129"'}, False),
    ("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15",
     {"accept-language": "en", "accept": "*/*"}, False),
    ("python-requests/2.32.3", {}, True),
    ("Mozilla/5.0 HeadlessChrome/129.0", {"accept-language": "en"}, True),
    ("", {}, True),
])
def test_automation_headers(ua, headers, expect_high):
    s, detail = automation_strength({"user-agent": ua, **headers} if ua else headers, {})
    assert (s >= 0.8) is expect_high, detail


def test_webdriver_flag():
    s, d = automation_strength({"user-agent": CHROME, "accept-language": "en", "accept": "*/*", "sec-ch-ua": "x"},
                               {"webdriver": True})
    assert s >= 0.95 and "webdriver" in d


def test_unauth_coverage_weaker_per_ip_than_per_device():
    dev = score_unauthenticated(UnauthFeatures(airlines_10m=6, airlines_keyed_by="device"), P).score
    ip = score_unauthenticated(UnauthFeatures(airlines_10m=6, airlines_keyed_by="ip"), P).score
    assert dev > ip > 0


def test_human_browsing_two_airlines_is_clean():
    r = score_unauthenticated(UnauthFeatures(searches_last_60s=3, limit_per_min=20, airlines_10m=2), P)
    assert r.score == 0


def test_policy_validation():
    with pytest.raises(ValidationError):
        AirlinePolicy(thresholds={"challenge": 90, "throttle": 60, "block": 80, "revoke": 95})
    with pytest.raises(ValidationError):
        AirlinePolicy(weights_authenticated={"booking_ratio": 1})
    with pytest.raises(ValidationError):
        AirlinePolicy(max_searches_per_min_per_credential=0)
    assert AirlinePolicy(vpn_tolerance="block").vpn_tolerance.value == "block"
