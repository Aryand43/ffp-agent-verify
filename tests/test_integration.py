"""End-to-end: tool registration -> member OAuth at the airline -> signed searches -> verify."""

import pytest

from ffpverify.crypto import generate_private_key, jwk_thumbprint, public_jwk
from ffpverify.sdk.tool import ToolClient

pytestmark = pytest.mark.integration

TOOL_IP = "104.131.20.7"  # DigitalOcean: tools often run in the cloud


async def tool_with_grant(env, name="SeatWatch", airline="AC", member="100200300", routes=None, age_s=7200):
    tool = await env.register_tool(name)
    tokens = await env.authorize(tool, airline, member, routes)
    env.clock.advance(age_s)  # let the grant age past min_grant_age_s
    tokens = await env.fresh_tokens(tool, airline, member)
    return tool, tokens


async def test_authorized_search_allowed(env):
    tool, tokens = await tool_with_grant(env, age_s=0)  # over HTTP the verifier uses the real clock
    r = await env.verify_http(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "allow" and body["lane"] == "authenticated"
    assert body["tool_id"] == tool.client.tool_id
    assert body["latency_us"] < 50_000


async def test_replay_blocked(env):
    tool, tokens = await tool_with_grant(env)
    req = env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP)
    assert (await env.verify(req, "AC")).decision == "allow"
    replay = await env.verify(req.model_copy(update={"client_ip": "5.9.1.1"}), "AC")
    assert replay.decision == "block" and replay.reasons[0].signal == "replay"


async def test_stolen_token_with_other_key(env):
    victim, tokens = await tool_with_grant(env, "Victim")
    thief = await env.register_tool("Thief")
    r = await env.verify(env.tool_request(thief, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "block" and r.reasons[0].signal == "key_mismatch"


async def test_unregistered_key(env):
    _, tokens = await tool_with_grant(env)
    rogue = ToolClient("tool_rogue", generate_private_key(), env.http, clock=env.clock)
    from sim.harness import ToolEnv
    r = await env.verify(env.tool_request(ToolEnv(rogue, "Rogue", "", ""), tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "block" and r.reasons[0].signal == "unknown_key"


async def test_forged_signatures_cannot_frame_a_tool(env):
    """Anyone can put a victim's public keyid on garbage; that must not hurt the victim's score."""
    victim, tokens = await tool_with_grant(env, "Victim")
    for i in range(50):
        req = env.tool_request(victim, tokens, "AC", "YVR", "NRT", f"5.9.0.{i}")
        h = dict(req.request.headers)
        h["Signature"] = "sig1=:" + "A" * 86 + "==:"
        r = await env.verify(req.model_copy(update={"request": req.request.model_copy(update={"headers": h})}), "AC")
        assert r.decision == "block" and r.reasons[0].signal == "bad_signature"
    await env.tick()
    ok = await env.verify(env.tool_request(victim, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert ok.decision == "allow" and ok.score == 0


async def test_route_scoped_credential(env):
    tool, tokens = await tool_with_grant(env, routes=["YVR-NRT", "YVR-HND"])
    assert (await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "HND", TOOL_IP), "AC")).decision == "allow"
    r = await env.verify(env.tool_request(tool, tokens, "AC", "YYZ", "LHR", TOOL_IP), "AC")
    assert r.decision == "block" and r.reasons[0].signal == "route_not_authorized"


async def test_credentials_are_airline_specific(env):
    tool, tokens = await tool_with_grant(env, airline="AC")
    r = await env.verify(env.tool_request(tool, tokens, "SQ", "SIN", "NRT", TOOL_IP), "SQ")
    assert r.decision == "block" and r.reasons[0].signal in {"bad_issuer", "bad_token", "unknown_kid"}


async def test_expired_token(env):
    tool, tokens = await tool_with_grant(env)
    env.clock.advance(601 + 30)
    r = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "block" and r.reasons[0].signal == "token_expired"
    tokens = await env.fresh_tokens(tool, "AC", "100200300")  # refresh-token rotation at the AS
    assert (await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")).decision == "allow"


async def test_rate_limit_throttles_with_retry_after(env):
    tool, tokens = await tool_with_grant(env)
    decisions = []
    for _ in range(20):  # 20 in the same instant vs. a 30/min quota with ~8 burst
        decisions.append(await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC"))
    allowed = sum(d.decision == "allow" for d in decisions)
    assert 6 <= allowed <= 9
    throttled = [d for d in decisions if d.decision == "throttle"]
    assert throttled and throttled[0].retry_after_s >= 1
    assert throttled[0].reasons[0].signal == "rate_credential"
    env.clock.advance(throttled[0].retry_after_s)
    assert (await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")).decision == "allow"


async def test_new_grant_gets_reduced_quota(env):
    tool = await env.register_tool("Fresh")
    tokens = await env.authorize(tool, "AC", "555")
    allowed = 0
    for _ in range(20):
        allowed += (await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")).decision == "allow"
    assert allowed <= 4  # half quota while the grant is younger than min_grant_age_s


async def test_policy_changes_apply_immediately(env):
    tool, tokens = await tool_with_grant(env)
    out = await env.patch_policy("AC", {"authorized_agents_allowed": False})
    assert out["version"] == 2
    r = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "block" and r.reasons[0].signal == "agents_not_permitted" and r.policy_version == 2

    await env.patch_policy("AC", {"authorized_agents_allowed": True, "vpn_tolerance": "block"})
    r = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "block" and r.reasons[0].signal == "vpn_not_permitted"
    r = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", "24.80.1.1"), "AC")
    assert r.decision == "allow"


async def test_policy_validation_rejected(env):
    r = await env.http.patch(f"{env.verify_url}/v1/airlines/AC/policy",
                             json={"thresholds": {"challenge": 95}}, headers={"X-Api-Key": env.airlines["AC"].api_key})
    assert r.status_code == 422
    r = await env.http.patch(f"{env.verify_url}/v1/airlines/AC/policy", json={"fail_mode": "closed"},
                             headers={"X-Api-Key": env.airlines["SQ"].api_key})
    assert r.status_code == 401  # one airline cannot edit another's policy


async def test_tool_revocation(env):
    tool, tokens = await tool_with_grant(env)
    r = await env.http.post(f"{env.verify_url}/v1/tools/{tool.client.tool_id}/revoke", json={"reason": "key leaked"},
                            headers={"X-Tool-Token": tool.management_token})
    assert r.status_code == 200
    r = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "block" and r.reasons[0].signal == "tool_revoked"
    jwks = (await env.http.get(f"{env.verify_url}/v1/tools/{tool.client.tool_id}/jwks")).json()
    assert jwks["keys"] == [] and jwks["status"] == "revoked"


async def test_credential_fanout_detected_and_auto_revoked(env):
    """One member's credential driven from many IPs in parallel (resale / abuse)."""
    tool, tokens = await tool_with_grant(env, "Reseller")
    first_block = None
    for second in range(120):
        for w in range(4):  # 4 workers, each on its own IP, rotating every ~5s
            ip = f"185.156.172.{(second // 5 * 4 + w) % 250}"
            r = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", ip), "AC")
            if r.decision == "block" and first_block is None:
                first_block = second
        env.clock.advance(1)
        if second % 2 == 1:
            await env.tick()
    assert first_block is not None and first_block < 60
    r = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "block"
    status = await env.state.pool.fetchval("SELECT status FROM grants WHERE tool_id = $1", tool.client.tool_id)
    assert status == "revoked"
    assert r.reasons[0].signal == "grant_revoked" and "auto-revoked" in r.reasons[0].detail


async def test_well_behaved_tool_stays_clean_over_time(env):
    tool, tokens = await tool_with_grant(env)
    routes = [("YVR", "NRT"), ("YVR", "HND"), ("SEA", "SIN")]
    decisions = []
    for minute in range(30):
        ip = f"104.131.30.{minute // 5}"  # rotate every 5 minutes
        tokens = await env.fresh_tokens(tool, "AC", "100200300")
        for i in range(15):  # 15/min against a 30/min quota
            o, d = routes[i % 3]
            decisions.append((await env.verify(env.tool_request(tool, tokens, "AC", o, d, ip), "AC")).decision)
            env.clock.advance(4)
        await env.tick()
    assert set(decisions) == {"allow"}


async def test_unauthenticated_lane(env):
    human = await env.verify(env.browser_request("AC", "YVR", "NRT", "24.80.1.1", device_id="d1"), "AC")
    assert human.decision == "allow" and human.lane == "unauthenticated"
    script = await env.verify(env.browser_request("AC", "YVR", "NRT", "24.80.1.2",
                                                  headers={"User-Agent": "python-requests/2.32"}), "AC")
    assert script.decision == "block"
    headless = await env.verify(env.browser_request("AC", "YVR", "NRT", "24.80.1.3", webdriver=True), "AC")
    assert headless.decision in ("block", "throttle")
    vpn_human = await env.verify(env.browser_request("AC", "YVR", "NRT", "198.51.100.7", device_id="d2"), "AC")
    assert vpn_human.decision == "challenge"  # humans use VPNs too: challenge, don't block


async def test_unsigned_bearer_rejected(env):
    _, tokens = await tool_with_grant(env)
    req = env.browser_request("AC", "YVR", "NRT", TOOL_IP, headers={"Authorization": f"Bearer {tokens.access_token}"})
    r = await env.verify(req, "AC")
    assert r.decision == "block" and r.reasons[0].signal == "missing_signature"


async def test_fail_open_and_closed(env):
    tool, tokens = await tool_with_grant(env)

    async def broken(*a, **kw):
        raise ConnectionError("redis down")

    env.state.verifier._auth_script = broken
    r = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "allow" and r.degraded
    await env.patch_policy("AC", {"fail_mode": "closed"})
    r = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "block" and r.degraded
    # Request-local heuristics don't need Redis either.
    env.state.verifier._unauth_script = broken
    await env.patch_policy("AC", {"fail_mode": "open"})
    r = await env.verify(env.browser_request("AC", "YVR", "NRT", "24.80.1.9",
                                             headers={"User-Agent": "python-requests/2.32"}), "AC")
    assert r.decision == "block" and r.degraded
    r = await env.verify(env.browser_request("AC", "YVR", "NRT", "24.80.1.9"), "AC")
    assert r.decision == "allow" and r.degraded
    # Crypto failures don't need Redis and still block in fail-open mode.
    await env.patch_policy("AC", {"fail_mode": "open"})
    thief = await env.register_tool("Thief")
    r = await env.verify(env.tool_request(thief, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    assert r.decision == "block" and not r.degraded


async def test_analytics_and_feedback(env):
    tool, tokens = await tool_with_grant(env)
    for _ in range(12):
        resp = await env.verify(env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP), "AC")
    await env.tick()
    r = await env.http.get(f"{env.verify_url}/v1/tools/{tool.client.tool_id}/analytics?hours=48",
                           headers={"X-Tool-Token": tool.management_token})
    assert r.status_code == 200, r.text
    a = r.json()
    assert {d["decision"] for d in a["decisions"]} >= {"allow", "throttle"}
    assert a["airline_quotas"]["AC"]["max_searches_per_min_per_credential"] == 30
    assert any(x["r"] == "rate_credential" for x in a["top_reasons"])
    r = await env.http.get(f"{env.verify_url}/v1/tools/{tool.client.tool_id}/analytics",
                           headers={"X-Tool-Token": "wrong"})
    assert r.status_code == 401

    r = await env.http.post(f"{env.verify_url}/v1/feedback", headers={"X-Api-Key": env.airlines["AC"].api_key},
                            json={"label": "false_positive", "request_id": resp.request_id, "notes": "legit tool"})
    assert r.status_code == 201


async def test_registration_requires_proof_of_possession(env):
    key, other = generate_private_key(), generate_private_key()
    import base64, time
    jwk = public_jwk(key)
    ts = int(time.time())
    bad_proof = base64.b64encode(other.sign(f"ffpv-register:{jwk_thumbprint(jwk)}:{ts}".encode())).decode()
    r = await env.http.post(f"{env.verify_url}/v1/tools/register", json={
        "name": "Squatter", "developer_contact": "x@y.z", "public_jwk": jwk, "proof": bad_proof, "proof_ts": ts})
    assert r.status_code == 422


async def test_reference_as_enforces_key_binding(env):
    tool = await env.register_tool("Binder")
    a = env.airlines["AC"]
    url, _, _ = tool.client.authorization_url(a.issuer, tool.redirect_uri)
    r = await env.http.get(url.replace(tool.client.jkt, "someone-elses-thumbprint"))
    assert r.status_code == 400 and "dpop_jkt" in r.text
    r = await env.http.get(url.replace("callback", "evil"))
    assert r.status_code == 400 and "redirect_uri" in r.text
