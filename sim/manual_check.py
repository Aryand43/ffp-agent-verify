"""A few hand-checkable cases, printed in full, to sense-check the simulator's accuracy numbers.

    uv run python -m sim.manual_check

Each case shows the request that reached the verifier and the full decision, so you can confirm by eye that
the decision matches what should happen and why. Uses the test database (ffpv_test), not the dev one.
"""

import asyncio
import json

from .harness import SimClock, environment

TOOL_IP = "104.131.20.7"


def show(title: str, expected: str, req, resp) -> bool:
    ok = resp.decision.value == expected
    print(f"\n=== {title} ===")
    print(f"client_ip: {req.client_ip}   url: {req.request.url}")
    print("headers:", json.dumps({k: (v[:60] + "…" if len(v) > 60 else v) for k, v in req.request.headers.items()},
                                 indent=2))
    print(f"decision: {resp.decision.value} (expected {expected})  score: {resp.score}  pillars: {resp.pillars}")
    for r in resp.reasons:
        print(f"  - [{r.pillar}] {r.signal}: {r.detail}")
    print("PASS" if ok else "FAIL")
    return ok


async def main():
    async with environment(airlines=("AC",), clock=SimClock()) as env:
        tool = await env.register_tool("SeatWatch")
        tokens = await env.authorize(tool, "AC", "100200300")
        env.clock.advance(7200)  # past the new-authorization period
        tokens = await env.fresh_tokens(tool, "AC", "100200300")

        results = []
        legit = env.tool_request(tool, tokens, "AC", "YVR", "NRT", TOOL_IP)
        results.append(show("1. Authorized tool, normal search", "allow", legit, await env.verify(legit, "AC")))

        replay = legit.model_copy(update={"client_ip": "5.9.1.1"})
        results.append(show("2. Same signed request replayed from another IP", "block", replay,
                            await env.verify(replay, "AC")))

        scraper = env.browser_request("AC", "YVR", "LHR", "66.1.2.3",
                                      headers={"User-Agent": "python-requests/2.32.3"})
        results.append(show("3. Credential-less scraper", "block", scraper, await env.verify(scraper, "AC")))

        human = env.browser_request("AC", "YYZ", "LHR", "72.14.9.20", device_id="dev-123")
        results.append(show("4. Human in a normal browser", "allow", human, await env.verify(human, "AC")))

        print(f"\n{sum(results)}/{len(results)} cases as expected")


if __name__ == "__main__":
    asyncio.run(main())
