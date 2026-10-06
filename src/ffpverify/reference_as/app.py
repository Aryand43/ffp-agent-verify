"""Reference airline authorization server.

Airlines run their own OAuth server; this is the minimum one has to do so its tokens
work with ffp-agent-verify, written as a template to copy and as the AS the test
harness talks to. Storage is in-memory and the member login is a mock.

Flow (RFC 6749 authorization code + PKCE, RFC 7523 private_key_jwt, RFC 9449 dpop_jkt):
  GET  /oauth/authorize   tool sends the member here with client_id, PKCE challenge, dpop_jkt
  POST /oauth/authorize   member logs in (mock) and approves -> redirect with ?code
  POST /oauth/token       tool swaps code (or refresh token) for a 10-min access token whose
                          cnf.jkt binds it to the tool's registered signing key
"""

import hashlib
import html
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from ..crypto import b64url, jwk_thumbprint, public_jwk

ACCESS_TOKEN_TTL_S = 600
REFRESH_TOKEN_TTL_S = 30 * 24 * 3600
CODE_TTL_S = 60
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


@dataclass
class PendingCode:
    client_id: str
    redirect_uri: str
    code_challenge: str
    dpop_jkt: str
    member_id: str
    scope: str
    routes: list[str] | None
    auth_time: int
    expires: float


@dataclass
class Grant:
    client_id: str
    member_id: str
    dpop_jkt: str
    scope: str
    routes: list[str] | None
    auth_time: int
    refresh_expires: float
    revoked: bool = False


@dataclass
class ASState:
    codes: dict[str, PendingCode] = field(default_factory=dict)
    refresh: dict[str, Grant] = field(default_factory=dict)  # refresh token -> grant (rotated on use)
    seen_assertions: dict[str, float] = field(default_factory=dict)
    tool_cache: dict[str, tuple[float, dict]] = field(default_factory=dict)


def create_as_app(airline_id: str, issuer: str, signing_key: Ed25519PrivateKey, registry_url: str,
                  audience: str = "ffp-agent-verify", http: httpx.AsyncClient | None = None,
                  clock=time.time) -> FastAPI:
    app = FastAPI(title=f"Reference authorization server ({airline_id})")
    st = ASState()
    jwk = public_jwk(signing_key)
    kid = jwk_thumbprint(jwk)
    client = http or httpx.AsyncClient(timeout=5)
    token_endpoint = f"{issuer}/oauth/token"
    app.state.as_state = st

    async def tool_info(client_id: str) -> dict:
        cached = st.tool_cache.get(client_id)
        if cached and cached[0] > clock():
            return cached[1]
        r = await client.get(f"{registry_url}/v1/tools/{client_id}/jwks")
        if r.status_code != 200:
            raise HTTPException(400, "unknown client_id")
        info = r.json()
        st.tool_cache[client_id] = (clock() + 60, info)
        return info

    @app.get("/.well-known/jwks.json")
    async def jwks():
        return {"keys": [{**jwk, "kid": kid, "alg": "EdDSA", "use": "sig"}]}

    @app.get("/.well-known/oauth-authorization-server")
    async def metadata():
        return {"issuer": issuer, "authorization_endpoint": f"{issuer}/oauth/authorize",
                "token_endpoint": token_endpoint, "jwks_uri": f"{issuer}/.well-known/jwks.json",
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["EdDSA"],
                "scopes_supported": ["award:search"]}

    async def _check_authorize(client_id: str, redirect_uri: str, code_challenge_method: str, dpop_jkt: str):
        info = await tool_info(client_id)
        if info["status"] != "active" or not info["keys"]:
            raise HTTPException(400, "client is not active")
        if redirect_uri not in info["redirect_uris"]:
            raise HTTPException(400, "redirect_uri not registered for this client")
        if code_challenge_method != "S256":
            raise HTTPException(400, "PKCE S256 required")
        if dpop_jkt not in {k["kid"] for k in info["keys"]}:
            raise HTTPException(400, "dpop_jkt must be the client's registered key thumbprint")
        return info

    @app.get("/oauth/authorize", response_class=HTMLResponse)
    async def authorize_page(client_id: str, redirect_uri: str, state: str, code_challenge: str,
                             dpop_jkt: str, response_type: str = "code", code_challenge_method: str = "S256",
                             scope: str = "award:search", ffp_routes: str | None = None):
        if response_type != "code":
            raise HTTPException(400, "response_type must be code")
        info = await _check_authorize(client_id, redirect_uri, code_challenge_method, dpop_jkt)
        hidden = dict(client_id=client_id, redirect_uri=redirect_uri, state=state, code_challenge=code_challenge,
                      code_challenge_method=code_challenge_method, dpop_jkt=dpop_jkt, scope=scope,
                      ffp_routes=ffp_routes or "")
        fields = "".join(f'<input type="hidden" name="{k}" value="{html.escape(v)}">' for k, v in hidden.items())
        routes = html.escape(ffp_routes) if ffp_routes else "any route"
        return f"""<!doctype html><title>Authorize {html.escape(info['name'])}</title>
<body style="font-family:system-ui;max-width:28rem;margin:3rem auto">
<h2>{html.escape(airline_id)} loyalty: authorize a monitoring tool</h2>
<p><b>{html.escape(info['name'])}</b> wants to search award availability on your behalf
for <b>{routes}</b>. It cannot book or see your balance.</p>
<form method="post">{fields}
<label>Member number <input name="member_id" required></label><br><br>
<label>PIN (mock: any 4+ digits) <input name="pin" type="password" required></label><br><br>
<button name="decision" value="approve">Approve</button> <button name="decision" value="deny">Deny</button>
</form></body>"""

    @app.post("/oauth/authorize")
    async def authorize_submit(client_id: str = Form(), redirect_uri: str = Form(), state: str = Form(),
                               code_challenge: str = Form(), code_challenge_method: str = Form("S256"),
                               dpop_jkt: str = Form(), scope: str = Form("award:search"),
                               ffp_routes: str = Form(""), member_id: str = Form(), pin: str = Form(),
                               decision: str = Form()):
        await _check_authorize(client_id, redirect_uri, code_challenge_method, dpop_jkt)
        if decision != "approve":
            return RedirectResponse(f"{redirect_uri}?{urlencode({'error': 'access_denied', 'state': state})}", 302)
        if len(pin) < 4 or not pin.isdigit():  # mock login - replace with the real member login
            raise HTTPException(401, "login failed")
        code = secrets.token_urlsafe(24)
        routes = [r.strip().upper() for r in ffp_routes.split(",") if r.strip()] or None
        st.codes[code] = PendingCode(client_id, redirect_uri, code_challenge, dpop_jkt, member_id, scope, routes,
                                     int(clock()), clock() + CODE_TTL_S)
        return RedirectResponse(f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", 302)

    async def _authenticate_client(client_id: str, assertion_type: str, assertion: str) -> dict:
        if assertion_type != ASSERTION_TYPE:
            raise HTTPException(401, "private_key_jwt client authentication required")
        info = await tool_info(client_id)
        if info["status"] != "active":
            raise HTTPException(401, "client is not active")
        try:
            hdr = jwt.get_unverified_header(assertion)
            key = next(k for k in info["keys"] if k["kid"] == hdr.get("kid"))
            claims = jwt.decode(assertion, jwt.PyJWK(key), algorithms=["EdDSA"], audience=token_endpoint,
                                issuer=client_id, options={"require": ["exp", "jti", "sub"], "verify_exp": False,
                                                           "verify_iat": False})
        except (StopIteration, jwt.PyJWTError) as e:
            raise HTTPException(401, f"client assertion invalid: {e}") from None
        if claims["sub"] != client_id or not (clock() <= claims["exp"] <= clock() + 300):
            raise HTTPException(401, "client assertion sub/exp invalid")
        if claims["jti"] in st.seen_assertions:
            raise HTTPException(401, "client assertion replayed")
        st.seen_assertions[claims["jti"]] = claims["exp"]
        return info

    def _issue(g: Grant) -> dict:
        now = int(clock())
        claims = {"iss": issuer, "aud": audience, "sub": f"{airline_id}-member-{g.member_id}",
                  "client_id": g.client_id, "scope": g.scope, "cnf": {"jkt": g.dpop_jkt},
                  "iat": now, "exp": now + ACCESS_TOKEN_TTL_S, "jti": secrets.token_urlsafe(16),
                  "auth_time": g.auth_time}
        if g.routes:
            claims["ffp_routes"] = g.routes
        access = jwt.encode(claims, signing_key, algorithm="EdDSA", headers={"kid": kid, "typ": "at+jwt"})
        refresh = secrets.token_urlsafe(32)
        g.refresh_expires = clock() + REFRESH_TOKEN_TTL_S
        st.refresh[refresh] = g
        return {"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_TTL_S,
                "refresh_token": refresh, "scope": g.scope}

    @app.post("/oauth/token")
    async def token(grant_type: str = Form(), client_id: str = Form(), client_assertion_type: str = Form(""),
                    client_assertion: str = Form(""), code: str = Form(""), code_verifier: str = Form(""),
                    redirect_uri: str = Form(""), refresh_token: str = Form("")):
        await _authenticate_client(client_id, client_assertion_type, client_assertion)
        if grant_type == "authorization_code":
            pc = st.codes.pop(code, None)
            if pc is None or pc.expires < clock() or pc.client_id != client_id or pc.redirect_uri != redirect_uri:
                raise HTTPException(400, "invalid_grant")
            if b64url(hashlib.sha256(code_verifier.encode()).digest()) != pc.code_challenge:
                raise HTTPException(400, "invalid_grant: PKCE verifier mismatch")
            g = Grant(client_id, pc.member_id, pc.dpop_jkt, pc.scope, pc.routes, pc.auth_time, 0)
            return _issue(g)
        if grant_type == "refresh_token":
            g = st.refresh.pop(refresh_token, None)  # rotation: each refresh token works once
            if g is None or g.revoked or g.refresh_expires < clock() or g.client_id != client_id:
                raise HTTPException(400, "invalid_grant")
            return _issue(g)
        raise HTTPException(400, "unsupported_grant_type")

    return app
