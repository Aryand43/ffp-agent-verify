import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from ffpverify.crypto import generate_private_key, jwk_thumbprint, public_jwk
from ffpverify.tokens import TokenError, TokenVerifier

NOW = 1_790_000_000
ISS = "https://auth.ac.example"


@pytest.fixture
def as_key():
    return generate_private_key()


@pytest.fixture
def verifier(as_key):
    v = TokenVerifier("ffp-agent-verify", skew_s=30, max_lifetime_s=900)
    v.set_airline_keys("AC", ISS, {"keys": [{**public_jwk(as_key), "kid": "k1"}]})
    return v


def mint(key, kid="k1", alg="EdDSA", **over):
    claims = {"iss": ISS, "aud": "ffp-agent-verify", "sub": "AC-member-1", "client_id": "tool_x",
              "scope": "award:search", "cnf": {"jkt": "thumb"}, "iat": NOW, "exp": NOW + 600, "jti": "j1",
              "auth_time": NOW - 7200}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def code(verifier, token, airline="AC", now=NOW):
    with pytest.raises(TokenError) as e:
        verifier.verify(token, airline, now)
    return e.value.code


def test_valid(verifier, as_key):
    at = verifier.verify(mint(as_key, ffp_routes=["yvr-nrt"]), "AC", NOW + 10)
    assert at.tool_id == "tool_x" and at.jkt == "thumb" and at.auth_time == NOW - 7200
    assert at.routes == {"YVR-NRT"}
    assert len(at.grant_id) == 32 and at.member_ref != "AC-member-1"


def test_expiry_checked_even_when_cached(verifier, as_key):
    t = mint(as_key)
    verifier.verify(t, "AC", NOW)
    assert code(verifier, t, now=NOW + 600 + 31) == "token_expired"


def test_claims(verifier, as_key):
    assert code(verifier, mint(as_key, aud="someone-else")) == "bad_audience"
    assert code(verifier, mint(as_key, iss="https://evil.example")) == "bad_issuer"
    assert code(verifier, mint(as_key, scope="profile")) == "insufficient_scope"
    assert code(verifier, mint(as_key, cnf=None)) == "unbound_token"
    assert code(verifier, mint(as_key, exp=NOW + 3600)) == "token_lifetime_too_long"
    assert code(verifier, mint(as_key, iat=NOW + 120, exp=NOW + 700)) == "token_not_yet_valid"
    assert code(verifier, mint(as_key, jti=None)) == "bad_token"


def test_credentials_are_airline_specific(verifier, as_key):
    verifier.set_airline_keys("SQ", "https://auth.sq.example", {"keys": [public_jwk(generate_private_key())]})
    t = mint(as_key)
    verifier.verify(t, "AC", NOW)
    assert code(verifier, t, airline="SQ") == "wrong_airline"


def test_forged_or_confused_tokens(verifier, as_key):
    assert code(verifier, mint(generate_private_key())) == "bad_token"   # wrong signing key
    assert code(verifier, mint(as_key, kid="unknown")) == "unknown_kid"
    assert code(verifier, "not.a.jwt") == "malformed_token"
    # alg confusion: HS256 keyed with the public key bytes must never verify
    pub_x = public_jwk(as_key)["x"].encode()
    assert code(verifier, jwt.encode({"iss": ISS}, pub_x, algorithm="HS256", headers={"kid": "k1"})) == "bad_token_alg"
    unsigned = jwt.encode({"iss": ISS}, None, algorithm="none")
    assert code(verifier, unsigned) == "bad_token_alg"


def test_es256_supported():
    k = ec.generate_private_key(ec.SECP256R1())
    v = TokenVerifier("ffp-agent-verify", 30, 900)
    v.set_airline_keys("QF", ISS, {"keys": [{**jwt.algorithms.ECAlgorithm.to_jwk(k.public_key(), as_dict=True),
                                             "kid": "e1"}]})
    assert v.verify(mint(k, kid="e1", alg="ES256"), "QF", NOW).tool_id == "tool_x"


def test_unchanged_keys_keep_cache(verifier, as_key):
    t = mint(as_key)
    verifier.verify(t, "AC", NOW)
    verifier.set_airline_keys("AC", ISS, {"keys": [{**public_jwk(as_key), "kid": "k1"}]})
    assert len(verifier._cache) == 1


def test_jwk_thumbprint_is_rfc7638():
    # RFC 8037 Appendix A.3 test vector
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    assert jwk_thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
