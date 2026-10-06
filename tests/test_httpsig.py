import base64
import time

import pytest

from ffpverify import httpsig
from ffpverify.crypto import generate_private_key, jwk_thumbprint, public_jwk

URL = "https://api.airline.example/award/search?from=YVR&to=NRT&date=2026-12-01"
NOW = 1_790_000_000


@pytest.fixture
def key():
    return generate_private_key()


def signed(key, method="GET", url=URL, headers=None, created=NOW, **kw):
    headers = {"Authorization": "Bearer tok", "Accept": "application/json", **(headers or {})}
    keyid = jwk_thumbprint(public_jwk(key))
    headers.update(httpsig.sign_request(key, keyid, method, url, headers, created=created,
                                        nonce="n" * 22, **kw))
    return headers


def verify(key, headers, method="GET", url=URL, now=NOW, body=None, max_age_s=60):
    lower = {k.lower(): v for k, v in headers.items()}
    params = httpsig.parse_signature_input(lower["signature-input"])
    sig = httpsig.parse_signature(lower["signature"], params.label)
    httpsig.verify_request(key.public_key(), params, sig, method, url, headers, now=now, skew_s=5,
                           max_age_s=max_age_s, body=body)
    return params


def test_roundtrip(key):
    p = verify(key, signed(key))
    assert p.keyid == jwk_thumbprint(public_jwk(key))
    assert p.tag == httpsig.SIGNATURE_TAG
    assert p.components == httpsig.DEFAULT_COMPONENTS


def test_header_names_are_case_insensitive(key):
    h = {k.lower(): v for k, v in signed(key).items()}
    verify(key, h)


@pytest.mark.parametrize("mutate", [
    lambda h: ("POST", URL, h),
    lambda h: ("GET", URL.replace("NRT", "HND"), h),                        # different route
    lambda h: ("GET", URL.replace("api.airline", "api.other-airline"), h),  # different airline host
    lambda h: ("GET", URL.replace("/award/search", "/award/book"), h),
    lambda h: ("GET", URL, {**h, "Authorization": "Bearer stolen"}),        # token swapped
])
def test_any_covered_change_breaks_signature(key, mutate):
    method, url, headers = mutate(signed(key))
    with pytest.raises(httpsig.SignatureError) as e:
        verify(key, headers, method=method, url=url)
    assert e.value.code == "bad_signature"


def test_uncovered_header_may_change(key):
    h = signed(key)
    h["Accept"] = "text/html"
    verify(key, h)


def test_wrong_key(key):
    with pytest.raises(httpsig.SignatureError, match="verification failed"):
        verify(generate_private_key(), signed(key))


def test_expired_and_future(key):
    with pytest.raises(httpsig.SignatureError) as e:
        verify(key, signed(key, created=NOW - 120))
    assert e.value.code == "signature_expired"
    with pytest.raises(httpsig.SignatureError) as e:
        verify(key, signed(key, created=NOW + 60))
    assert e.value.code == "signature_from_future"
    with pytest.raises(httpsig.SignatureError) as e:  # its own `expires` passed even though max_age allows it
        verify(key, signed(key, created=NOW - 40, ttl_s=10))
    assert e.value.code == "signature_expired"


def test_insufficient_coverage_rejected(key):
    h = signed(key, components=("@method", "@path"))
    with pytest.raises(httpsig.SignatureError) as e:
        verify(key, h)
    assert e.value.code == "insufficient_coverage"


def test_target_uri_satisfies_coverage(key):
    verify(key, signed(key, components=("@method", "@target-uri", "authorization")))


def test_content_digest(key):
    body = b'{"from":"YVR","to":"NRT"}'
    h = signed(key, "POST", headers={"Content-Digest": httpsig.content_digest(body)},
               components=httpsig.DEFAULT_COMPONENTS + ("content-digest",))
    verify(key, h, method="POST", body=body)
    with pytest.raises(httpsig.SignatureError) as e:
        verify(key, h, method="POST", body=b'{"from":"YVR","to":"HND"}')
    assert e.value.code == "digest_mismatch"


def test_multiple_signatures_picks_ours(key):
    h = signed(key)
    other_input = 'cdn=("@authority");created=1;keyid="cdn-key";alg="ed25519";tag="web-bot-auth"'
    h["Signature-Input"] = other_input + ", " + h["Signature-Input"]
    h["Signature"] = "cdn=:" + base64.b64encode(b"x" * 64).decode() + ":, " + h["Signature"]
    assert verify(key, h).label == "sig1"


def test_malformed_inputs(key):
    for bad in ["", "sig1=", 'sig1=("@method");keyid="k"', "sig1=@method;created=1"]:
        with pytest.raises(httpsig.SignatureError):
            httpsig.parse_signature_input(bad)
    with pytest.raises(httpsig.SignatureError):
        httpsig.parse_signature("sig1=:not base64!!:", "sig1")


def test_signing_overhead_under_budget(key):
    """Spec: <10ms signing overhead. Ed25519 should be ~100x under that."""
    h = signed(key)
    n = 500
    t0 = time.perf_counter()
    for _ in range(n):
        signed(key)
    sign_ms = (time.perf_counter() - t0) / n * 1000
    t0 = time.perf_counter()
    for _ in range(n):
        verify(key, h)
    verify_ms = (time.perf_counter() - t0) / n * 1000
    assert sign_ms < 1 and verify_ms < 1, (sign_ms, verify_ms)
