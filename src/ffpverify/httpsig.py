"""Minimal RFC 9421 HTTP Message Signatures (Ed25519 only).

Implements the subset that Web Bot Auth uses: derived components @method, @authority,
@path, @query, @target-uri, plain header fields, and the signature parameters
created / expires / nonce / keyid / alg / tag. Both the tool-side signer and the
verifier build the signature base with the same function, so they cannot drift.
"""

import base64
import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_TAG = "ffp-agent-verify"
DEFAULT_COMPONENTS = ("@method", "@authority", "@path", "@query", "authorization")
# The verifier refuses signatures that don't cover at least these: they bind the
# signature to this exact search and to this exact bearer token.
REQUIRED_COMPONENTS = frozenset({"@method", "@authority", "@path", "@query", "authorization"})


class SignatureError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SignatureParams:
    label: str
    components: tuple[str, ...]
    created: int
    expires: int | None
    nonce: str
    keyid: str
    alg: str
    tag: str
    raw: str  # serialized inner list + params, reused verbatim in the signature base


def _authority(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and not ((parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)):
        return f"{host}:{port}"
    return host


def _component_value(name: str, method: str, url: str, headers: dict[str, str]) -> str:
    parts = urlsplit(url)
    if name == "@method":
        return method.upper()
    if name == "@authority":
        return _authority(url)
    if name == "@path":
        return parts.path or "/"
    if name == "@query":
        return f"?{parts.query}"
    if name == "@target-uri":
        return url
    if name.startswith("@"):
        raise SignatureError("unsupported_component", f"unsupported derived component {name}")
    value = headers.get(name)
    if value is None:
        raise SignatureError("missing_component", f"covered header '{name}' not present")
    return value.strip()


def serialize_params(components: tuple[str, ...], created: int, expires: int | None, nonce: str, keyid: str,
                     alg: str = "ed25519", tag: str = SIGNATURE_TAG) -> str:
    inner = "(" + " ".join(f'"{c}"' for c in components) + ")"
    params = f";created={created}"
    if expires is not None:
        params += f";expires={expires}"
    params += f';nonce="{nonce}";keyid="{keyid}";alg="{alg}";tag="{tag}"'
    return inner + params


def signature_base(method: str, url: str, headers: dict[str, str], components: tuple[str, ...],
                   params_raw: str) -> bytes:
    lower = {k.lower(): v for k, v in headers.items()}
    lines = [f'"{c}": {_component_value(c, method, url, lower)}' for c in components]
    lines.append(f'"@signature-params": {params_raw}')
    return "\n".join(lines).encode()


def content_digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def sign_request(key: Ed25519PrivateKey, keyid: str, method: str, url: str, headers: dict[str, str], *,
                 created: int, nonce: str, ttl_s: int = 30, components: tuple[str, ...] = DEFAULT_COMPONENTS,
                 label: str = "sig1") -> dict[str, str]:
    """Returns the Signature-Input and Signature headers to add to the request."""
    params_raw = serialize_params(components, created, created + ttl_s, nonce, keyid)
    base = signature_base(method, url, headers, components, params_raw)
    sig = base64.b64encode(key.sign(base)).decode()
    return {"Signature-Input": f"{label}={params_raw}", "Signature": f"{label}=:{sig}:"}


# --- parsing -----------------------------------------------------------------

_PARAM_RE = re.compile(r';\s*([a-z][a-z0-9_.*-]*)=("(?:[^"\\]|\\.)*"|-?\d+)')
_INNER_RE = re.compile(r'^\(\s*((?:"[^"]*"\s*)*)\)')


def _split_dict_members(value: str) -> dict[str, str]:
    """Split a structured-field dictionary on top-level commas (quotes respected)."""
    if "," not in value:  # fast path: a single signature, which is what tools send
        key, _, rest = value.strip().partition("=")
        return {key.strip(): rest.strip()} if key.strip() else {}
    members, buf, in_quotes, depth = {}, [], False, 0
    for ch in value + ",":
        if ch == '"' and (not buf or buf[-1] != "\\"):
            in_quotes = not in_quotes
        elif not in_quotes and ch == "(":
            depth += 1
        elif not in_quotes and ch == ")":
            depth -= 1
        if ch == "," and not in_quotes and depth == 0:
            item = "".join(buf).strip()
            if item:
                key, _, rest = item.partition("=")
                members[key.strip()] = rest.strip()
            buf = []
        else:
            buf.append(ch)
    return members


def parse_signature_input(header: str, label: str | None = None) -> SignatureParams:
    members = _split_dict_members(header)
    if not members:
        raise SignatureError("malformed_signature_input", "empty Signature-Input")
    if label is None:
        # Prefer our tag if several signatures are present, else the first one.
        label = next((k for k, v in members.items() if f'tag="{SIGNATURE_TAG}"' in v), next(iter(members)))
    raw = members.get(label)
    if raw is None:
        raise SignatureError("malformed_signature_input", f"no signature labelled {label}")
    m = _INNER_RE.match(raw)
    if not m:
        raise SignatureError("malformed_signature_input", "covered components must be an inner list")
    components = tuple(re.findall(r'"([^"]*)"', m.group(1)))
    params: dict[str, str | int] = {}
    for key, val in _PARAM_RE.findall(raw[m.end():]):
        params[key] = val[1:-1] if val.startswith('"') else int(val)
    try:
        return SignatureParams(
            label=label,
            components=components,
            created=int(params["created"]),
            expires=int(params["expires"]) if "expires" in params else None,
            nonce=str(params["nonce"]),
            keyid=str(params["keyid"]),
            alg=str(params.get("alg", "ed25519")),
            tag=str(params.get("tag", "")),
            raw=raw,
        )
    except KeyError as e:
        raise SignatureError("malformed_signature_input", f"missing signature parameter {e.args[0]}") from None


def parse_signature(header: str, label: str) -> bytes:
    members = _split_dict_members(header)
    raw = members.get(label, "")
    if not (raw.startswith(":") and raw.endswith(":")):
        raise SignatureError("malformed_signature", f"no byte-sequence signature labelled {label}")
    try:
        return base64.b64decode(raw[1:-1], validate=True)
    except ValueError:
        raise SignatureError("malformed_signature", "signature is not valid base64") from None


def verify_request(public_key: Ed25519PublicKey, params: SignatureParams, signature: bytes, method: str, url: str,
                   headers: dict[str, str], *, now: int, skew_s: int, max_age_s: int,
                   body: bytes | None = None) -> None:
    """Raises SignatureError on any failure. Replay (nonce reuse) is checked by the caller in Redis."""
    if params.alg != "ed25519":
        raise SignatureError("unsupported_alg", f"alg {params.alg} not supported")
    missing = REQUIRED_COMPONENTS - set(params.components)
    if missing and not ("@target-uri" in params.components and missing <= {"@authority", "@path", "@query"}):
        raise SignatureError("insufficient_coverage", f"signature must cover {sorted(missing)}")
    if params.created > now + skew_s:
        raise SignatureError("signature_from_future", "signature created in the future")
    if now - params.created > max_age_s + skew_s:
        raise SignatureError("signature_expired", "signature too old")
    if params.expires is not None and now > params.expires + skew_s:
        raise SignatureError("signature_expired", "signature past its expires parameter")
    if not params.nonce or len(params.nonce) < 16:
        raise SignatureError("weak_nonce", "nonce must be at least 16 characters")
    lower = {k.lower(): v for k, v in headers.items()}
    if "content-digest" in params.components:
        if body is None or lower.get("content-digest") != content_digest(body):
            raise SignatureError("digest_mismatch", "content-digest does not match body")
    base = signature_base(method, url, lower, params.components, params.raw)
    try:
        public_key.verify(signature, base)
    except InvalidSignature:
        raise SignatureError("bad_signature", "signature verification failed") from None
