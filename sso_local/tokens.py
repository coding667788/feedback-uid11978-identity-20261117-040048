"""Fixed HS256 compact-token handling (no discovery, no key URLs).

The local test protocol uses exactly one signing shape::

    header  = {"alg":"HS256","typ":"JWT"}      (exact two members)
    payload = strict JSON object, no duplicate members

Login tickets and logout events share this envelope.  A token can never point
at key material: the header is compared to an exact literal, so ``jku``,
``jwk``, ``x5u``, ``kid`` and ``crit`` are rejected rather than ignored.

This module only does envelope + signature + expiry work.  Claim semantics live
in :mod:`sso_local.claims`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

from .strictjson import StrictJSONError, loads_strict

_B64URL_SEGMENT = re.compile(r"^[A-Za-z0-9_-]*$")
MAX_TOKEN_BYTES = 16 * 1024
EXPECTED_HEADER = {"alg": "HS256", "typ": "JWT"}


class TokenError(ValueError):
    """A rejected token with a stable machine-readable reason."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode_segment(text: str, *, allow_empty: bool) -> bytes:
    if not isinstance(text, str) or not _B64URL_SEGMENT.fullmatch(text):
        raise TokenError("invalid_base64", "segment is not unpadded base64url")
    if not text:
        if allow_empty:
            return b""
        raise TokenError("invalid_base64", "empty segment")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise TokenError("invalid_base64", str(exc)) from exc


def sign_hs256(signing_input: bytes, key: bytes) -> bytes:
    return hmac.new(key, signing_input, hashlib.sha256).digest()


def encode_token(claims: dict[str, Any], key: bytes) -> str:
    header_b64 = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload_b64 = b64url_encode(
        json.dumps(
            claims, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return f"{header_b64}.{payload_b64}.{b64url_encode(sign_hs256(signing_input, key))}"


@dataclass(frozen=True)
class ParsedToken:
    token: str
    header: dict[str, Any]
    claims: dict[str, Any]
    header_segment: str
    payload_segment: str
    signature_segment: str


def parse_structure(token: str) -> ParsedToken:
    """Envelope checks that do not need a key.

    Rejections, in order: non-string / oversized input, wrong segment count,
    bad base64, non-object JSON, duplicate JSON members (header or payload),
    header that is not exactly the fixed HS256 header.
    """

    if not isinstance(token, str):
        raise TokenError("invalid_token", "token must be a string")
    if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise TokenError("token_too_large")
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed_token", "expected exactly 3 segments")
    header_raw = b64url_decode_segment(parts[0], allow_empty=False)
    payload_raw = b64url_decode_segment(parts[1], allow_empty=False)
    # An empty signature is structurally allowed so that a "none" algorithm is
    # rejected by the header check, not by an incidental base64 error.
    b64url_decode_segment(parts[2], allow_empty=True)

    try:
        header = loads_strict(header_raw)
        claims = loads_strict(payload_raw)
    except StrictJSONError as exc:
        raise TokenError("invalid_json", str(exc)) from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise TokenError("invalid_json", "header and payload must be JSON objects")
    if header != EXPECTED_HEADER:
        raise TokenError(
            "invalid_header",
            "header must be exactly " + json.dumps(EXPECTED_HEADER, sort_keys=True),
        )
    return ParsedToken(
        token=token,
        header=header,
        claims=claims,
        header_segment=parts[0],
        payload_segment=parts[1],
        signature_segment=parts[2],
    )


def verify_signature(parsed: ParsedToken, key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise TokenError("unknown_issuer", "no key configured")
    signature = b64url_decode_segment(parsed.signature_segment, allow_empty=True)
    expected = sign_hs256(
        f"{parsed.header_segment}.{parsed.payload_segment}".encode("ascii"), bytes(key)
    )
    if len(signature) != len(expected) or not hmac.compare_digest(signature, expected):
        raise TokenError("bad_signature")


def check_not_expired(claims: dict[str, Any], *, now: int, skew: int = 0) -> None:
    exp = claims.get("exp")
    if type(exp) is not int:
        raise TokenError("invalid_exp", "exp must be a JSON integer")
    if exp + skew <= now:
        raise TokenError("expired", f"exp={exp}")

