"""Claim-level validation for login tickets and logout events.

Everything here runs *after* :func:`sso_local.tokens.parse_structure` and
:func:`~sso_local.tokens.verify_signature`.  Issuer selection is driven purely
by the claims' ``iss`` looked up in pre-provisioned configuration; no claim can
nominate its own key source.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .config import Config
from .tokens import TokenError, check_not_expired, verify_signature

LOGIN_REQUIRED = {"iss", "sub", "sid", "generation", "aud", "exp"}
MAX_TEXT = 200


@dataclass(frozen=True)
class LoginClaims:
    iss: str
    sub: str
    sid: str
    generation: int
    aud: str
    exp: int
    claims: dict[str, Any]
    digest: str

    @property
    def identity(self) -> tuple[str, str]:
        return (self.iss, self.sub)


@dataclass(frozen=True)
class LogoutClaims:
    event_id: str
    event_iss: str
    kind: str  # "sid" or "range"
    iss: str
    sub: str
    sid: str | None
    cutoff_generation: int | None
    claims: dict[str, Any]
    digest: str  # semantic digest: the revocation content only

    @property
    def identity(self) -> tuple[str, str]:
        return (self.iss, self.sub)


def event_semantic_digest(claims: dict[str, Any]) -> str:
    """Digest of what a logout *asserts*, excluding its validity window.

    ``iat``/``exp`` are transport concerns: a notifier that re-signs the same
    event with a fresh expiry is retrying, not changing its meaning.  Every
    field that can widen or move a revocation (type, target, sub, sid, cutoff,
    event id, event issuer) is included.
    """

    fields = (
        "event_id",
        "iss",
        "type",
        "target_iss",
        "sub",
        "sid",
        "cutoff_generation",
    )
    canonical = {name: claims[name] for name in fields if name in claims}
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _text(claims: dict[str, Any], name: str, *, max_len: int = MAX_TEXT) -> str:
    value = claims.get(name)
    if not isinstance(value, str):
        raise TokenError("invalid_type", f"{name} must be a string")
    if not value or len(value) > max_len:
        raise TokenError("invalid_value", f"{name} has an invalid length")
    if any(ord(ch) < 0x20 for ch in value):
        raise TokenError("invalid_value", f"{name} contains control characters")
    return value


def _positive_int(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if type(value) is not int:  # bool is an int subclass; reject it
        raise TokenError("invalid_type", f"{name} must be a JSON integer")
    if value < 1:
        raise TokenError("invalid_value", f"{name} must be >= 1")
    return value


def validate_login(
    parsed,
    config: Config,
    *,
    now: int,
    skip_expiry: bool = False,
) -> LoginClaims:
    """Full login-ticket validation against pre-provisioned issuer config."""

    claims = parsed.claims
    iss = claims.get("iss")
    if not isinstance(iss, str) or not iss:
        raise TokenError("invalid_type", "iss must be a non-empty string")
    issuer = config.login_issuer(iss)
    if issuer is None:
        # Unknown issuer is rejected before any signature work.
        raise TokenError("unknown_issuer", iss)
    verify_signature(parsed, issuer.key)
    if not skip_expiry:
        check_not_expired(claims, now=now, skew=config.clock_skew_seconds)

    sub = _text(claims, "sub")
    sid = _text(claims, "sid")
    aud = _text(claims, "aud")
    exp = _positive_int(claims, "exp")

    if aud != config.audience:
        raise TokenError("bad_audience", f"expected {config.audience!r}")
    if sub not in issuer.subjects:
        raise TokenError("unknown_subject", f"{iss}/{sub} is not provisioned")
    if any(ord(ch) < 0x21 for ch in sid):
        raise TokenError("invalid_value", "sid contains whitespace/controls")
    generation = _positive_int(claims, "generation")

    return LoginClaims(
        iss=iss,
        sub=sub,
        sid=sid,
        generation=generation,
        aud=aud,
        exp=exp,
        claims=claims,
        digest=event_semantic_digest(claims),
    )


def validate_logout(
    parsed,
    config: Config,
    *,
    now: int,
) -> LogoutClaims:
    """Full logout-event validation.  Content is authoritative, arrival time is not."""

    claims = parsed.claims
    if type(claims.get("v")) is not int or claims.get("v") != 1:
        raise TokenError("invalid_version", "v must be the integer 1")

    event_id = _text(claims, "event_id", max_len=120)
    event_iss = claims.get("iss")
    if not isinstance(event_iss, str) or not event_iss:
        raise TokenError("invalid_type", "iss must be a non-empty string")
    issuer = config.logout_issuer(event_iss)
    if issuer is None:
        raise TokenError("unknown_issuer", event_iss)
    verify_signature(parsed, issuer.key)
    check_not_expired(claims, now=now, skew=config.clock_skew_seconds)

    event_type = claims.get("type")
    if not isinstance(event_type, str):
        raise TokenError("invalid_type", "type must be a string")
    if event_type == "sid":
        sid = _text(claims, "sid", max_len=120)
        subject_iss = _text(claims, "target_iss")
        sub = _text(claims, "sub")
        if "cutoff_generation" in claims:
            raise TokenError("invalid_shape", "sid logout must not carry a cutoff")
        return LogoutClaims(
            event_id=event_id,
            event_iss=event_iss,
            kind="sid",
            iss=subject_iss,
            sub=sub,
            sid=sid,
            cutoff_generation=None,
            claims=claims,
            digest=event_semantic_digest(claims),
        )
    if event_type == "range":
        subject_iss = _text(claims, "target_iss")
        if "sid" in claims:
            raise TokenError("invalid_shape", "range logout must not carry a sid")
        sub = _text(claims, "sub")
        cutoff = claims.get("cutoff_generation")
        if type(cutoff) is not int:
            raise TokenError("invalid_type", "cutoff_generation must be a JSON integer")
        if cutoff < 0:
            raise TokenError("invalid_value", "cutoff_generation must be >= 0")
        return LogoutClaims(
            event_id=event_id,
            event_iss=event_iss,
            kind="range",
            iss=subject_iss,
            sub=sub,
            sid=None,
            cutoff_generation=cutoff,
            claims=claims,
            digest=event_semantic_digest(claims),
        )
    raise TokenError("invalid_value", f"unknown logout type {event_type!r}")
