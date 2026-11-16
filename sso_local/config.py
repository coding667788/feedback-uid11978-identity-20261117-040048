"""Configuration: issuers, audiences, keys, and process-level knobs.

Configuration is loaded from a JSON file whose shape is::

    {
      "audience": "rp-local",
      "issuers": {
        "<iss>": {"key": "base64url-or-plain", "subjects": [...]}
      },
      "logout_issuers": {"<iss>": "base64url-or-plain"},
      "clock_skew_seconds": 0
    }

Issuer metadata is *pre-provisioned*: there is no discovery, no URL lookup.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .strictjson import StrictJSONError, loads_strict, require_object

DEFAULT_AUDIENCE = "rp-local"
MAX_CLOCK_SKEW = 300


class ConfigError(ValueError):
    pass


def parse_key_material(value: str, *, what: str) -> bytes:
    """Accept a ``b64:`` prefixed base64url value or a plain ASCII secret."""

    if not isinstance(value, str) or not value:
        raise ConfigError(f"{what}: key must be a non-empty string")
    if value.startswith("b64:"):
        raw = value[4:]
        if not raw:
            raise ConfigError(f"{what}: empty base64 key")
        try:
            key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except (binascii.Error, ValueError) as exc:
            raise ConfigError(f"{what}: invalid base64 key") from exc
        if not key:
            raise ConfigError(f"{what}: empty key")
        return key
    key = value.encode("utf-8")
    if len(key) < 8:
        raise ConfigError(f"{what}: secret shorter than 8 bytes")
    return key


@dataclass(frozen=True)
class IssuerConfig:
    iss: str
    key: bytes
    subjects: frozenset[str]


@dataclass(frozen=True)
class LogoutIssuerConfig:
    iss: str
    key: bytes


@dataclass(frozen=True)
class Config:
    audience: str
    login_issuers: dict[str, IssuerConfig]
    logout_issuers: dict[str, LogoutIssuerConfig]
    clock_skew_seconds: int = 0
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    def login_issuer(self, iss: str) -> IssuerConfig | None:
        return self.login_issuers.get(iss)

    def logout_issuer(self, iss: str) -> LogoutIssuerConfig | None:
        return self.logout_issuers.get(iss)

    def describe(self) -> dict[str, Any]:
        """Public view: never exposes key bytes."""

        return {
            "audience": self.audience,
            "clock_skew_seconds": self.clock_skew_seconds,
            "login_issuers": {
                iss: sorted(c.subjects) for iss, c in sorted(self.login_issuers.items())
            },
            "logout_issuers": sorted(self.logout_issuers),
        }


def load_config(path: str | Path) -> Config:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {p}: {exc}") from exc
    try:
        doc = loads_strict(text)
    except StrictJSONError as exc:
        raise ConfigError(f"config is not strict JSON: {exc}") from exc
    doc = require_object(doc, "config")

    audience = doc.get("audience", DEFAULT_AUDIENCE)
    if not isinstance(audience, str) or not audience or len(audience) > 200:
        raise ConfigError("audience must be a non-empty string")

    skew = doc.get("clock_skew_seconds", 0)
    if type(skew) is not int or not 0 <= skew <= MAX_CLOCK_SKEW:
        raise ConfigError(f"clock_skew_seconds must be an int in 0..{MAX_CLOCK_SKEW}")

    issuers_doc = require_object(doc.get("issuers", {}), "issuers")
    login: dict[str, IssuerConfig] = {}
    for iss, entry in issuers_doc.items():
        if not isinstance(iss, str) or not iss:
            raise ConfigError("issuer name must be a non-empty string")
        entry = require_object(entry, f"issuers[{iss}]")
        key = parse_key_material(entry.get("key"), what=f"issuers[{iss}]")
        subjects_doc = entry.get("subjects", [])
        if not isinstance(subjects_doc, list) or not all(
            isinstance(s, str) and s for s in subjects_doc
        ):
            raise ConfigError(f"issuers[{iss}].subjects must be a list of strings")
        if len(set(subjects_doc)) != len(subjects_doc):
            raise ConfigError(f"issuers[{iss}].subjects has duplicates")
        login[iss] = IssuerConfig(
            iss=iss, key=key, subjects=frozenset(subjects_doc)
        )

    logout_doc = require_object(doc.get("logout_issuers", {}), "logout_issuers")
    logout: dict[str, LogoutIssuerConfig] = {}
    for iss, value in logout_doc.items():
        if not isinstance(iss, str) or not iss:
            raise ConfigError("logout issuer name must be a non-empty string")
        logout[iss] = LogoutIssuerConfig(
            iss=iss, key=parse_key_material(value, what=f"logout_issuers[{iss}]")
        )

    if not login:
        raise ConfigError("at least one login issuer must be configured")
    if not logout:
        raise ConfigError("at least one logout issuer must be configured")

    return Config(
        audience=audience,
        login_issuers=login,
        logout_issuers=logout,
        clock_skew_seconds=skew,
        raw=doc,
    )
