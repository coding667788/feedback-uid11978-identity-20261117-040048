"""Local SSO session + out-of-order logout notification demo service.

Explicitly *not* full OIDC: fixed HS256 compact tokens, no discovery, no
authorization-code flow, no refresh tokens.  See ``docs/PROTOCOL.md``.
"""

__all__ = ["__version__"]

__version__ = "1.0.0"
