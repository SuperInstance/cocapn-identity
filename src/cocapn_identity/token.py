"""Authentication tokens for fleet agents."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .agent import AgentIdentity
from .registry import AgentRegistry


@dataclass(frozen=True, slots=True)
class AuthToken:
    """Immutable authentication token."""

    agent_fingerprint: str
    issued_at: float
    expires_at: float
    scope: tuple[str, ...]
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_fingerprint": self.agent_fingerprint,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scope": list(self.scope),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthToken:
        return cls(
            agent_fingerprint=data["agent_fingerprint"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            scope=tuple(data.get("scope", [])),
            signature=data["signature"],
        )


def _get_secret() -> str:
    """Return the fleet secret from the environment or a default.

    In production this should be loaded from a secure vault.
    """
    import os

    return os.environ.get("FLEET_SECRET", "fleet-secret-default-CHANGE-ME")


def _sign_payload(payload: str, secret: str) -> str:
    """Sign a canonical payload with HMAC-SHA256."""
    return hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def generate_token(
    agent: AgentIdentity,
    ttl_seconds: float,
    scope: list[str] | tuple[str, ...],
    secret: str | None = None,
) -> AuthToken:
    """Create a signed authentication token for an agent.

    Args:
        agent: The identity to issue the token for.
        ttl_seconds: Time-to-live in seconds.
        scope: List of permission strings.
        secret: Optional fleet secret override.

    Returns:
        A new AuthToken.
    """
    now = time.time()
    expires = now + ttl_seconds
    fingerprint = agent.fingerprint()
    scope_tuple = tuple(sorted(set(scope)))

    payload = json.dumps(
        {
            "agent_fingerprint": fingerprint,
            "issued_at": now,
            "expires_at": expires,
            "scope": list(scope_tuple),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    sig = _sign_payload(payload, secret or _get_secret())

    return AuthToken(
        agent_fingerprint=fingerprint,
        issued_at=now,
        expires_at=expires,
        scope=scope_tuple,
        signature=sig,
    )


def verify_token(
    token: AuthToken,
    registry: AgentRegistry,
    secret: str | None = None,
) -> AgentIdentity:
    """Verify a token and return the associated agent.

    Args:
        token: The token to verify.
        registry: Registry to look up the agent fingerprint.
        secret: Optional fleet secret override.

    Returns:
        The matched AgentIdentity.

    Raises:
        ValueError: If the token is invalid, expired, or the agent is unknown.
    """
    now = time.time()
    if token.expires_at < now:
        raise ValueError("token has expired")

    payload = json.dumps(
        {
            "agent_fingerprint": token.agent_fingerprint,
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
            "scope": list(token.scope),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    expected_sig = _sign_payload(payload, secret or _get_secret())
    if not hmac.compare_digest(expected_sig, token.signature):
        raise ValueError("token signature is invalid")

    for agent in registry.list_all():
        if agent.fingerprint() == token.agent_fingerprint:
            return agent

    raise ValueError("token agent fingerprint not found in registry")
