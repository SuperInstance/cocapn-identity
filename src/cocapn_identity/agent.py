"""Agent identity definition."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any

VALID_ROLES = {"keeper", "vessel", "forge", "scout"}
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}[a-z0-9]$")


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    """Immutable identity for a fleet agent."""

    name: str
    role: str
    public_key: str
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    created: float = field(default_factory=time.time)
    parent: str | None = None

    def __post_init__(self) -> None:
        # Normalise capabilities to a sorted tuple for stable hashing
        object.__setattr__(
            self, "capabilities", tuple(sorted(set(self.capabilities)))
        )

    def verify(self) -> None:
        """Validate name format and role.

        Raises:
            ValueError: If the identity is invalid.
        """
        if not self.name:
            raise ValueError("name must not be empty")
        if not _NAME_RE.match(self.name):
            raise ValueError(
                f"name '{self.name}' must match ^[a-z][a-z0-9-]{{0,62}}[a-z0-9]$"
            )
        if self.role not in VALID_ROLES:
            raise ValueError(
                f"role '{self.role}' must be one of {VALID_ROLES}"
            )
        if not self.public_key:
            raise ValueError("public_key must not be empty")

    def fingerprint(self) -> str:
        """Return a SHA-256 fingerprint of this identity."""
        payload: dict[str, Any] = {
            "name": self.name,
            "role": self.role,
            "public_key": self.public_key,
            "capabilities": list(self.capabilities),
            "created": self.created,
            "parent": self.parent,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict."""
        return {
            "name": self.name,
            "role": self.role,
            "public_key": self.public_key,
            "capabilities": list(self.capabilities),
            "created": self.created,
            "parent": self.parent,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentIdentity:
        """Deserialise from a plain dict."""
        return cls(
            name=data["name"],
            role=data["role"],
            public_key=data["public_key"],
            capabilities=tuple(data.get("capabilities", [])),
            created=data.get("created", time.time()),
            parent=data.get("parent"),
        )
