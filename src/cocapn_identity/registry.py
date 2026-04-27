"""Agent registry with lookup and JSON export/import."""

from __future__ import annotations

import json
from typing import Any

from .agent import AgentIdentity


class AgentRegistry:
    """In-memory store for agent identities."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentIdentity] = {}

    def register(self, agent: AgentIdentity) -> None:
        """Register an agent, replacing any existing entry with the same name."""
        agent.verify()
        self._agents[agent.name] = agent

    def unregister(self, name: str) -> None:
        """Remove an agent by name.

        Raises:
            KeyError: If the agent does not exist.
        """
        if name not in self._agents:
            raise KeyError(f"Agent '{name}' not found")
        del self._agents[name]

    def get(self, name: str) -> AgentIdentity | None:
        """Lookup an agent by exact name."""
        return self._agents.get(name)

    def find_by_role(self, role: str) -> list[AgentIdentity]:
        """Return all agents with the given role."""
        return [a for a in self._agents.values() if a.role == role]

    def find_by_capability(self, capability: str) -> list[AgentIdentity]:
        """Return all agents that have the given capability."""
        return [a for a in self._agents.values() if capability in a.capabilities]

    def list_all(self) -> list[AgentIdentity]:
        """Return all registered agents."""
        return list(self._agents.values())

    def export_json(self) -> str:
        """Export the registry as a JSON string."""
        payload = [a.to_dict() for a in self._agents.values()]
        return json.dumps(payload, indent=2, sort_keys=True)

    def import_json(self, data: str) -> None:
        """Import agents from a JSON string."""
        parsed: list[dict[str, Any]] = json.loads(data)
        for item in parsed:
            agent = AgentIdentity.from_dict(item)
            self.register(agent)

    def __len__(self) -> int:
        return len(self._agents)
