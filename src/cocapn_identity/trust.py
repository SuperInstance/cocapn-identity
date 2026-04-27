"""Trust scoring between agents."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class _Interaction:
    """A single directed interaction record."""

    timestamp: float
    success: bool


class TrustScore:
    """Tracks interaction history and computes decayed trust scores.

    Trust is computed per unordered pair of agents.  A success contributes
    +1, a failure contributes 0.  Older interactions are exponentially
    decayed with a half-life of 30 days.
    """

    _HALF_LIFE_SECONDS: float = 30 * 24 * 3600  # 30 days

    def __init__(self) -> None:
        # key -> list of interactions from key[0] to key[1]
        self._history: dict[tuple[str, str], list[_Interaction]] = {}

    def record_interaction(
        self, from_agent: str, to_agent: str, success: bool
    ) -> None:
        """Log a directed interaction between two agents."""
        key = self._canonical_key(from_agent, to_agent)
        record = _Interaction(timestamp=time.time(), success=success)
        self._history.setdefault(key, []).append(record)

    def get_trust(self, agent_a: str, agent_b: str) -> float:
        """Return the decayed trust score between two agents, 0.0–1.0.

        A score of 1.0 means all recent interactions were successful;
        0.0 means all were failures or there is no history.
        """
        key = self._canonical_key(agent_a, agent_b)
        interactions = self._history.get(key, [])
        if not interactions:
            return 0.0

        now = time.time()
        total_weight = 0.0
        weighted_score = 0.0
        decay_lambda = math.log(2) / self._HALF_LIFE_SECONDS

        for ix in interactions:
            age = max(0.0, now - ix.timestamp)
            weight = math.exp(-decay_lambda * age)
            total_weight += weight
            weighted_score += weight * (1.0 if ix.success else 0.0)

        if total_weight == 0.0:
            return 0.0
        return weighted_score / total_weight

    @staticmethod
    def _canonical_key(a: str, b: str) -> tuple[str, str]:
        """Return an unordered pair key."""
        return (a, b) if a < b else (b, a)
