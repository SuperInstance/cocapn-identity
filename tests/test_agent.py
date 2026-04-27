"""Tests for agent identity."""

import json

import pytest

from cocapn_identity.agent import AgentIdentity


def test_agent_creation_and_fingerprint() -> None:
    agent = AgentIdentity(
        name="alpha-1",
        role="keeper",
        public_key="aabbccdd",
        capabilities=("read", "write"),
        created=12345.0,
        parent=None,
    )
    assert agent.name == "alpha-1"
    assert agent.role == "keeper"
    assert agent.capabilities == ("read", "write")
    agent.verify()

    fp = agent.fingerprint()
    assert len(fp) == 64
    # Same data -> same fingerprint
    agent2 = AgentIdentity(
        name="alpha-1",
        role="keeper",
        public_key="aabbccdd",
        capabilities=("write", "read"),
        created=12345.0,
        parent=None,
    )
    assert agent2.fingerprint() == fp


def test_agent_verify_bad_name() -> None:
    agent = AgentIdentity(name="", role="keeper", public_key="pk")
    with pytest.raises(ValueError):
        agent.verify()

    agent = AgentIdentity(name="BadName", role="keeper", public_key="pk")
    with pytest.raises(ValueError):
        agent.verify()


def test_agent_verify_bad_role() -> None:
    agent = AgentIdentity(name="good-name", role="hacker", public_key="pk")
    with pytest.raises(ValueError):
        agent.verify()


def test_agent_serde() -> None:
    agent = AgentIdentity(
        name="beta-2",
        role="vessel",
        public_key="00112233",
        capabilities=("log",),
        created=999.0,
        parent="alpha-1",
    )
    d = agent.to_dict()
    restored = AgentIdentity.from_dict(d)
    assert restored == agent
    assert restored.fingerprint() == agent.fingerprint()


def test_agent_capabilities_sorted() -> None:
    agent = AgentIdentity(
        name="gamma-3",
        role="scout",
        public_key="pk",
        capabilities=("z", "a", "m"),
    )
    assert agent.capabilities == ("a", "m", "z")
