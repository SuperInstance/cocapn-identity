"""Tests for authentication tokens."""

import time

import pytest

from cocapn_identity.agent import AgentIdentity
from cocapn_identity.registry import AgentRegistry
from cocapn_identity.token import AuthToken, generate_token, verify_token


def test_generate_and_verify_token() -> None:
    registry = AgentRegistry()
    agent = AgentIdentity(
        name="token-agent",
        role="forge",
        public_key="deadbeef",
        capabilities=("build",),
    )
    registry.register(agent)

    token = generate_token(agent, ttl_seconds=300, scope=["build:all"])
    assert token.agent_fingerprint == agent.fingerprint()
    assert token.expires_at > token.issued_at
    assert token.scope == ("build:all",)

    matched = verify_token(token, registry)
    assert matched.name == agent.name


def test_token_expired() -> None:
    registry = AgentRegistry()
    agent = AgentIdentity(
        name="expired-agent",
        role="scout",
        public_key="cafebabe",
    )
    registry.register(agent)

    token = generate_token(agent, ttl_seconds=-1, scope=["read"])
    with pytest.raises(ValueError, match="expired"):
        verify_token(token, registry)


def test_token_bad_signature() -> None:
    registry = AgentRegistry()
    agent = AgentIdentity(
        name="bad-sig-agent",
        role="keeper",
        public_key="feedface",
    )
    registry.register(agent)

    token = generate_token(agent, ttl_seconds=300, scope=["read"])
    tampered = AuthToken(
        agent_fingerprint=token.agent_fingerprint,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        scope=token.scope,
        signature="a" * 64,
    )
    with pytest.raises(ValueError, match="signature"):
        verify_token(tampered, registry)


def test_token_unknown_agent() -> None:
    registry = AgentRegistry()
    agent = AgentIdentity(
        name="unknown-agent",
        role="vessel",
        public_key="baadf00d",
    )
    # do NOT register
    token = generate_token(agent, ttl_seconds=300, scope=["read"])
    with pytest.raises(ValueError, match="fingerprint"):
        verify_token(token, registry)


def test_token_scope_is_tuple_and_sorted() -> None:
    agent = AgentIdentity(
        name="scope-agent",
        role="keeper",
        public_key="pk",
    )
    token = generate_token(agent, ttl_seconds=60, scope=["z", "a"])
    assert token.scope == ("a", "z")


def test_token_custom_secret() -> None:
    registry = AgentRegistry()
    agent = AgentIdentity(
        name="secret-agent",
        role="forge",
        public_key="secret-pk",
    )
    registry.register(agent)

    secret = "my-super-secret"
    token = generate_token(agent, ttl_seconds=300, scope=["deploy"], secret=secret)
    matched = verify_token(token, registry, secret=secret)
    assert matched.name == "secret-agent"

    # Wrong secret should fail
    with pytest.raises(ValueError, match="signature"):
        verify_token(token, registry, secret="wrong-secret")
