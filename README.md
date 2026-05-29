# cocapn-identity

Agent identity and trust management for the Cocapn Fleet — immutable identities, role-based capabilities, token-based auth, and trust scoring.

## What This Gives You

- **AgentIdentity** — immutable, hashable identity with name, role, public key, and capabilities
- **Role system** — keeper, vessel, forge, scout roles with validation
- **Token management** — issue and verify fleet authentication tokens
- **Trust scoring** — behavioral trust metrics for fleet agent interactions
- **Cryptographic hashing** — SHA-256 based identity verification

## Quick Start

```bash
pip install cocapn-identity

from cocapn_identity import AgentIdentity

agent = AgentIdentity(
    name="scout-alpha",
    role="scout",
    public_key="ed25519:abc123",
    capabilities=("observe", "report")
)
agent.verify()  # Validates name format and role
```

## How It Fits

The identity layer for the Cocapn Fleet. Part of the SuperInstance ecosystem.

Related repos:
- [cocapn-protocol](https://github.com/SuperInstance/cocapn-protocol) — fleet messaging protocol
- [cocapn-core](https://github.com/SuperInstance/cocapn-core) — core fleet library
- [cocapn-auth](https://github.com/SuperInstance/cocapn-health) — health and auth

## License

Apache 2.0
