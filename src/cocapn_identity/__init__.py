"""cocapn-identity — Fleet agent identity and authentication."""

__version__ = "0.1.0"

from .agent import AgentIdentity
from .registry import AgentRegistry
from .token import AuthToken, generate_token, verify_token
from .trust import TrustScore

__all__ = [
    "AgentIdentity",
    "AgentRegistry",
    "AuthToken",
    "TrustScore",
    "generate_token",
    "verify_token",
]
