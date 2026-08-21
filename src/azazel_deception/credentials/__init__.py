"""AZ-06 credential-lure lifecycle (Deception#6: "Credential lures").

Public surface: :func:`mint_lure` mints a fully synthetic, uniquely
identifiable, scoped, expiring credential lure as the canonical Fabric
:class:`~azazel_fabric.deception_contracts.CredentialLure`; :class:`LureRegistry`
tracks which minted lures are currently active and fails closed on any
unknown, expired, invalidated, or mis-scoped lookup.
"""

from azazel_deception.credentials.lures import (
    LureInvalidationInfo,
    LureRegistry,
    mint_lure,
)

__all__ = ["mint_lure", "LureRegistry", "LureInvalidationInfo"]
