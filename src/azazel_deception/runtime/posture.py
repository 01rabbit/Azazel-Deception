"""Strict-by-default posture for the reference live deployment (AZ-06).

``DockerComposeAdapter`` keeps permissive, explicit defaults
(``require_sbom_verification=False``, ``require_authenticated_decisions=False``)
so unit tests and library callers can construct exactly the adapter they mean
to test without fighting a class-level default. This module is the one place
that decides what the *reference deployment* actually runs with: every
production/reference construction site (the CLI, the virtual Phase-1 lab) goes
through :func:`build_reference_adapter` instead of instantiating
``DockerComposeAdapter`` directly, so the reference deployment gets the strict
posture by default without changing the class's own defaults.

Strict posture requires both the SBOM verifier and the decision authenticator
to be configured; a live activation or termination fails closed
(``RuntimeGateError``) if either is missing while strict. Shadow/replay
service construction (``runtime/shadow_server.py``) does not go through this
module: it pins ``live_enabled=False`` unconditionally, so the strict-posture
question does not apply to it.

Opting out is possible for development only, and only explicitly: pass
``dev_relaxed_posture=True`` (CLI/script flag: ``--dev-relaxed-posture``) or
set the environment variable named below to ``"1"``. There is deliberately no
quieter way to relax the posture - anyone reading a reference-deployment
invocation must be able to see that the strict gates were turned off on
purpose.
"""

from __future__ import annotations

import os
from pathlib import Path

from azazel_deception.runtime.compose import DockerComposeAdapter
from azazel_deception.runtime.preflight import PackageVerifier, SbomVerifier
from azazel_deception.runtime.transport import DecisionAuthenticator

# The one supported opt-out mechanism for relaxing the reference deployment's
# strict posture. Loudly named on purpose: it must read as a development
# escape hatch, not a routine configuration switch.
DEV_RELAXED_POSTURE_ENV_VAR = "AZAZEL_DECEPTION_RELAXED_POSTURE"


def dev_relaxed_posture_requested(explicit: bool | None = None) -> bool:
    """Resolve whether the strict reference posture should be relaxed.

    ``explicit`` (a CLI/script flag) wins when given. Otherwise the
    environment variable is consulted, mirroring the ``AZAZEL_DECEPTION_LIVE``
    pattern ``DockerComposeAdapter`` already uses for ``live_enabled``.
    """

    if explicit is not None:
        return bool(explicit)
    return os.environ.get(DEV_RELAXED_POSTURE_ENV_VAR, "0") == "1"


def build_reference_adapter(
    compose_file: str | Path,
    state_root: str | Path,
    *,
    live_enabled: bool | None = None,
    package_verifier: PackageVerifier | None = None,
    sbom_verifier: SbomVerifier | None = None,
    decision_authenticator: DecisionAuthenticator | None = None,
    dev_relaxed_posture: bool | None = None,
) -> DockerComposeAdapter:
    """Construct the adapter used by every reference-deployment entry point.

    Strict posture (``require_sbom_verification=True`` and
    ``require_authenticated_decisions=True``) is the enforced default here.
    It is not silently satisfied: if a verifier/authenticator is not also
    passed in (and the posture is not relaxed), the first live activation or
    termination attempt fails closed with ``RuntimeGateError`` - the same
    fail-closed shape every other AZ-06 gate uses. A trusted package verifier
    remains mandatory for live activation regardless of this posture, per
    ``DockerComposeAdapter``.

    Set ``dev_relaxed_posture=True`` or ``AZAZEL_DECEPTION_RELAXED_POSTURE=1``
    to fall back to the permissive, optional-gate posture for local
    development. Never set this for a real reference deployment.
    """

    relaxed = dev_relaxed_posture_requested(dev_relaxed_posture)
    strict = not relaxed
    return DockerComposeAdapter(
        compose_file,
        state_root,
        live_enabled=live_enabled,
        package_verifier=package_verifier,
        sbom_verifier=sbom_verifier,
        decision_authenticator=decision_authenticator,
        require_sbom_verification=strict,
        require_authenticated_decisions=strict,
    )
