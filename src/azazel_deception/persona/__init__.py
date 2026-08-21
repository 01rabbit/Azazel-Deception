"""AZ-06 persona/activity runtime.

Deterministic, bounded scheduling of synthetic persona activity for
deception hosts. See :mod:`azazel_deception.persona.runtime` for the
public API (`PersonaSpec`, `PersonaActivityEvent`, `PersonaRuntime`).
"""

from __future__ import annotations

from .runtime import (
    ALLOWED_ACTIVITIES,
    PersonaActivityEvent,
    PersonaRuntime,
    PersonaSpec,
    PersonaSpecError,
    WorkingHours,
)

__all__ = [
    "ALLOWED_ACTIVITIES",
    "PersonaActivityEvent",
    "PersonaRuntime",
    "PersonaSpec",
    "PersonaSpecError",
    "WorkingHours",
]
