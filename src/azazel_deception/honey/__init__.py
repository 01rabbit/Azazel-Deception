"""AZ-06 "Deception#6" honey artifacts: synthetic decoy descriptors + manifest.

This package *generates* in-memory descriptors of synthetic honey artifacts
(files & related documents, metadata & revision history, configuration
breadcrumbs, service/host history) plus a traceable manifest. It never writes
to a real or attacker-facing filesystem location -- materialization/placement
of these descriptors onto a running decoy is the runtime adapter's job and is
out of scope here.

Everything is deterministic and replayable: outputs are a pure function of
``(package, seed, as_of)``. No ``datetime.now``/``time``/``random`` is used.
"""

from __future__ import annotations

from .artifacts import (
    BANNED_PATTERNS,
    HoneyArtifact,
    HoneyArtifactError,
    HoneyArtifactManifest,
    RevisionEntry,
    SyntheticGuardViolation,
    assert_synthetic_only,
    generate_honey_artifacts,
)

__all__ = [
    "BANNED_PATTERNS",
    "HoneyArtifact",
    "HoneyArtifactError",
    "HoneyArtifactManifest",
    "RevisionEntry",
    "SyntheticGuardViolation",
    "assert_synthetic_only",
    "generate_honey_artifacts",
]
