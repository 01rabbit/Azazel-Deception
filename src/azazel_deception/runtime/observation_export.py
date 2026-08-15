"""Read-side export of AZ-06's recorded interaction observations.

:mod:`azazel_deception.runtime.observation` appends fact-only
``InteractionObservation`` records into the same tamper-evident evidence
chain as environment lifecycle events (activation, termination, resets,
failures). This module is the read side: it filters that mixed chain down to
*only* the interaction-observation records, in append order, and re-validates
each one through Fabric's ``InteractionObservation`` model so a caller gets a
canonical, wire-shaped dict back — never the raw evidence-chain record (which
carries local hash-chain bookkeeping fields Fabric's schema does not know
about and rejects under ``extra="forbid"``).

Export here means "read what AZ-06 already recorded", not "send it
anywhere". AZ-06 does not talk to Azazel-Knowledge directly; in production,
Azazel-Edge reads (or is pushed) these facts and relays them onward. This
module authorizes nothing, starts nothing, and computes no effectiveness
judgement — it is a pure, side-effect-free projection of the evidence chain.
"""

from __future__ import annotations

import json
from typing import Any

from azazel_fabric.deception_contracts import InteractionObservation

from azazel_deception.runtime.state import RuntimeStateStore

_OBSERVATION_SCHEMA_VERSION = "interaction-observation/v0.1"

# Local hash-chain bookkeeping keys `RuntimeStateStore.append_evidence` stamps
# onto every evidence record. Fabric's `InteractionObservation` model does not
# know about these (and forbids extra fields), so they are stripped before
# validation -- the chain integrity they support is verified separately via
# `RuntimeStateStore.verify_evidence_chain`, not by this read-side export.
_EVIDENCE_CHAIN_KEYS = ("_evidence_seq", "_evidence_prev", "_evidence_hash")


def export_observations(
    state: RuntimeStateStore,
    environment_id: str,
) -> list[dict[str, Any]]:
    """Return this environment's interaction observations, in record order.

    Reads the environment's evidence chain, keeps only records whose
    ``schema_version`` is ``interaction-observation/v0.1`` (lifecycle events
    such as ``activated``/``terminated``/``reset_completed``/``failure`` and
    any other evidence-chain schema are filtered out), and re-validates each
    kept record through :class:`InteractionObservation` before re-dumping it.
    That round trip is deliberate: it guarantees every dict this function
    returns is exactly the canonical Fabric wire shape a downstream relay
    (Edge) can trust, with none of the local evidence-chain bookkeeping
    fields (``_evidence_seq``/``_evidence_prev``/``_evidence_hash``) leaking
    through.

    Ordering is the evidence chain's append order (its ``_evidence_seq``),
    which is deterministic for a given environment.
    """

    path = state.evidence_path(environment_id)
    if not path.exists():
        return []

    observations: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            continue
        if record.get("schema_version") != _OBSERVATION_SCHEMA_VERSION:
            continue
        canonical = {k: v for k, v in record.items() if k not in _EVIDENCE_CHAIN_KEYS}
        observation = InteractionObservation.model_validate(canonical)
        observations.append(observation.model_dump(mode="json"))
    return observations


def observations_since(
    state: RuntimeStateStore,
    environment_id: str,
    after_observation_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return observations recorded after ``after_observation_id``.

    An incremental cursor for a dev/virtual-E2E relay loop that wants to
    stream only new facts instead of re-fetching the whole chain each time.
    Observation IDs are monotonically issued per environment
    (``{environment_id}-obs-0001``, ``-0002``, ...), so "after" is a simple
    positional cut over :func:`export_observations`'s already-ordered
    output: everything strictly after the matching ID, or the full list when
    ``after_observation_id`` is ``None``.

    Raises ``ValueError`` if ``after_observation_id`` is given but does not
    match any observation in this environment's chain, so a caller with a
    stale or wrong cursor fails closed instead of silently resyncing from
    the start (which would look like "no new observations" and hide a bug).
    """

    observations = export_observations(state, environment_id)
    if after_observation_id is None:
        return observations

    for index, observation in enumerate(observations):
        if observation.get("observation_id") == after_observation_id:
            return observations[index + 1 :]

    raise ValueError(
        f"after_observation_id {after_observation_id!r} not found in "
        f"environment {environment_id!r}'s observation chain"
    )
