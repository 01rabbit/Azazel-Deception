"""SO-08 run records: the virtual-lab regression record and the HIL
field-exercise record, and the one validator both are held to.

SO-08 (Azazel-Deception#41) is a **hardware-only** objective. Its release form
is a field exercise on a real segment, recorded as JSON and *committed to this
repository* under ``docs/field-exercises/so08/``. A namespace-based virtual-lab
run is useful as a CI regression signal for the detection half and nothing
more: **no green CI run, and no virtual-lab record, satisfies the HIL gate.**
That is not a convention here, it is what :func:`validate_record` checks:

* a ``virtual-lab-regression`` record must carry ``gate: false``, can never
  carry ``verdict: "pass"``, and must say it has no commissioned identity;
* a ``hil-field-exercise`` record must name a commissioned composite
  identifier that is neither the virtual-lab marker nor a kernel interface
  name, and can only pass when *both* halves were measured on every sample.

The target values below are the §8 row's. They are stated here once and read
by the harness, the validator and the tests; changing them is changing the
objective, which this repository does not own.

This module computes verdicts from samples. It authorizes nothing and grants
nothing: a passing HIL record is evidence an operator may cite in a
``LiveGateCertification``, not a certification.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from azazel_deception.runtime.isolation_drift import DRIFT_KINDS

SCHEMA = "azazel-deception/so08-record/v1"
OBJECTIVE_ID = "SO-08"
OWNING_REPOSITORY = "01rabbit/Azazel-Deception"

#: §8 targets. Not this repository's to change.
DETECTION_BOUND_MS = 2000.0
WITHDRAWAL_BOUND_MS = 5000.0
SAMPLES_PER_KIND = 20

CLASS_VIRTUAL_LAB = "virtual-lab-regression"
CLASS_HIL = "hil-field-exercise"
RECORD_CLASSES = (CLASS_VIRTUAL_LAB, CLASS_HIL)

#: The ``product_configuration.commissioned_identity`` of every virtual-lab
#: record. A namespace lab has nothing commissioned, and a kernel interface
#: name standing in for an identity would look like one.
VIRTUAL_LAB_NO_IDENTITY = "virtual-lab, no commissioned identity"

#: The only backend a virtual-lab record may come from. A test double has no
#: kernel under it and its record is not even regression evidence.
VIRTUAL_LAB_BACKEND = "linux-netns"

VERDICTS = ("pass", "fail", "not_measurable")

#: Where committed HIL field-exercise records live.
FIELD_EXERCISE_DIR = "docs/field-exercises/so08"

#: The withdrawal gap every record carries until Edge declares its
#: authoritative enforcement path. Withdrawal is enforcement; AZ-06 has no
#: authority to perform it and no stand-in performs it here.
EDGE_WITHDRAWAL_GAP_ID = "SO08-NO-EDGE-WITHDRAWAL-PATH"
EDGE_WITHDRAWAL_GAP_REF = "01rabbit/Azazel-Edge#412"


def edge_withdrawal_gap() -> dict[str, Any]:
    return {
        "id": EDGE_WITHDRAWAL_GAP_ID,
        "blocks_verdict": True,
        "refs": [EDGE_WITHDRAWAL_GAP_REF],
        "summary": (
            "Withdrawing attacker-route exposure is an enforcement action that "
            "must go through Azazel-Edge's authority path end-to-end. Edge has "
            "not declared an authoritative enforcement path (Azazel-Edge#412), "
            "so nothing withdraws the drift and the withdrawal end event cannot "
            "occur. AZ-06 does not withdraw (no enforcement authority) and the "
            "harness does not stand in for Edge."
        ),
    }


# Kernel interface names: the thing a commissioned identity must not be.
_INTERFACE_NAME = re.compile(
    r"^(?:lo|eth|en[a-z]|wl|wlan|br|veth|docker|virbr|tap|tun|bond|vlan|wg|ib|usb|azs08-)"
    r"[A-Za-z0-9._@-]*$"
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def looks_like_interface_name(value: str) -> bool:
    return bool(_INTERFACE_NAME.match(value.strip()))


def evaluate_samples(
    samples: Sequence[Mapping[str, Any]],
    *,
    bound_ms: float,
    start_key: str = "start_monotonic_ns",
    end_key: str = "end_monotonic_ns",
) -> dict[str, Any]:
    """Evaluate the every-sample rule over ``samples``.

    A sample with no end time is *unfinished*. Unfinished samples are counted
    as violations: a drift that was never recorded was not detected within the
    bound. ``holds`` is ``False`` for an empty sample set, never vacuously
    true.
    """

    elapsed: list[float] = []
    unfinished = 0
    violations = 0
    for sample in samples:
        start = sample.get(start_key)
        end = sample.get(end_key)
        if not isinstance(start, int) or not isinstance(end, int):
            unfinished += 1
            violations += 1
            continue
        ms = (end - start) / 1e6
        elapsed.append(ms)
        if ms < 0 or ms > bound_ms:
            violations += 1
    return {
        "sample_count": len(samples),
        "unfinished_samples": unfinished,
        "violations": violations,
        "max_elapsed_ms": round(max(elapsed), 3) if elapsed else None,
        "min_elapsed_ms": round(min(elapsed), 3) if elapsed else None,
        "holds": bool(samples) and violations == 0,
    }


def overall_verdict(part_verdicts: Sequence[str]) -> str:
    """Combine part verdicts: any fail is fail; else any unmeasured is unmeasured."""

    if not part_verdicts:
        return "not_measurable"
    if "fail" in part_verdicts:
        return "fail"
    if "not_measurable" in part_verdicts:
        return "not_measurable"
    return "pass"


def _part(record: Mapping[str, Any], name: str) -> Mapping[str, Any] | None:
    parts = record.get("parts")
    if not isinstance(parts, list):
        return None
    for part in parts:
        if isinstance(part, Mapping) and part.get("name") == name:
            return part
    return None


def validate_record(record: Mapping[str, Any]) -> list[str]:
    """Return every reason ``record`` is not a well-formed SO-08 record.

    An empty list means well-formed, not passing. The verdict is recomputed
    from the samples and must equal the one stated; a record cannot state a
    better verdict than its own samples support.
    """

    problems: list[str] = []
    if not isinstance(record, Mapping):
        return ["record is not a mapping"]

    if record.get("schema") != SCHEMA:
        problems.append(f"schema must be {SCHEMA!r}")
    if record.get("objective_id") != OBJECTIVE_ID:
        problems.append(f"objective_id must be {OBJECTIVE_ID!r}")
    record_class = record.get("class")
    if record_class not in RECORD_CLASSES:
        problems.append(f"class must be one of {RECORD_CLASSES}")
    verdict = record.get("verdict")
    if verdict not in VERDICTS:
        problems.append(f"verdict must be one of {VERDICTS} (there is no 'skip')")

    owner = record.get("owner")
    if not isinstance(owner, Mapping):
        problems.append("owner is missing")
    else:
        if owner.get("repository") != OWNING_REPOSITORY:
            problems.append(f"owner.repository must be {OWNING_REPOSITORY!r}")
        if not isinstance(owner.get("commit"), str) or not _COMMIT.match(owner["commit"]):
            problems.append("owner.commit must be a full 40-hex commit")

    config = record.get("product_configuration")
    identity = config.get("commissioned_identity") if isinstance(config, Mapping) else None
    if not isinstance(config, Mapping):
        problems.append("product_configuration is missing")
    elif list(config.get("drift_kinds") or []) != list(DRIFT_KINDS):
        problems.append(f"product_configuration.drift_kinds must be {list(DRIFT_KINDS)}")

    executed = record.get("executed")
    if not isinstance(executed, bool):
        problems.append("executed must be a boolean")

    detection = _part(record, "detection")
    withdrawal = _part(record, "withdrawal")
    if detection is None or withdrawal is None:
        problems.append("parts must include 'detection' and 'withdrawal'")
        return problems

    # Recompute each part's verdict from its samples.
    derived: dict[str, str] = {}
    for part, bound, name in (
        (detection, DETECTION_BOUND_MS, "detection"),
        (withdrawal, WITHDRAWAL_BOUND_MS, "withdrawal"),
    ):
        rule = part.get("pass_rule")
        if not isinstance(rule, Mapping) or rule.get("bound_ms") != bound:
            problems.append(f"{name}.pass_rule.bound_ms must be {bound} (target values are fixed)")
        samples = part.get("samples")
        if not isinstance(samples, list):
            problems.append(f"{name}.samples must be a list")
            samples = []
        gaps = part.get("gaps") or []
        blocking = [g for g in gaps if isinstance(g, Mapping) and g.get("blocks_verdict")]
        if executed is not True:
            expected = "not_measurable"
        elif blocking:
            expected = "not_measurable"
        else:
            evaluated = evaluate_samples(samples, bound_ms=bound)
            expected = "pass" if evaluated["holds"] else "fail"
            if isinstance(rule, Mapping) and rule.get("evaluated") != evaluated:
                problems.append(f"{name}.pass_rule.evaluated does not match its samples")
        derived[name] = expected
        if part.get("verdict") != expected:
            problems.append(
                f"{name}.verdict is {part.get('verdict')!r}; its samples and gaps give {expected!r}"
            )

    if executed is True:
        samples = detection.get("samples") or []
        for kind in DRIFT_KINDS:
            count = sum(1 for s in samples if isinstance(s, Mapping) and s.get("drift_kind") == kind)
            if count < SAMPLES_PER_KIND:
                problems.append(f"detection has {count} samples of {kind}; {SAMPLES_PER_KIND} required")

    expected_overall = overall_verdict(list(derived.values()))
    if verdict != expected_overall:
        problems.append(f"verdict is {verdict!r}; its parts give {expected_overall!r}")

    if record_class == CLASS_VIRTUAL_LAB:
        if record.get("gate") is not False:
            problems.append("a virtual-lab-regression record must carry gate: false")
        if verdict == "pass":
            problems.append("a virtual-lab-regression record can never pass SO-08")
        if identity != VIRTUAL_LAB_NO_IDENTITY:
            problems.append(
                f"virtual-lab commissioned_identity must be {VIRTUAL_LAB_NO_IDENTITY!r}"
            )
        if isinstance(config, Mapping) and config.get("lab_backend") != VIRTUAL_LAB_BACKEND:
            problems.append(f"virtual-lab lab_backend must be {VIRTUAL_LAB_BACKEND!r}")
        gap_ids = {g.get("id") for g in withdrawal.get("gaps") or [] if isinstance(g, Mapping)}
        if EDGE_WITHDRAWAL_GAP_ID not in gap_ids:
            problems.append(f"virtual-lab withdrawal part must carry gap {EDGE_WITHDRAWAL_GAP_ID}")
    elif record_class == CLASS_HIL:
        if record.get("gate") is not True:
            problems.append("a hil-field-exercise record carries gate: true")
        if (
            not isinstance(identity, str)
            or not identity.strip()
            or identity == VIRTUAL_LAB_NO_IDENTITY
            or looks_like_interface_name(identity)
        ):
            problems.append(
                "hil commissioned_identity must be a commissioned composite identifier, "
                "not empty, not the virtual-lab marker and not a kernel interface name"
            )
        exercise = record.get("field_exercise")
        required = ("performed_at_utc", "operator", "site_ref", "protected_network_ref", "edge")
        if not isinstance(exercise, Mapping):
            problems.append("hil record requires field_exercise")
        else:
            for key in required:
                if not exercise.get(key):
                    problems.append(f"field_exercise.{key} is required")
            edge = exercise.get("edge")
            if isinstance(edge, Mapping):
                if not isinstance(edge.get("commit"), str) or not _COMMIT.match(edge["commit"]):
                    problems.append("field_exercise.edge.commit must be a full 40-hex commit")
                if not edge.get("authority_path_ref"):
                    problems.append("field_exercise.edge.authority_path_ref is required")
        if isinstance(config, Mapping) and config.get("lab_backend") == VIRTUAL_LAB_BACKEND:
            problems.append("a hil record cannot come from the virtual-lab backend")

    return problems
