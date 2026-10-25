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
  identifier of the shape :data:`COMMISSIONED_IDENTITY_PATTERN` (a positive
  shape, so no kernel interface name can satisfy it), and can only pass when
  *both* halves were measured on every sample with an Edge enforcement event
  named per sample;
* **no record of either class can pass while Edge's withdrawal path is
  undeclared.** :data:`EDGE_WITHDRAWAL_PATH_DECLARED` is ``False`` and, while it
  is, the withdrawal gap naming Azazel-Edge#412 is mandatory and blocking on
  every record. Lifting it is a code change in a future PR, never a record
  field.

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

#: Backends a HIL record may come from. Positive list: anything else is refused.
HIL_BACKENDS = ("field-segment",)

#: Where committed HIL field-exercise records live.
FIELD_EXERCISE_DIR = "docs/field-exercises/so08"

#: The withdrawal gap every record carries until Edge declares its
#: authoritative enforcement path. Withdrawal is enforcement; AZ-06 has no
#: authority to perform it and no stand-in performs it here.
EDGE_WITHDRAWAL_GAP_ID = "SO08-NO-EDGE-WITHDRAWAL-PATH"
EDGE_WITHDRAWAL_GAP_REF = "01rabbit/Azazel-Edge#412"

#: Whether Azazel-Edge has declared the authoritative enforcement path the
#: withdrawal half is measured through. ``False`` until Azazel-Edge#412 lands;
#: while ``False`` the withdrawal gap is mandatory on every record, so no SO-08
#: record can pass. Changing this is a reviewed code change, not a record field.
EDGE_WITHDRAWAL_PATH_DECLARED = False

#: The commissioned composite identifier a HIL record must carry:
#: ``az06-commission:<site>/<node>/<segment>``, each part lower-case
#: alphanumerics and hyphens. A positive shape rather than an interface-name
#: blacklist: ``eth0``, ``ETH0``, ``wwan0``, ``cni0`` … cannot match it, and
#: ordinary site names such as ``lobby-3`` or ``enterprise-site-1`` can.
COMMISSIONED_IDENTITY_PATTERN = re.compile(
    r"^az06-commission:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?"
    r"/[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?"
    r"/[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"
)

#: How a HIL record names the Edge authority path and, per withdrawal sample,
#: the Edge enforcement event that ended exposure.
EDGE_REF_PATTERN = re.compile(r"^01rabbit/Azazel-Edge(?:#[0-9]+|@[0-9a-f]{40}:[^\s]+)$")
EDGE_ENFORCEMENT_EVENT_PATTERN = re.compile(r"^edge-enforcement:[A-Za-z0-9._:/-]{1,200}$")


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


_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def is_commissioned_identity(value: object) -> bool:
    return isinstance(value, str) and bool(COMMISSIONED_IDENTITY_PATTERN.match(value))


def _is_int(value: object) -> bool:
    # bool is an int subclass; True must never stand in for a timestamp.
    return isinstance(value, int) and not isinstance(value, bool)


def evaluate_samples(
    samples: Sequence[Mapping[str, Any]],
    *,
    bound_ms: float,
    start_key: str = "start_monotonic_ns",
    end_key: str = "end_monotonic_ns",
) -> dict[str, Any]:
    """Evaluate the every-sample rule over ``samples``.

    A sample with no integer end time is *unfinished*. Unfinished samples are
    counted as violations: a drift that was never recorded was not detected
    within the bound. ``holds`` is ``False`` for an empty sample set, never
    vacuously true. Booleans are not accepted as times.
    """

    elapsed: list[float] = []
    unfinished = 0
    violations = 0
    for sample in samples:
        start = sample.get(start_key)
        end = sample.get(end_key)
        if not _is_int(start) or not _is_int(end):
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


def _check_samples(name: str, samples: list[Any], executed: bool) -> list[str]:
    """Shape rules every sample list obeys: known kinds, unique ids, 20 per kind."""

    problems: list[str] = []
    ids: list[Any] = []
    counts = {kind: 0 for kind in DRIFT_KINDS}
    for sample in samples:
        if not isinstance(sample, Mapping):
            problems.append(f"{name}: a sample is not a mapping")
            continue
        kind = sample.get("drift_kind")
        if kind not in counts:
            problems.append(f"{name}: sample {sample.get('sample_id')!r} has undeclared "
                            f"drift_kind {kind!r}")
        else:
            counts[kind] += 1
        ids.append(sample.get("sample_id"))
    if any(not isinstance(i, str) or not i for i in ids):
        problems.append(f"{name}: every sample needs a non-empty sample_id")
    if len(set(map(str, ids))) != len(ids):
        problems.append(f"{name}: duplicate sample_id — copies do not count as samples")
    if executed:
        for kind, count in counts.items():
            if count < SAMPLES_PER_KIND:
                problems.append(
                    f"{name} has {count} samples of {kind}; {SAMPLES_PER_KIND} required"
                )
    return problems


def _edge_gap_problems(part: Mapping[str, Any]) -> list[str]:
    gaps = [g for g in part.get("gaps") or [] if isinstance(g, Mapping)]
    edge = [g for g in gaps if g.get("id") == EDGE_WITHDRAWAL_GAP_ID]
    if not edge:
        return [
            f"withdrawal part must carry gap {EDGE_WITHDRAWAL_GAP_ID} while Edge's "
            "withdrawal path is undeclared (Azazel-Edge#412)"
        ]
    problems = []
    if edge[0].get("blocks_verdict") is not True:
        problems.append(f"gap {EDGE_WITHDRAWAL_GAP_ID} must carry blocks_verdict: true")
    if EDGE_WITHDRAWAL_GAP_REF not in (edge[0].get("refs") or []):
        problems.append(f"gap {EDGE_WITHDRAWAL_GAP_ID} must reference {EDGE_WITHDRAWAL_GAP_REF}")
    return problems


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
    backend = config.get("lab_backend") if isinstance(config, Mapping) else None
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

    if not EDGE_WITHDRAWAL_PATH_DECLARED:
        problems.extend(_edge_gap_problems(withdrawal))

    # Recompute each part's verdict from its samples.
    derived: dict[str, str] = {}
    part_samples: dict[str, list[Any]] = {}
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
        part_samples[name] = samples
        problems.extend(_check_samples(name, samples, executed is True))
        gaps = part.get("gaps") or []
        for gap in gaps:
            if not isinstance(gap, Mapping) or not isinstance(gap.get("blocks_verdict"), bool):
                problems.append(f"{name}: every gap needs a boolean blocks_verdict")
        blocking = [g for g in gaps if isinstance(g, Mapping) and g.get("blocks_verdict") is True]
        evaluated = evaluate_samples(
            [s for s in samples if isinstance(s, Mapping)], bound_ms=bound
        )
        if executed is not True or blocking:
            expected = "not_measurable"
        else:
            expected = "pass" if evaluated["holds"] else "fail"
        if executed is True and isinstance(rule, Mapping) and rule.get("evaluated") != evaluated:
            problems.append(f"{name}.pass_rule.evaluated does not match its samples")
        derived[name] = expected
        if part.get("verdict") != expected:
            problems.append(
                f"{name}.verdict is {part.get('verdict')!r}; its samples and gaps give {expected!r}"
            )

    # A finished detection sample must point at the evidence-chain record it read.
    for sample in part_samples["detection"]:
        if isinstance(sample, Mapping) and _is_int(sample.get("end_monotonic_ns")):
            if not sample.get("evidence_event_id") or not _is_int(sample.get("evidence_seq")):
                problems.append(
                    f"detection sample {sample.get('sample_id')!r} has an end time but no "
                    "evidence_event_id / evidence_seq"
                )
    detection_ids = {s.get("sample_id") for s in part_samples["detection"] if isinstance(s, Mapping)}
    withdrawal_ids = {
        s.get("sample_id") for s in part_samples["withdrawal"] if isinstance(s, Mapping)
    }
    if detection_ids != withdrawal_ids:
        problems.append("detection and withdrawal must cover the same injections (sample_id)")

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
        if backend != VIRTUAL_LAB_BACKEND:
            problems.append(f"virtual-lab lab_backend must be {VIRTUAL_LAB_BACKEND!r}")
    elif record_class == CLASS_HIL:
        if record.get("gate") is not True:
            problems.append("a hil-field-exercise record carries gate: true")
        if not is_commissioned_identity(identity):
            problems.append(
                "hil commissioned_identity must be a commissioned composite identifier "
                "az06-commission:<site>/<node>/<segment> (never a kernel interface name)"
            )
        if backend not in HIL_BACKENDS:
            problems.append(f"hil lab_backend must be one of {HIL_BACKENDS}")
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
                if edge.get("repository") != "01rabbit/Azazel-Edge":
                    problems.append("field_exercise.edge.repository must be 01rabbit/Azazel-Edge")
                if not isinstance(edge.get("commit"), str) or not _COMMIT.match(edge["commit"]):
                    problems.append("field_exercise.edge.commit must be a full 40-hex commit")
                ref = edge.get("authority_path_ref")
                if not isinstance(ref, str) or not EDGE_REF_PATTERN.match(ref):
                    problems.append(
                        "field_exercise.edge.authority_path_ref must name an Azazel-Edge "
                        "issue (01rabbit/Azazel-Edge#N) or file at a commit"
                    )
        # Every measured withdrawal must name the Edge enforcement event that
        # ended the exposure: the withdrawal half is Edge's, end-to-end.
        for sample in part_samples["withdrawal"]:
            if isinstance(sample, Mapping) and _is_int(sample.get("end_monotonic_ns")):
                ref = sample.get("edge_enforcement_event_ref")
                if not isinstance(ref, str) or not EDGE_ENFORCEMENT_EVENT_PATTERN.match(ref):
                    problems.append(
                        f"withdrawal sample {sample.get('sample_id')!r} has an end time but no "
                        "edge_enforcement_event_ref"
                    )

    return problems
