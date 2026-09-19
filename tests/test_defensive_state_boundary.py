"""Deception#28: AZ-06's lifecycle is not the producer's Defensive State.

    **Deception materializes an approved engagement; it does not decide the
    producer's Defensive State.**

The separation is already how this repository is built -- `lifecycle_state`
and `producer_decision_ref` are different fields, and activation runs off a
signed one-shot Edge decision. What was missing is the part that makes it stay
that way: nothing mechanically prevented a future change from teaching AZ-06
the five canonical values, accepting `REDIRECT` as a lifecycle state, or
letting a reported state prolong an environment.

That gap is the shape this program keeps finding -- a claim written down and
not enforced -- so these tests enforce it rather than restate it.
"""

from __future__ import annotations

import ast
import inspect
import pkgutil
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

import azazel_deception
from azazel_deception.runtime.presented_terrain import PresentedTerrainSnapshotV0

SRC_ROOT = Path(azazel_deception.__file__).resolve().parent

#: The canonical Edge/Gadget vocabulary (Azazel-Fabric#14). Written here as the
#: thing AZ-06 must NOT contain, which is the only reason this file may name it.
CANONICAL_DEFENSIVE_STATES = frozenset(
    {"OBSERVE", "NOTIFY", "THROTTLE", "REDIRECT", "ISOLATE"}
)

#: AZ-06's own lifecycle namespace. A separate vocabulary, by design.
AZ06_LIFECYCLE_STATES = frozenset(
    {"active", "terminated", "reset", "failed", "stale"}
)


def _python_sources() -> list[Path]:
    # `__main__.py` runs the CLI at import time, so it is swept as text (below)
    # but never imported by the model walk.
    return sorted(SRC_ROOT.rglob("*.py"))


def _code_string_literals(path: Path) -> list[str]:
    """Every string literal in a module except its docstrings.

    Parsed rather than grepped: a module may legitimately *discuss* the
    canonical vocabulary in prose -- this file does -- and a text search cannot
    tell an explanation from a definition.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc is not None:
                docstrings.add(doc)
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]


def _all_models() -> list[type[BaseModel]]:
    models: dict[str, type[BaseModel]] = {}
    for info in pkgutil.walk_packages([str(SRC_ROOT)], prefix="azazel_deception."):
        if info.name.endswith("__main__"):
            continue  # importing it runs the CLI
        try:
            module = __import__(info.name, fromlist=["_"])
        except Exception:  # noqa: BLE001 -- a module that will not import is another test's problem
            continue
        for name, obj in vars(module).items():
            if inspect.isclass(obj) and issubclass(obj, BaseModel) and obj is not BaseModel:
                models[f"{obj.__module__}.{obj.__name__}"] = obj
    return sorted(models.values(), key=lambda m: f"{m.__module__}.{m.__name__}")


@pytest.fixture
def terrain_fields() -> dict:
    """A minimal valid `PresentedTerrainSnapshotV0` payload.

    Built from the model's own required fields rather than copied from another
    test, so a schema change surfaces here as a construction error instead of
    quietly making these assertions test a stale shape.
    """

    return {
        "presentation_id": "presentation-1",
        "environment_id": "env-1",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "producer_decision_ref": "decision-1",
        "producer_execution_ref": "execution-1",
        "producer_mechanism_ref": "mechanism-1",
        "package_id": "municipal-linux-v1",
        "package_version": "0.2.0",
        "package_digest": "sha256:" + "a" * 64,
        "runtime_node_id": "deception-node-1",
        "lifecycle_state": "active",
        # An `active` presentation must carry surface and isolation evidence;
        # the model refuses one that claims to be live without it.
        "active_surface_refs": ("deception:surface:http-8080",),
        "isolation_assertion_refs": ("deception:isolation:1",),
        "started_at": "2026-08-26T00:00:00+00:00",
        "observed_at": "2026-08-26T00:05:00+00:00",
    }


# -- AC-1 / AC-2: the two vocabularies stay distinct ------------------------


def test_the_sweep_actually_finds_this_package():
    """Guard the guard: an empty sweep would make every test below vacuous."""
    sources = _python_sources()
    assert len(sources) >= 20, f"only found {len(sources)} source files under {SRC_ROOT}"
    assert len(_all_models()) >= 5, "the model sweep found almost nothing"


def test_az06_defines_no_defensive_state_vocabulary():
    """AZ-06 never learns the producer's words.

    A copy of the vocabulary here would be a second place that defines it, and
    the first thing a consumer would do with it is compare an AZ-06 value to an
    Edge one -- which is the merge this boundary exists to prevent.
    """

    offenders: list[str] = []
    for path in _python_sources():
        for literal in _code_string_literals(path):
            if literal in CANONICAL_DEFENSIVE_STATES:
                offenders.append(f"{path.relative_to(SRC_ROOT)}: {literal!r}")
    assert offenders == [], (
        "the canonical Defensive State vocabulary appears in AZ-06 code: "
        f"{offenders}. It belongs to Edge/Gadget (Azazel-Fabric#14)"
    )


def test_no_lifecycle_value_collides_with_a_defensive_state():
    upper = {value.upper() for value in AZ06_LIFECYCLE_STATES}
    assert upper & CANONICAL_DEFENSIVE_STATES == set()


@pytest.mark.parametrize("state", sorted(CANONICAL_DEFENSIVE_STATES))
def test_a_defensive_state_is_refused_where_a_lifecycle_state_belongs(state, terrain_fields):
    """`REDIRECT` alone is not an AZ-06 lifecycle state (AC-2)."""
    with pytest.raises(ValidationError):
        PresentedTerrainSnapshotV0(**{**terrain_fields, "lifecycle_state": state})


def test_the_lifecycle_namespace_is_what_this_test_thinks_it_is():
    """Pin the lifecycle vocabulary by name.

    Without this, the test above would keep passing if the lifecycle enum were
    widened to include a Defensive State value under a different spelling.
    """

    annotation = PresentedTerrainSnapshotV0.model_fields["lifecycle_state"].annotation
    from typing import get_args

    assert set(get_args(annotation)) == AZ06_LIFECYCLE_STATES


# -- AC-3: AZ-06 cannot set the producer's Defensive State ------------------


def test_az06_exposes_no_function_that_sets_a_producer_state():
    """Stated as a test because the invariant is an absence."""
    offenders: list[str] = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                low = node.name.lower()
                if "defensive_state" in low or "set_producer_state" in low:
                    offenders.append(f"{path.relative_to(SRC_ROOT)}: {node.name}")
    assert offenders == [], f"AZ-06 grew a producer-state function: {offenders}"


def test_the_presentation_fact_is_not_executable_and_says_whose_claim_it_is(terrain_fields):
    fact = PresentedTerrainSnapshotV0(**terrain_fields)

    assert fact.executable is False
    assert fact.authority_class == "deception_presentation_fact"
    with pytest.raises(ValidationError):
        PresentedTerrainSnapshotV0(**{**terrain_fields, "executable": True})
    with pytest.raises(ValidationError):
        PresentedTerrainSnapshotV0(**{**terrain_fields, "authority_class": "producer_decision_ref"})


# -- AC-5: audit correlates the two without merging them --------------------


def test_the_producers_decision_and_az06s_lifecycle_are_separate_fields(terrain_fields):
    """Correlation without merging: both refs survive onto the same fact, and
    neither is derived from the other."""
    fact = PresentedTerrainSnapshotV0(**terrain_fields)

    assert fact.producer_decision_ref == terrain_fields["producer_decision_ref"]
    assert fact.lifecycle_state == terrain_fields["lifecycle_state"]
    assert fact.producer_decision_ref != fact.lifecycle_state

    exported = fact.model_dump(mode="json")
    assert "producer_decision_ref" in exported
    assert "lifecycle_state" in exported


def test_no_model_carries_a_field_that_merges_the_two_namespaces():
    """A single field naming both concepts is how they get conflated."""
    offenders: list[str] = []
    for model in _all_models():
        for field in model.model_fields:
            low = field.lower()
            if "defensive_state" in low:
                offenders.append(f"{model.__module__}.{model.__name__}.{field}")
    assert offenders == [], f"a Defensive State field appeared on an AZ-06 model: {offenders}"


# -- AC-6: no ambiguous generic `mode` --------------------------------------


def test_no_model_exposes_an_ambiguous_mode_field():
    """`mode` is the word that gets confused with Edge/Gadget Defensive State."""
    offenders: list[str] = []
    for model in _all_models():
        for field in model.model_fields:
            if field.lower() in {"mode", "state"}:
                offenders.append(f"{model.__module__}.{model.__name__}.{field}")
    assert offenders == [], (
        f"ambiguous state field(s): {offenders}. Name the namespace -- "
        "`lifecycle_state` for AZ-06's own, and nothing for the producer's"
    )


# -- the behavioural question the issue asks (work item 5/6) ----------------


def test_a_reported_producer_state_is_not_an_input_to_activation():
    """The issue asks what happens when producer state leaves `REDIRECT` while
    an environment is active. The answer is *nothing, by itself*.

    A reported state is not an activation, transition, or termination input
    anywhere in AZ-06: the runtime acts on signed, one-shot Edge decisions and
    on the lease it was given. That is why a stale, replayed, or malformed
    producer state cannot activate or prolong an environment -- there is no
    parameter for it to arrive through.

    Asserted structurally, over every public runtime entry point, so adding
    such a parameter fails here rather than in a review nobody runs.
    """

    from azazel_deception.runtime import compose

    offenders: list[str] = []
    for name, obj in vars(compose).items():
        if not inspect.isclass(obj):
            continue
        for method_name, method in vars(obj).items():
            if method_name.startswith("_") or not callable(method):
                continue
            try:
                signature = inspect.signature(method)
            except (TypeError, ValueError):
                continue
            for parameter in signature.parameters:
                low = parameter.lower()
                if "defensive_state" in low or low in {"producer_state", "reported_state"}:
                    offenders.append(f"{name}.{method_name}({parameter})")
    assert offenders == [], (
        f"a producer state became an input to the AZ-06 runtime: {offenders}. "
        "AZ-06 acts on signed decisions and its lease, never on a reported state"
    )


# -- AC-7 is open, and says so ----------------------------------------------


def test_the_fabric_pin_does_not_yet_carry_the_canonical_vocabulary():
    """AC-7 is "adopt Fabric#14 **when compatible**". It is not yet.

    This repository pins `v0.8.0`; `DefensiveState` shipped to no tag. Written
    so it fails once a pin that carries the vocabulary lands -- the moment AC-7
    becomes actionable, and a louder signal than a comment nobody re-reads.
    """

    import tomllib

    manifest = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text("utf-8")
    )
    pins = [d for d in manifest["project"]["dependencies"] if "azazel-fabric" in d]
    assert len(pins) == 1, f"expected exactly one Fabric pin, got {pins}"
    assert "@v" in pins[0], f"Fabric must be pinned to an exact tag, got {pins[0]!r}"

    try:
        from azazel_fabric.schema.defensive_state import DefensiveState  # noqa: F401
    except ImportError:
        return
    pytest.fail(
        f"the pinned Fabric ({pins[0]}) now carries DefensiveState; Deception#28 AC-7 is "
        "actionable -- adopt it for status/audit correlation, keeping the lifecycle "
        "namespace separate, and delete this test"
    )
