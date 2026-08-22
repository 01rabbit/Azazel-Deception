"""Cross-repo interop: AZ-06 consumes Fabric's published golden decision vectors.

Fabric#9 "cross-repository fixture tests": the AZ-06 TransitionExecutor must
accept/reject Fabric's shipped canonical golden decisions exactly per their
scenario, proving the producer (Edge) / contract (Fabric) / consumer (AZ-06)
chain agrees against one shared set of vectors. Skipped when the installed
Fabric predates the golden vectors (they land in Fabric#9 / >= 0.8.0), so this
stays green on the current pinned Fabric and activates once it is bumped.
"""

from __future__ import annotations

import pytest

_testing = pytest.importorskip("azazel_fabric.testing")
if not hasattr(_testing, "load_golden_decision"):  # Fabric < 0.8.0
    pytest.skip(
        "requires azazel_fabric >= 0.8.0 golden decision vectors",
        allow_module_level=True,
    )

from azazel_fabric.testing import (  # noqa: E402
    GOLDEN_DECISION_SIGNATURE_KEY,
    load_golden_decision,
    make_transition_catalog,
)

from azazel_deception.runtime.compose import RuntimeGateError  # noqa: E402
from azazel_deception.runtime.state import RuntimeStateStore  # noqa: E402
from azazel_deception.runtime.transitions import TransitionExecutor  # noqa: E402
from azazel_deception.runtime.transport import HmacDecisionAuthenticator  # noqa: E402

AS_OF = "2026-08-21T00:00:00+00:00"  # within the golden decisions' [effective, expires)


def _strict(tmp_path) -> TransitionExecutor:
    return TransitionExecutor.strict(
        make_transition_catalog(),
        decision_authenticator=HmacDecisionAuthenticator(GOLDEN_DECISION_SIGNATURE_KEY),
        state=RuntimeStateStore(tmp_path),
    )


def test_fabric_golden_signed_decision_drives_executor(tmp_path):
    signed = load_golden_decision("decision_signed_valid")
    result = _strict(tmp_path).execute(
        environment_id="env-1", current_state="baseline",
        transition_id="open-smb-share", edge_decision=signed, as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"
    assert result["edge_decision_id"] == signed["decision_id"]


def test_fabric_golden_tampered_decision_is_rejected(tmp_path):
    tampered = load_golden_decision("decision_signature_tampered")
    with pytest.raises(RuntimeGateError, match="authentication"):
        _strict(tmp_path).execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=tampered, as_of=AS_OF,
        )


def test_fabric_golden_unsupported_schema_is_rejected(tmp_path):
    bad = load_golden_decision("transition_unsupported_schema")
    # Unsigned + wrong schema: strict posture requires authentication first, so
    # it fails closed regardless -- the point is AZ-06 never accepts it.
    with pytest.raises(RuntimeGateError):
        _strict(tmp_path).execute(
            environment_id="env-1", current_state="baseline",
            transition_id="open-smb-share", edge_decision=bad, as_of=AS_OF,
        )
