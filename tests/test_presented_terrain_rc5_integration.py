"""Presented Terrain の `v0.9.0rc5` 統合テスト（Deception#31 で約束したもの）。

#31 の最後のコメントは、Fabric#51 のリリース後に「success と ref/trace/分類の
取り違え拒否を含む integration test」を追加すると約束した。`v0.9.0rc5` の採用
（Deception#51）では、個々の部品のテストは `test_effect_contracts_producer.py`
に入った。本ファイルが固定するのは、部品をつないだ一本の経路である。

    Edge の effect payload
    → accept_defensive_effect_ref（境界での受理。shadow は受理されず束縛のみ）
    → ProducerRedirectionEvidence（観測された redirection のみ）
    → PresentedTerrainSnapshotV0
    → project_presented_terrain（source_effect で effect と trace に束縛）
    → JSON へ直列化 → Fabric の PresentedTerrainRef として再検証
    → assert_effect_chain_consistent / observe_effect

取り違えの拒否は三種類を経路の上で確かめる。

* ref: 別の effect・別の decision に束縛された terrain は連鎖しない。
* trace: 別 incident の trace は射影前にも、射影後の連鎖検査でも拒否される。
* 分類: identity の参照を credential の欄へ、credential の参照を identity の欄へ
  入れたものは、レコードができる前に拒否される。直列化後に欄を入れ替えた
  レコードも Fabric が受理しない。

本ファイルは何かを決定・承認・実行する経路を追加しない。成功ケースが示すのは
「連鎖が整合している」ことだけであり、DIVERT・欺瞞の成功・攻撃者の信念を
主張しない。
"""

from __future__ import annotations

import json

import pytest
from azazel_fabric.effect_contracts import (
    AuthorityClass,
    DefensiveEffectRef,
    EffectClass,
    PresentedTerrainRef,
    assert_effect_chain_consistent,
)
from pydantic import ValidationError

from azazel_deception.runtime.effect_projection import (
    EffectProjectionRefused,
    EffectRefRejected,
    accept_defensive_effect_ref,
    observe_effect,
    project_presented_terrain,
)
from azazel_deception.runtime.presented_terrain import (
    ProducerRedirectionEvidence,
    build_presented_terrain_snapshot,
)

IDENTITY = "identity:finance:clerk-1"
CREDENTIAL = "credential:smb:clerk-1"


def _edge_payload(**overrides) -> dict:
    """Edge が直列化して渡す effect。AZ-06 はこれを受理するだけで、選ばない。"""

    data = {
        "effect_id": "effect:e1",
        "effect_class": EffectClass.REDIRECT_TO_PRESENTED_TERRAIN.value,
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "target_scope_ref": "scope:s1",
        "policy_ref": "policy-1",
        "created_at": "2026-08-26T00:00:00+00:00",
        "expires_at": "2026-08-26T01:00:00+00:00",
        "authority_class": AuthorityClass.PRODUCER_DECISION_REF.value,
        "decision_ref": "decision-1",
    }
    data.update(overrides)
    return json.loads(json.dumps(data))


def _shadow_payload(**overrides) -> dict:
    data = _edge_payload(authority_class=AuthorityClass.PLANNED_SHADOW.value)
    data.pop("decision_ref")
    data.update(overrides)
    return data


def _receive(payload: dict) -> DefensiveEffectRef:
    """Edge の effect を受け取る。decision のある effect だけが受理を通る。

    shadow の effect は `accept_defensive_effect_ref` が実体化を拒否する
    （束縛は受理ではない）。束縛に使うのは Fabric の契約として読んだ値である。
    """

    if payload.get("decision_ref") is None:
        with pytest.raises(EffectRefRejected, match="shadow run"):
            accept_defensive_effect_ref(payload)
        return DefensiveEffectRef.model_validate(payload)
    return accept_defensive_effect_ref(payload)


def _producer_for(effect: DefensiveEffectRef, **overrides) -> ProducerRedirectionEvidence:
    """effect と同じ trace・decision を持つ、観測された redirection。"""

    data = {
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": effect.trace_id,
        "decision_ref": effect.decision_ref or "decision-1",
        "execution_ref": "execution-1",
        "mechanism_observation_ref": "mechanism-1",
        "evidence_refs": ["edge-nft-1"],
    }
    data.update(overrides)
    return ProducerRedirectionEvidence(**data)


def _snapshot(producer: ProducerRedirectionEvidence, *, live: bool = True, **overrides):
    data = {
        "environment_id": "env-1",
        "producer": producer,
        "runtime_state": {
            "environment_id": "env-1",
            "state": "active",
            "package_id": "municipal-linux-v1",
            "package_digest": "sha256:abc123",
            "node_id": "deception-node-1",
            "activated_at": "2026-08-26T00:00:00+00:00",
        },
        "expected_package_id": "municipal-linux-v1",
        "expected_package_digest": "sha256:abc123",
        "package_version": "1.0.0",
        "observed_at": "2026-08-26T00:00:02+00:00",
        "active_surface_refs": ("surface:http:8080",) if live else (),
        "isolation_assertion_refs": ("isolation-net-none",),
        "runtime_verified_active": live,
        "evidence_refs": ("runtime-inspect-1",),
        "expires_at": "2026-08-26T01:00:00+00:00",
        "synthetic_identity_refs": (IDENTITY,),
        "synthetic_credential_refs": (CREDENTIAL,),
    }
    data.update(overrides)
    return build_presented_terrain_snapshot(**data)


def _roundtrip(ref: PresentedTerrainRef) -> PresentedTerrainRef:
    """消費者が受け取る形（JSON）を経て、Fabric の契約として再検証する。"""

    return PresentedTerrainRef.model_validate(json.loads(ref.model_dump_json()))


# --------------------------------------------------------------------------
# success
# --------------------------------------------------------------------------


def test_a_decided_effect_travels_the_whole_path_and_chains():
    effect = accept_defensive_effect_ref(_edge_payload())
    snapshot = _snapshot(_producer_for(effect))

    projected = project_presented_terrain(
        snapshot, presentation_version=0, source_effect=effect
    )
    terrain = _roundtrip(projected.ref)

    assert terrain == projected.ref
    assert terrain.trace_id == effect.trace_id == "trace-1"
    assert terrain.source_effect_ref == effect.effect_id
    assert terrain.activation_decision_ref == effect.decision_ref
    assert terrain.synthetic_identity_refs == (IDENTITY,)
    assert terrain.synthetic_credential_refs == (CREDENTIAL,)
    assert terrain.authority_class is AuthorityClass.ACTIVE_MATERIALIZED

    observation = observe_effect(
        effect, status="active", observed_at="2026-08-26T00:05:00+00:00"
    )
    assert_effect_chain_consistent(effect, terrain=terrain, observations=[observation])


def test_a_shadow_effect_travels_the_whole_path_without_inventing_a_decision():
    """既定の shadow mode。decision は作られず、live activation とも称さない。"""

    effect = _receive(_shadow_payload())
    assert effect.decision_ref is None
    snapshot = _snapshot(_producer_for(effect), live=False)
    assert snapshot.lifecycle_state == "stale"

    terrain = _roundtrip(
        project_presented_terrain(
            snapshot, presentation_version=0, source_effect=effect
        ).ref
    )

    assert terrain.activation_decision_ref is None
    assert terrain.source_effect_ref == effect.effect_id
    assert terrain.trace_id == effect.trace_id
    assert terrain.authority_class is AuthorityClass.PLANNED_SHADOW
    assert terrain.active_surface_refs == ()
    assert_effect_chain_consistent(effect, terrain=terrain)


# --------------------------------------------------------------------------
# ref の取り違え
# --------------------------------------------------------------------------


def test_a_terrain_bound_to_one_effect_does_not_chain_to_another():
    effect = accept_defensive_effect_ref(_edge_payload())
    other = accept_defensive_effect_ref(_edge_payload(effect_id="effect:e2"))
    terrain = _roundtrip(
        project_presented_terrain(
            _snapshot(_producer_for(effect)), presentation_version=0, source_effect=effect
        ).ref
    )

    with pytest.raises(ValueError, match="different effect"):
        assert_effect_chain_consistent(other, terrain=terrain)


def test_an_observed_redirection_of_another_decision_cannot_be_bound():
    effect = accept_defensive_effect_ref(_edge_payload())
    snapshot = _snapshot(_producer_for(effect, decision_ref="decision-9"))

    with pytest.raises(EffectRefRejected, match="different decision"):
        project_presented_terrain(snapshot, presentation_version=0, source_effect=effect)


# --------------------------------------------------------------------------
# trace の取り違え
# --------------------------------------------------------------------------


@pytest.mark.parametrize("payload", [_edge_payload, _shadow_payload])
def test_another_incidents_trace_is_refused_before_a_record_exists(payload):
    effect = _receive(payload())
    live = effect.decision_ref is not None
    snapshot = _snapshot(_producer_for(effect, trace_id="trace-2"), live=live)

    with pytest.raises(EffectRefRejected, match="different trace"):
        project_presented_terrain(snapshot, presentation_version=0, source_effect=effect)


def test_a_record_rewritten_to_another_trace_does_not_chain():
    """射影後に trace だけ書き換えたレコードは、Fabric を通っても連鎖しない。"""

    effect = accept_defensive_effect_ref(_edge_payload())
    terrain = project_presented_terrain(
        _snapshot(_producer_for(effect)), presentation_version=0, source_effect=effect
    ).ref
    rewritten = json.loads(terrain.model_dump_json())
    rewritten["trace_id"] = "trace-2"

    with pytest.raises(ValueError, match="different trace"):
        assert_effect_chain_consistent(
            effect, terrain=PresentedTerrainRef.model_validate(rewritten)
        )


# --------------------------------------------------------------------------
# 分類の取り違え（identity と credential）
# --------------------------------------------------------------------------


def test_a_credential_ref_in_the_identity_slot_is_refused_before_a_record_exists():
    """スナップショットは identity 欄の種別を問わないため、射影が最後の関門になる。"""

    effect = accept_defensive_effect_ref(_edge_payload())
    snapshot = _snapshot(
        _producer_for(effect), synthetic_identity_refs=(CREDENTIAL,)
    )

    with pytest.raises(EffectProjectionRefused, match="'identity' reference") as exc:
        project_presented_terrain(snapshot, presentation_version=0, source_effect=effect)
    assert CREDENTIAL in str(exc.value)


def test_an_identity_ref_in_the_credential_slot_is_refused_where_it_enters():
    effect = accept_defensive_effect_ref(_edge_payload())

    with pytest.raises(ValueError, match="synthetic_credential_ref"):
        _snapshot(_producer_for(effect), synthetic_credential_refs=(IDENTITY,))


def test_a_serialized_record_with_swapped_slots_is_not_a_fabric_record():
    """AZ-06 の外で欄が入れ替えられても、Fabric の契約が受理しない。"""

    effect = accept_defensive_effect_ref(_edge_payload())
    terrain = project_presented_terrain(
        _snapshot(_producer_for(effect)), presentation_version=0, source_effect=effect
    ).ref
    swapped = json.loads(terrain.model_dump_json())
    swapped["synthetic_identity_refs"], swapped["synthetic_credential_refs"] = (
        swapped["synthetic_credential_refs"],
        swapped["synthetic_identity_refs"],
    )

    with pytest.raises(ValidationError):
        PresentedTerrainRef.model_validate(swapped)
