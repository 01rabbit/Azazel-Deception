from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest
from azazel_fabric.deception_contracts import NarrativeConsistencyReport

from azazel_deception.narrative import (
    NarrativeContradiction,
    assert_narrative_consistent,
    check_narrative_consistency,
)


def _coherent_package() -> dict:
    """A synthetic, internally-coherent environment/narrative profile."""

    return {
        "package_id": "municipal-linux-v1",
        "narrative": {
            "narrative_id": "municipal-public-health-v1",
            "purpose": "reference static municipal-office Linux decoy",
            "environment_profile_id": "municipal-public-health",
            "synthetic_only": True,
            "locale": "ja-JP",
            "timezone": "Asia/Tokyo",
            "engage_objective": "collect",
            "engage_approach": "channel",
            "engage_activities": ["expose_allowlisted_decoy", "record_interaction"],
        },
        "environment": {
            "hostname": "muni-web01",
            "organization": "City of Springfield",
            "department": "Public Health",
            "os_family": "linux",
            "os_generation": "ubuntu-22.04",
            "operational_calendar": {"working_days": ["mon", "tue", "wed", "thu", "fri"]},
        },
        "services": [
            {"component_id": "intranet-web", "banner": "Apache/2.4.41 (Ubuntu)"},
        ],
        "accounts": [
            {
                "account_id": "svc-web",
                "hostname": "muni-web01",
                "department": "Public Health",
                "organization": "City of Springfield",
            },
        ],
        "personas": [
            {
                "persona_id": "p-clerk",
                "role": "clerk",
                "department": "Public Health",
                "organization": "City of Springfield",
                "schedule": {"days": ["mon", "tue", "wed", "thu", "fri"], "hours": [9, 17]},
                "activities": ["file_records", "answer_phones"],
            },
        ],
        "files": [
            {
                "path": "/srv/public-health/records/intake.docx",
                "author_persona_id": "p-clerk",
                "owner_persona_id": "p-clerk",
                "department": "Public Health",
                "created_at": "2024-01-10T09:00:00+09:00",
                "modified_at": "2024-01-10T10:00:00+09:00",
                "revision": 1,
            },
        ],
        "credentials": [
            {
                "credential_id": "cred-1",
                "owner_persona_id": "p-clerk",
                "source_artifact_path": "/srv/public-health/records/intake.docx",
                "target_surface_id": "intranet-web",
                "scope": "read",
                "expires_at": "2099-01-01T00:00:00+09:00",
            },
        ],
    }


def test_coherent_narrative_passes_with_no_fatal_findings():
    report = check_narrative_consistency(_coherent_package())
    assert report.fatal_contradictions == []
    assert report.activatable is True
    assert_narrative_consistent(_coherent_package())  # must not raise


def test_report_validates_as_the_fabric_model():
    report = check_narrative_consistency(_coherent_package())
    assert isinstance(report, NarrativeConsistencyReport)
    # Round-trips cleanly through the Fabric model's own (extra="forbid")
    # validation -- i.e. the shape we return is exactly the contract shape.
    round_tripped = NarrativeConsistencyReport.model_validate(report.model_dump())
    assert round_tripped == report


def test_os_service_generation_and_banner_contradiction_is_fatal():
    package = _coherent_package()
    # Environment is declared linux, but the service banner now names a
    # Windows product -- a service-generation/banner contradiction.
    package["services"][0]["banner"] = "Microsoft-IIS/10.0"
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("os_service_generation/banner-family-mismatch" in f for f in report.fatal_contradictions)


def test_naming_coherence_contradiction_is_fatal():
    package = _coherent_package()
    package["accounts"][0]["hostname"] = "totally-different-host"
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("naming_coherence/account-hostname-mismatch" in f for f in report.fatal_contradictions)


def test_chronology_locale_timezone_contradiction_is_fatal():
    package = _coherent_package()
    # ja-JP paired with an America/* zone is internally incoherent.
    package["narrative"]["timezone"] = "America/New_York"
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("chronology_locale_timezone/locale-timezone-mismatch" in f for f in report.fatal_contradictions)


def test_file_relationship_contradiction_is_fatal():
    package = _coherent_package()
    package["files"][0]["author_persona_id"] = "p-ghost"
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("file_relationships/unknown-author" in f for f in report.fatal_contradictions)


def test_persona_role_activity_contradiction_is_fatal():
    package = _coherent_package()
    package["personas"][0]["role"] = "guest"
    package["personas"][0]["activities"] = ["file_records", "rotate_credentials"]
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("persona_relationships/role-activity-contradiction" in f for f in report.fatal_contradictions)


def test_credential_relationship_contradiction_is_fatal():
    package = _coherent_package()
    package["credentials"][0]["target_surface_id"] = "phantom-surface"
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("credential_relationships/unknown-target-surface" in f for f in report.fatal_contradictions)


def test_fatal_report_raises_narrative_contradiction():
    package = _coherent_package()
    package["credentials"][0]["target_surface_id"] = "phantom-surface"
    with pytest.raises(NarrativeContradiction):
        assert_narrative_consistent(package)


def test_determinism_identical_input_yields_identical_report():
    package = _coherent_package()
    package["services"][0]["banner"] = "Microsoft-IIS/10.0"  # exercise a fatal + report both fatal/warning lists
    snapshot = copy.deepcopy(package)

    first = check_narrative_consistency(copy.deepcopy(package))
    second = check_narrative_consistency(copy.deepcopy(package))

    assert first == second
    assert first.model_dump() == second.model_dump()
    # The function must not mutate its input.
    assert package == snapshot


def test_determinism_is_insensitive_to_list_ordering():
    package = _coherent_package()
    package["personas"].append(
        {
            "persona_id": "p-manager",
            "role": "manager",
            "department": "Public Health",
            "organization": "City of Springfield",
            "schedule": {"days": ["mon", "tue", "wed", "thu", "fri"], "hours": [8, 18]},
            "activities": ["approve_records"],
        }
    )
    package["files"][0]["owner_persona_id"] = "p-manager"
    package["credentials"].append(
        {
            "credential_id": "cred-2",
            "owner_persona_id": "p-manager",
            "source_artifact_path": "/srv/public-health/records/intake.docx",
            "target_surface_id": "intranet-web",
            "scope": "read",
            "expires_at": "2099-01-01T00:00:00+09:00",
        }
    )

    reordered = copy.deepcopy(package)
    reordered["personas"] = list(reversed(reordered["personas"]))
    reordered["credentials"] = list(reversed(reordered["credentials"]))

    report_a = check_narrative_consistency(package)
    report_b = check_narrative_consistency(reordered)

    assert report_a == report_b


def test_credential_freshness_uses_explicit_reference_time_only():
    package = _coherent_package()
    package["credentials"][0]["expires_at"] = "2020-01-01T00:00:00+00:00"

    # No reference_time supplied: this module must never sample the wall
    # clock, so an already-past expiry produces no freshness finding at all.
    report_no_reference = check_narrative_consistency(package)
    assert not any("credential-already-expired" in w for w in report_no_reference.warnings)

    reference_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
    report_with_reference = check_narrative_consistency(package, reference_time=reference_time)
    assert any("credential_relationships/credential-already-expired" in w for w in report_with_reference.warnings)
    # Expiry freshness is a warning, not a fatal narrative contradiction.
    assert report_with_reference.activatable is True


def test_unknown_os_generation_fails_closed():
    package = _coherent_package()
    package["environment"]["os_generation"] = "totally-unknown-os-9000"
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("os_service_generation/unknown-os-generation" in f for f in report.fatal_contradictions)


# -- adversarial-review regressions -----------------------------------------


def test_mixed_naive_and_aware_timestamps_do_not_raise():
    # created_at is tz-aware, modified_at is naive: comparing them must report
    # (or not) a contradiction, never raise a naive/aware TypeError.
    package = _coherent_package()
    package["files"][0]["created_at"] = "2024-01-10T09:00:00+09:00"
    package["files"][0]["modified_at"] = "2024-01-10T00:30:00"  # naive, == 09:30 JST
    report = check_narrative_consistency(package)  # must not raise
    # 00:30Z == 09:30 JST is after 09:00 JST, so no reversed-chronology fatal.
    assert not any("reversed-file-chronology" in f for f in report.fatal_contradictions)


def test_naive_reference_time_against_aware_expiry_does_not_raise():
    package = _coherent_package()
    package["credentials"][0]["expires_at"] = "2020-01-01T00:00:00+09:00"  # aware, past
    naive_reference = datetime(2026, 1, 1, 0, 0, 0)  # naive
    report = check_narrative_consistency(package, reference_time=naive_reference)  # no raise
    # Expiry is in the past relative to the reference: reported as a warning,
    # and crucially the comparison did not raise a naive/aware TypeError.
    assert any("credential-already-expired" in f for f in report.warnings)


def test_miscased_os_family_still_catches_banner_mismatch():
    # A capitalized os_family must not silently disable the banner-family check.
    package = _coherent_package()
    del package["environment"]["os_generation"]
    package["environment"]["os_family"] = "Linux"  # note the capital L
    package["services"][0]["banner"] = "Microsoft-IIS/10.0"
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("banner-family-mismatch" in f for f in report.fatal_contradictions)


def test_unknown_os_family_without_generation_fails_closed():
    package = _coherent_package()
    del package["environment"]["os_generation"]
    package["environment"]["os_family"] = "plan9"
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("os_service_generation/unknown-os-family" in f for f in report.fatal_contradictions)


def test_non_integral_float_revision_is_rejected():
    package = _coherent_package()
    package["files"][0]["revision"] = 2.5
    report = check_narrative_consistency(package)
    assert not report.activatable
    assert any("file_relationships/invalid-revision" in f for f in report.fatal_contradictions)


def test_integral_float_revision_is_accepted():
    package = _coherent_package()
    package["files"][0]["revision"] = 3.0
    report = check_narrative_consistency(package)
    assert not any("invalid-revision" in f for f in report.fatal_contradictions)
