"""Deterministic narrative-consistency compiler for AZ-06 environment profiles.

``check_narrative_consistency`` walks one versioned deception-environment /
narrative profile (a plain ``dict``, the shape produced by
``azazel_deception.package`` plus the narrative-detail sections documented
below) and reports internal contradictions as a Fabric
``NarrativeConsistencyReport``.

Doctrine, enforced structurally:

* **Synthetic-only.** This module never contacts a network, filesystem clock,
  or external service; it only reasons about the dict it is handed.
* **Deterministic & replayable.** No ``datetime.now()``, ``time.time()``, or
  ``random`` is used anywhere in a logic path. The one place a "current time"
  could matter (credential freshness) takes it as an explicit
  ``reference_time`` parameter that defaults to ``None`` (freshness check
  skipped) rather than ever sampling the wall clock. Given the same
  ``package`` dict (and the same ``reference_time``), the returned report is
  byte-for-byte identical: findings are rendered to plain strings and sorted
  by a stable key before being split into ``fatal_contradictions`` /
  ``warnings``.
* **No LLM.** Every check below is plain, inspectable Python over small
  static lookup tables.
* **Fail-closed on contradiction/unknown.** A reference that cannot be
  resolved (an unknown OS generation, a credential owner that names no
  declared persona, a malformed timestamp, ...) is treated as a *fatal*
  finding, never silently skipped. Sections that are simply absent from the
  input (e.g. no ``credentials`` declared at all) are not evaluated -- there
  is nothing to contradict -- but any item that *is* present must resolve
  cleanly against the rest of the profile.

Input shape
-----------
``package`` is expected to carry the canonical ``narrative`` mapping shaped
by :mod:`azazel_deception.package` (``narrative_id``, ``purpose``,
``environment_profile_id``, ``synthetic_only``, ``locale``, ``timezone``,
``engage_objective``, ``engage_approach``, ``engage_activities``) alongside
the following optional narrative-detail sections, each a list/dict of plain
``dict`` records (unknown/missing sections are simply not checked):

``environment``
    ``{"hostname", "organization", "department", "os_family",
    "os_generation", "operational_calendar": {"working_days": [...]}}``

``services``
    ``[{"component_id", "banner", "os_generation"?}]`` -- ``os_generation``
    is optional and, when present, must match ``environment.os_generation``.

``accounts``
    ``[{"account_id", "hostname"?, "department"?, "organization"?}]``

``personas``
    ``[{"persona_id", "role", "department"?, "organization"?,
    "schedule": {"days": [...], "hours": [start, end]}, "activities": [...]}]``

``files``
    ``[{"path", "author_persona_id"?, "owner_persona_id"?, "department"?,
    "created_at", "modified_at", "revision"}]`` -- timestamps are ISO-8601
    strings.

``credentials``
    ``[{"credential_id", "owner_persona_id", "source_artifact_path"?,
    "target_surface_id"?, "scope"?, "expires_at"}]``

``report_id`` (optional) overrides the derived report id.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Literal

from azazel_fabric.deception_contracts import NarrativeConsistencyReport

__all__ = [
    "Finding",
    "NarrativeContradiction",
    "check_narrative_consistency",
    "assert_narrative_consistent",
]

Severity = Literal["fatal", "warning"]


class NarrativeContradiction(ValueError):
    """Raised by :func:`assert_narrative_consistent` on a fatal finding.

    ``check_narrative_consistency`` itself never raises for narrative
    contradictions -- it always returns a (possibly unusable, i.e.
    ``activatable is False``) report so callers can inspect every finding.
    This exception is available for callers that want fail-closed
    all-or-nothing behavior instead.
    """


@dataclass(frozen=True, order=True)
class Finding:
    """One contradiction/observation, sortable for deterministic output."""

    dimension: str
    code: str
    subject: str
    message: str
    severity: Severity

    def render(self) -> str:
        return f"[{self.dimension}/{self.code}] {self.subject}: {self.message}"


def _fatal(dimension: str, code: str, subject: str, message: str) -> Finding:
    return Finding(dimension=dimension, code=code, subject=subject, message=message, severity="fatal")


def _warn(dimension: str, code: str, subject: str, message: str) -> Finding:
    return Finding(dimension=dimension, code=code, subject=subject, message=message, severity="warning")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise TypeError(f"expected a list, got {type(value).__name__}")


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise TypeError(f"expected a dict, got {type(value).__name__}")


def _parse_iso(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp string. Returns ``None`` if unparseable.

    Never touches the wall clock; purely a string -> datetime conversion.
    """

    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Dimension 1: OS/service generation & banner compatibility
# ---------------------------------------------------------------------------

# Small, static allowlist of synthetic OS generations this compiler knows how
# to reason about. Deliberately not exhaustive: an unrecognized
# ``os_generation`` fails closed (dimension below) rather than being guessed.
_OS_GENERATION_PROFILES: dict[str, dict[str, Any]] = {
    "ubuntu-20.04": {"family": "linux", "tokens": ("ubuntu", "debian", "openssh")},
    "ubuntu-22.04": {"family": "linux", "tokens": ("ubuntu", "debian", "openssh")},
    "debian-11": {"family": "linux", "tokens": ("debian", "openssh")},
    "debian-12": {"family": "linux", "tokens": ("debian", "openssh")},
    "centos-7": {"family": "linux", "tokens": ("centos", "red hat", "rhel", "openssh")},
    "rhel-8": {"family": "linux", "tokens": ("red hat", "rhel", "openssh")},
    "windows-server-2016": {"family": "windows", "tokens": ("windows", "microsoft", "iis")},
    "windows-server-2019": {"family": "windows", "tokens": ("windows", "microsoft", "iis")},
    "windows-server-2022": {"family": "windows", "tokens": ("windows", "microsoft", "iis")},
}

_LINUX_TOKENS = {"ubuntu", "debian", "centos", "red hat", "rhel", "openssh", "linux"}
_WINDOWS_TOKENS = {"windows", "microsoft", "iis", ".net", "win32"}


def check_os_service_generation(environment: dict[str, Any], services: Iterable[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    os_generation = environment.get("os_generation")
    os_family = environment.get("os_family")

    if os_generation is not None:
        profile = _OS_GENERATION_PROFILES.get(os_generation)
        if profile is None:
            # Unknown OS generation: fail closed rather than assume it is fine.
            findings.append(
                _fatal(
                    "os_service_generation",
                    "unknown-os-generation",
                    str(os_generation),
                    "environment.os_generation is not a recognized synthetic OS generation",
                )
            )
        elif os_family is not None and profile["family"] != os_family:
            findings.append(
                _fatal(
                    "os_service_generation",
                    "os-family-generation-mismatch",
                    str(os_generation),
                    f"environment.os_family={os_family!r} contradicts os_generation family {profile['family']!r}",
                )
            )

    profile = _OS_GENERATION_PROFILES.get(os_generation) if os_generation else None
    declared_family = profile["family"] if profile else os_family

    for service in services:
        component_id = str(service.get("component_id") or "<unknown-component>")
        service_generation = service.get("os_generation")
        if service_generation is not None and os_generation is not None and service_generation != os_generation:
            findings.append(
                _fatal(
                    "os_service_generation",
                    "service-generation-mismatch",
                    component_id,
                    f"service declares os_generation={service_generation!r} but environment is {os_generation!r}",
                )
            )

        banner = service.get("banner")
        if not banner:
            findings.append(_warn("os_service_generation", "missing-banner", component_id, "service has no banner declared"))
            continue
        banner_lower = str(banner).lower()
        if declared_family == "linux" and any(token in banner_lower for token in _WINDOWS_TOKENS):
            findings.append(
                _fatal(
                    "os_service_generation",
                    "banner-family-mismatch",
                    component_id,
                    f"banner {banner!r} names a Windows product but the environment family is linux",
                )
            )
        elif declared_family == "windows" and any(token in banner_lower for token in _LINUX_TOKENS):
            findings.append(
                _fatal(
                    "os_service_generation",
                    "banner-family-mismatch",
                    component_id,
                    f"banner {banner!r} names a Linux/Unix product but the environment family is windows",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Dimension 2: hostname/account/department/organization naming coherence
# ---------------------------------------------------------------------------


def check_naming_coherence(
    environment: dict[str, Any],
    accounts: Iterable[dict[str, Any]],
    personas: Iterable[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    env_hostname = environment.get("hostname")
    env_department = environment.get("department")
    env_organization = environment.get("organization")

    for account in accounts:
        account_id = str(account.get("account_id") or "<unknown-account>")
        hostname = account.get("hostname")
        if hostname is not None and env_hostname is not None and hostname != env_hostname:
            findings.append(
                _fatal(
                    "naming_coherence",
                    "account-hostname-mismatch",
                    account_id,
                    f"account hostname {hostname!r} does not match environment hostname {env_hostname!r}",
                )
            )
        department = account.get("department")
        if department is not None and env_department is not None and department != env_department:
            findings.append(
                _fatal(
                    "naming_coherence",
                    "account-department-mismatch",
                    account_id,
                    f"account department {department!r} does not match environment department {env_department!r}",
                )
            )
        organization = account.get("organization")
        if organization is not None and env_organization is not None and organization != env_organization:
            findings.append(
                _fatal(
                    "naming_coherence",
                    "account-organization-mismatch",
                    account_id,
                    f"account organization {organization!r} does not match environment organization {env_organization!r}",
                )
            )

    for persona in personas:
        persona_id = str(persona.get("persona_id") or "<unknown-persona>")
        department = persona.get("department")
        if department is not None and env_department is not None and department != env_department:
            findings.append(
                _fatal(
                    "naming_coherence",
                    "persona-department-mismatch",
                    persona_id,
                    f"persona department {department!r} does not match environment department {env_department!r}",
                )
            )
        organization = persona.get("organization")
        if organization is not None and env_organization is not None and organization != env_organization:
            findings.append(
                _fatal(
                    "naming_coherence",
                    "persona-organization-mismatch",
                    persona_id,
                    f"persona organization {organization!r} does not match environment organization {env_organization!r}",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Dimension 3: chronology/locale/timezone/operational-calendar coherence
# ---------------------------------------------------------------------------

# Minimal, static locale -> expected timezone-region prefix table. This is a
# coherence heuristic for a synthetic narrative, not a real geo/locale
# database: an unlisted locale is simply not checked against timezone.
_LOCALE_TIMEZONE_REGION: dict[str, str] = {
    "ja-JP": "Asia/",
    "en-US": "America/",
    "en-GB": "Europe/",
    "de-DE": "Europe/",
    "fr-FR": "Europe/",
    "pt-BR": "America/",
    "zh-CN": "Asia/",
    "ko-KR": "Asia/",
    "es-ES": "Europe/",
    "en-AU": "Australia/",
}

_VALID_WEEKDAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}


def check_chronology_locale_timezone(
    narrative: dict[str, Any],
    environment: dict[str, Any],
    files: Iterable[dict[str, Any]],
    personas: Iterable[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    locale = narrative.get("locale")
    timezone = narrative.get("timezone")
    if locale is not None and timezone is not None:
        expected_prefix = _LOCALE_TIMEZONE_REGION.get(locale)
        if expected_prefix is not None and not str(timezone).startswith(expected_prefix):
            findings.append(
                _fatal(
                    "chronology_locale_timezone",
                    "locale-timezone-mismatch",
                    str(locale),
                    f"narrative locale {locale!r} is incoherent with timezone {timezone!r} "
                    f"(expected a {expected_prefix}* zone)",
                )
            )

    calendar = _as_dict(environment.get("operational_calendar"))
    working_days = calendar.get("working_days")
    normalized_working_days: set[str] | None = None
    if working_days is not None:
        normalized_working_days = {str(day).lower()[:3] for day in working_days}
        unknown = normalized_working_days - _VALID_WEEKDAYS
        if unknown:
            findings.append(
                _fatal(
                    "chronology_locale_timezone",
                    "unknown-working-day",
                    "operational_calendar",
                    f"operational_calendar.working_days contains unrecognized day tokens: {sorted(unknown)}",
                )
            )

    for file_ in files:
        path = str(file_.get("path") or "<unknown-file>")
        created = _parse_iso(file_.get("created_at"))
        modified = _parse_iso(file_.get("modified_at"))
        if file_.get("created_at") is not None and created is None:
            findings.append(_fatal("chronology_locale_timezone", "unparseable-timestamp", path, "created_at is not a valid ISO-8601 timestamp"))
        if file_.get("modified_at") is not None and modified is None:
            findings.append(_fatal("chronology_locale_timezone", "unparseable-timestamp", path, "modified_at is not a valid ISO-8601 timestamp"))
        if created is not None and modified is not None and modified < created:
            findings.append(
                _fatal(
                    "chronology_locale_timezone",
                    "reversed-file-chronology",
                    path,
                    f"modified_at ({modified.isoformat()}) precedes created_at ({created.isoformat()})",
                )
            )

    if normalized_working_days is not None:
        for persona in personas:
            persona_id = str(persona.get("persona_id") or "<unknown-persona>")
            schedule = _as_dict(persona.get("schedule"))
            days = schedule.get("days")
            if not days:
                continue
            persona_days = {str(day).lower()[:3] for day in days}
            outside = persona_days - _VALID_WEEKDAYS
            if outside:
                findings.append(
                    _fatal(
                        "chronology_locale_timezone",
                        "unknown-persona-day",
                        persona_id,
                        f"persona schedule.days contains unrecognized day tokens: {sorted(outside)}",
                    )
                )
                continue
            if not persona_days & normalized_working_days:
                findings.append(
                    _fatal(
                        "chronology_locale_timezone",
                        "persona-outside-operational-calendar",
                        persona_id,
                        f"persona schedule days {sorted(persona_days)} never overlap the operational "
                        f"calendar's working days {sorted(normalized_working_days)}",
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Dimension 4: file author/owner/timestamp/revision/path relationships
# ---------------------------------------------------------------------------


def check_file_relationships(files: Iterable[dict[str, Any]], persona_ids: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    for file_ in files:
        path = str(file_.get("path") or "<unknown-file>")

        for role in ("author_persona_id", "owner_persona_id"):
            persona_id = file_.get(role)
            if persona_id is not None and persona_id not in persona_ids:
                findings.append(
                    _fatal(
                        "file_relationships",
                        f"unknown-{role.replace('_persona_id', '')}",
                        path,
                        f"{role}={persona_id!r} does not match any declared persona",
                    )
                )

        revision = file_.get("revision")
        if revision is not None:
            try:
                revision_int = int(revision)
            except (TypeError, ValueError):
                findings.append(_fatal("file_relationships", "invalid-revision", path, f"revision {revision!r} is not an integer"))
            else:
                if revision_int < 1:
                    findings.append(_fatal("file_relationships", "invalid-revision", path, f"revision {revision_int} must be >= 1"))

        department = file_.get("department")
        if department is not None and department.strip().lower().replace(" ", "-") not in path.lower().replace(" ", "-"):
            findings.append(
                _warn(
                    "file_relationships",
                    "path-department-mismatch",
                    path,
                    f"file department {department!r} is not reflected in its path",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Dimension 5: persona role/schedule/activity relationships
# ---------------------------------------------------------------------------

# Static allowlist of activities each role may plausibly perform in a
# synthetic decoy narrative. Roles/activities outside this table are simply
# not checked (unknown activity strings are the operator's business); the
# table only rules out *known* incoherent combinations.
_ROLE_FORBIDDEN_ACTIVITIES: dict[str, set[str]] = {
    "guest": {"admin_console_access", "modify_firewall_rules", "rotate_credentials", "deploy_release"},
    "read_only_visitor": {"modify_config", "delete_records", "admin_console_access", "rotate_credentials"},
    "intern": {"rotate_credentials", "deploy_release", "modify_firewall_rules"},
}


def check_persona_relationships(personas: Iterable[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []

    for persona in personas:
        persona_id = str(persona.get("persona_id") or "<unknown-persona>")
        role = persona.get("role")
        activities = _as_list(persona.get("activities"))

        if role is not None:
            forbidden = _ROLE_FORBIDDEN_ACTIVITIES.get(role)
            if forbidden:
                overlap = sorted(set(activities) & forbidden)
                if overlap:
                    findings.append(
                        _fatal(
                            "persona_relationships",
                            "role-activity-contradiction",
                            persona_id,
                            f"role {role!r} is incompatible with declared activities {overlap}",
                        )
                    )

        schedule = persona.get("schedule")
        if schedule is not None:
            schedule = _as_dict(schedule)
            hours = schedule.get("hours")
            if hours is not None:
                if not (isinstance(hours, (list, tuple)) and len(hours) == 2):
                    findings.append(_fatal("persona_relationships", "invalid-schedule-hours", persona_id, f"schedule.hours {hours!r} must be a [start, end] pair"))
                else:
                    start, end = hours
                    valid_bounds = all(isinstance(v, int) and 0 <= v <= 24 for v in (start, end))
                    if not valid_bounds or start >= end:
                        findings.append(
                            _fatal(
                                "persona_relationships",
                                "invalid-schedule-hours",
                                persona_id,
                                f"schedule.hours {hours!r} must satisfy 0 <= start < end <= 24",
                            )
                        )
        elif activities:
            findings.append(
                _warn(
                    "persona_relationships",
                    "activity-without-schedule",
                    persona_id,
                    "persona declares activities but no schedule to anchor them to",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Dimension 6: credential owner/source/target/scope/expiry relationships
# ---------------------------------------------------------------------------

# Static allowlist mirroring the dimension-5 role table: which credential
# scopes a given persona role may plausibly own.
_ROLE_FORBIDDEN_SCOPES: dict[str, set[str]] = {
    "guest": {"admin", "domain_admin", "root"},
    "read_only_visitor": {"admin", "domain_admin", "root", "write"},
    "intern": {"domain_admin", "root"},
}


def check_credential_relationships(
    credentials: Iterable[dict[str, Any]],
    personas_by_id: dict[str, dict[str, Any]],
    file_paths: set[str],
    surface_ids: set[str],
    reference_time: datetime | None,
) -> list[Finding]:
    findings: list[Finding] = []

    for credential in credentials:
        credential_id = str(credential.get("credential_id") or "<unknown-credential>")

        owner_id = credential.get("owner_persona_id")
        owner = personas_by_id.get(owner_id) if owner_id is not None else None
        if owner_id is not None and owner is None:
            findings.append(
                _fatal(
                    "credential_relationships",
                    "unknown-owner",
                    credential_id,
                    f"owner_persona_id={owner_id!r} does not match any declared persona",
                )
            )

        source = credential.get("source_artifact_path")
        if source is not None and source not in file_paths:
            findings.append(
                _fatal(
                    "credential_relationships",
                    "unknown-source-artifact",
                    credential_id,
                    f"source_artifact_path={source!r} does not match any declared file",
                )
            )

        target = credential.get("target_surface_id")
        if target is not None and target not in surface_ids:
            findings.append(
                _fatal(
                    "credential_relationships",
                    "unknown-target-surface",
                    credential_id,
                    f"target_surface_id={target!r} does not match any declared service/surface",
                )
            )

        scope = credential.get("scope")
        if scope is not None and owner is not None:
            role = owner.get("role")
            forbidden = _ROLE_FORBIDDEN_SCOPES.get(role)
            if forbidden and scope in forbidden:
                findings.append(
                    _fatal(
                        "credential_relationships",
                        "role-scope-contradiction",
                        credential_id,
                        f"scope {scope!r} is incompatible with owner role {role!r}",
                    )
                )

        expires_at = _parse_iso(credential.get("expires_at"))
        if credential.get("expires_at") is not None and expires_at is None:
            findings.append(
                _fatal(
                    "credential_relationships",
                    "unparseable-expiry",
                    credential_id,
                    f"expires_at {credential.get('expires_at')!r} is not a valid ISO-8601 timestamp",
                )
            )

        if expires_at is not None and reference_time is not None and expires_at <= reference_time:
            findings.append(
                _warn(
                    "credential_relationships",
                    "credential-already-expired",
                    credential_id,
                    f"expires_at ({expires_at.isoformat()}) is not after reference_time ({reference_time.isoformat()})",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _surface_ids(package: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for service in _as_list(package.get("services")):
        component_id = service.get("component_id")
        if component_id is not None:
            ids.add(str(component_id))
    for component in _as_list(package.get("components")):
        component_id = component.get("component_id")
        if component_id is not None:
            ids.add(str(component_id))
        for surface in _as_list(component.get("surfaces")):
            surface_id = surface.get("surface_id")
            if surface_id is not None:
                ids.add(str(surface_id))
    return ids


def check_narrative_consistency(
    package: dict[str, Any],
    *,
    reference_time: datetime | None = None,
) -> NarrativeConsistencyReport:
    """Validate one narrative/environment profile and return a Fabric report.

    ``package`` is a plain dict (see module docstring for the sections it may
    carry). ``reference_time``, if given, is used only for the credential
    freshness check (dimension 6) -- it must be supplied by the caller
    (e.g. from an evidence timestamp), never sampled from the wall clock, to
    keep this function deterministic and replayable.

    Findings are collected from every dimension, rendered to plain strings,
    and sorted by a stable key so that identical input always produces an
    identical report regardless of internal iteration order.
    """

    narrative = _as_dict(package.get("narrative"))
    environment = _as_dict(package.get("environment"))
    services = [_as_dict(item) for item in _as_list(package.get("services"))]
    accounts = [_as_dict(item) for item in _as_list(package.get("accounts"))]
    personas = [_as_dict(item) for item in _as_list(package.get("personas"))]
    files = [_as_dict(item) for item in _as_list(package.get("files"))]
    credentials = [_as_dict(item) for item in _as_list(package.get("credentials"))]

    persona_ids = {str(p["persona_id"]) for p in personas if p.get("persona_id") is not None}
    personas_by_id = {str(p["persona_id"]): p for p in personas if p.get("persona_id") is not None}
    file_paths = {str(f["path"]) for f in files if f.get("path") is not None}
    surface_ids = _surface_ids(package)

    findings: list[Finding] = []
    findings.extend(check_os_service_generation(environment, services))
    findings.extend(check_naming_coherence(environment, accounts, personas))
    findings.extend(check_chronology_locale_timezone(narrative, environment, files, personas))
    findings.extend(check_file_relationships(files, persona_ids))
    findings.extend(check_persona_relationships(personas))
    findings.extend(check_credential_relationships(credentials, personas_by_id, file_paths, surface_ids, reference_time))

    findings.sort()

    fatal = [f.render() for f in findings if f.severity == "fatal"]
    warnings = [f.render() for f in findings if f.severity == "warning"]

    report_id = package.get("report_id") or f"{narrative.get('narrative_id') or package.get('package_id') or 'narrative'}-consistency-check"

    existing_consistency = _as_dict(package.get("consistency"))
    waivers = [str(w) for w in _as_list(existing_consistency.get("waivers"))]

    return NarrativeConsistencyReport(
        report_id=str(report_id),
        fatal_contradictions=fatal,
        warnings=warnings,
        waivers=waivers,
    )


def assert_narrative_consistent(
    package: dict[str, Any],
    *,
    reference_time: datetime | None = None,
) -> NarrativeConsistencyReport:
    """Like :func:`check_narrative_consistency`, but raises on any fatal finding.

    Fail-closed convenience wrapper for callers that want an exception rather
    than an inspectable-but-unusable report.
    """

    report = check_narrative_consistency(package, reference_time=reference_time)
    if not report.activatable:
        raise NarrativeContradiction(
            f"{report.report_id}: {len(report.fatal_contradictions)} fatal narrative contradiction(s): "
            + "; ".join(report.fatal_contradictions)
        )
    return report
