"""Deterministic synthetic "honey artifact" generation for AZ-06 (Deception#6).

``generate_honey_artifacts`` turns a deception ``package`` mapping (see
``azazel_deception.package`` for the package dict shape: ``package_id``,
``narrative``, ``components``, ...) plus an injected ``seed``/``as_of`` into an
in-memory :class:`HoneyArtifactManifest` describing synthetic decoy content:
files & related documents, metadata & revision history, configuration
breadcrumbs, and service/host history.

Doctrine enforced here:

* SYNTHETIC-ONLY -- every generated body is built from a small fictional
  vocabulary (fake personas at the RFC 2606 reserved ``example.com`` domain,
  RFC 5737 TEST-NET-1 addresses, hash-derived identifiers) and is passed
  through :func:`assert_synthetic_only` before it is attached to a
  descriptor. No real personal/operational/secret/customer/production data is
  ever consulted or emitted.
* DETERMINISTIC & REPLAYABLE -- nothing here reads the wall clock or process
  entropy. All identifiers, paths, timestamps, and content are derived from
  ``(package_id, seed, as_of, ...)`` via :mod:`hashlib`. The same inputs
  always produce a byte-identical manifest; a different seed or ``as_of``
  always changes it.
* NO LLM -- content is template + hash driven only.
* FAIL-CLOSED -- if any package-authored text, or any rendered artifact body,
  matches a banned real-secret/PII pattern, generation raises
  :class:`SyntheticGuardViolation` instead of silently emitting it.

This module only *generates descriptors*; it never touches a real or
attacker-facing filesystem. Placement/materialization is the runtime
adapter's responsibility and is out of scope here.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

MANIFEST_SCHEMA_VERSION = "honey-artifact-manifest/v0.1"

ArtifactKind = Literal[
    "file",
    "document",
    "config_breadcrumb",
    "service_history",
    "metadata",
    "revision",
]

_T = TypeVar("_T")


class HoneyArtifactError(ValueError):
    """Raised when honey-artifact generation cannot proceed (fail-closed)."""


class SyntheticGuardViolation(HoneyArtifactError):
    """Raised when content matches a banned real-secret/PII pattern."""


# ---------------------------------------------------------------------------
# Synthetic-only guard
# ---------------------------------------------------------------------------
#
# These patterns intentionally err toward over-rejection: a false positive on
# a decoy body only costs a re-authoring of the offending package field, while
# a false negative would leak a real-secret-shaped string into a manifest.
BANNED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key_header",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "credit_card_visa",
        re.compile(r"\b4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b"),
    ),
    (
        "credit_card_mastercard",
        re.compile(r"\b5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b"),
    ),
    (
        "credit_card_amex",
        re.compile(r"\b3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}\b"),
    ),
    (
        "us_ssn",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    ),
)


def assert_synthetic_only(content: str, *, context: str = "content") -> None:
    """Fail closed if ``content`` matches an obvious real-secret/PII pattern.

    This is a syntactic guard only: it cannot prove content is *not* real, but
    it reliably catches the shapes (private-key headers, credential IDs,
    payment-card and SSN-like digit groupings) that a mis-authored package
    could otherwise cause to be echoed into a synthetic artifact.
    """

    for name, pattern in BANNED_PATTERNS:
        if pattern.search(content):
            raise SyntheticGuardViolation(
                f"synthetic-only guard rejected {context}: matched banned pattern '{name}'"
            )


# ---------------------------------------------------------------------------
# Deterministic derivation helpers (hashlib only -- no random/time/datetime.now)
# ---------------------------------------------------------------------------


def _digest_hex(*parts: str) -> str:
    joined = "\x1f".join(parts)  # unit separator avoids cross-part collisions
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _sha256_of(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _int_from(*parts: str, modulo: int) -> int:
    if modulo <= 0:
        raise HoneyArtifactError("modulo must be positive")
    return int(_digest_hex(*parts), 16) % modulo


def _choice(seq: Sequence[_T], *parts: str) -> _T:
    if not seq:
        raise HoneyArtifactError("cannot choose from an empty sequence")
    return seq[_int_from(*parts, modulo=len(seq))]


def _fake_ip(*parts: str) -> str:
    # RFC 5737 TEST-NET-1: reserved for documentation/examples, never routable.
    octet = _int_from(*parts, modulo=254) + 1
    return f"192.0.2.{octet}"


def _fake_port(*parts: str) -> int:
    return 20000 + _int_from(*parts, modulo=20000)


def _parse_as_of(as_of: str) -> datetime:
    if not isinstance(as_of, str) or not as_of.strip():
        raise HoneyArtifactError("as_of must be a non-empty ISO-8601 timestamp string")
    text = as_of.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise HoneyArtifactError(f"invalid as_of timestamp: {as_of!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _lifecycle(as_of_dt: datetime, *parts: str) -> tuple[datetime, datetime]:
    """Derive a deterministic (created_at, revised_at) pair, both <= as_of."""

    created_days_ago = 30 + _int_from(*parts, "created-offset-days", modulo=335)
    created_hours = _int_from(*parts, "created-offset-hours", modulo=24)
    created_dt = as_of_dt - timedelta(days=created_days_ago, hours=created_hours)

    revised_days_ago = _int_from(*parts, "revised-offset-days", modulo=created_days_ago)
    revised_hours = _int_from(*parts, "revised-offset-hours", modulo=24)
    revised_dt = as_of_dt - timedelta(days=revised_days_ago, hours=revised_hours)
    if revised_dt < created_dt:
        revised_dt = created_dt
    if revised_dt > as_of_dt:
        revised_dt = as_of_dt
    return created_dt, revised_dt


# ---------------------------------------------------------------------------
# Synthetic vocabularies (fictional only; RFC 2606 reserved email domain)
# ---------------------------------------------------------------------------

_FIRST_NAMES = (
    "Alex", "Jordan", "Riley", "Morgan", "Taylor", "Casey", "Drew", "Sam",
    "Jamie", "Quinn", "Avery", "Reese", "Skyler", "Rowan", "Elliot", "Harper",
)
_LAST_NAMES = (
    "Whitfield", "Nakamura", "Oduya", "Bergstrom", "Castellano", "Mercer",
    "Okafor", "Lindgren", "Vasquez", "Petrov", "Delacroix", "Yamashita",
    "Kowalski", "Abioye", "Marchetti", "Sundberg",
)
_ROLES = (
    "Systems Administrator", "IT Support Analyst", "Network Engineer",
    "Facilities Coordinator", "Records Officer", "Help Desk Technician",
    "Operations Assistant", "Compliance Analyst",
)
_DEPARTMENTS = (
    "IT Operations", "Facilities", "Records Management", "Network Services",
    "Help Desk", "Support Services",
)
_ORG_NAMES = (
    "Meridian County Public Services", "Northgate Municipal Authority",
    "Cascadia Regional Utilities", "Fairview Township Office",
    "Bellwood Community Services",
)
_FILE_DIRS = ("srv", "opt", "var/lib", "home/svc")
_FILE_NAMES = (
    "settings", "runtime", "export", "handoff", "legacy-backup",
    "service-state", "inventory-snapshot", "migration-notes",
)
_FILE_EXTS = ("conf", "yaml", "ini", "log")
_BREADCRUMB_EXTS = ("bak", "old", "orig", "swp")
_DOC_TITLES = (
    "Onboarding Notes", "Environment Handoff", "Support Runbook Draft",
    "Change Log Summary", "Access Notes",
)
_SERVICE_EVENTS = (
    "service_started", "service_stopped", "health_check_passed",
    "health_check_failed", "config_reloaded", "restarted_by_watchdog",
)
_REVISION_SUMMARIES = (
    "Updated network configuration.",
    "Rotated internal documentation.",
    "Migrated storage layout.",
    "Adjusted service thresholds.",
    "Reassigned ownership.",
    "Cleaned up legacy breadcrumbs.",
)


def _persona(*parts: str) -> dict[str, str]:
    first = _choice(_FIRST_NAMES, *parts, "first")
    last = _choice(_LAST_NAMES, *parts, "last")
    role = _choice(_ROLES, *parts, "role")
    department = _choice(_DEPARTMENTS, *parts, "department")
    persona_id = "persona-" + _digest_hex(*parts, "persona-id")[:12]
    email = f"{first.lower()}.{last.lower()}@example.com"
    return {
        "persona_id": persona_id,
        "display_name": f"{first} {last}",
        "email": email,
        "role": role,
        "department": department,
    }


# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class RevisionEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision_id: str = Field(min_length=1)
    revised_at: str = Field(min_length=1)
    author: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    content_sha256: str = Field(min_length=1)


class HoneyArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(min_length=1)
    kind: ArtifactKind
    path: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    author: str = Field(min_length=1)
    created_at: str = Field(min_length=1)
    revised_at: str = Field(min_length=1)
    content_sha256: str = Field(min_length=1)
    provenance: Literal["synthetic"] = "synthetic"
    metadata: dict[str, Any] = Field(default_factory=dict)
    revision_history: list[RevisionEntry] = Field(default_factory=list)


class HoneyArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[MANIFEST_SCHEMA_VERSION] = MANIFEST_SCHEMA_VERSION
    manifest_id: str = Field(min_length=1)
    package_id: str = Field(min_length=1)
    generated_as_of: str = Field(min_length=1)
    synthetic: Literal[True] = True
    artifacts: list[HoneyArtifact] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Artifact builders
# ---------------------------------------------------------------------------


def _build_artifact(
    kind: ArtifactKind,
    package_id: str,
    seed: str,
    as_of_dt: datetime,
    path: str,
    content: str,
    salt: tuple[str, ...],
    extra_metadata: dict[str, Any],
) -> HoneyArtifact:
    assert_synthetic_only(content, context=f"{kind} artifact body ({path})")

    base = (package_id, seed, kind, *salt)
    artifact_id = f"honey-{kind}-" + _digest_hex(*base, "artifact-id")[:16]
    created_dt, revised_dt = _lifecycle(as_of_dt, *base)
    owner_persona = _persona(*base, "owner")
    author_persona = _persona(*base, "author")
    content_sha256 = _sha256_of(content)

    span_days = max((revised_dt - created_dt).days, 0)
    revision_count = _int_from(*base, "revision-count", modulo=3) + 1
    revisions: list[RevisionEntry] = []
    for index in range(revision_count):
        offset_days = (span_days * (index + 1)) // (revision_count + 1)
        rev_dt = created_dt + timedelta(days=offset_days)
        if rev_dt > revised_dt:
            rev_dt = revised_dt
        summary = _choice(_REVISION_SUMMARIES, *base, f"revision-{index}-summary")
        rev_author = _persona(*base, f"revision-{index}-author")
        rev_content_sha256 = _sha256_of(
            f"{artifact_id}|revision-{index}|{summary}|{content_sha256}"
        )
        revisions.append(
            RevisionEntry(
                revision_id=f"{artifact_id}-rev-{index + 1}",
                revised_at=_iso(rev_dt),
                author=rev_author["persona_id"],
                summary=summary,
                content_sha256=rev_content_sha256,
            )
        )

    metadata: dict[str, Any] = {
        "content": content,
        "owner_persona": owner_persona,
        "author_persona": author_persona,
    }
    metadata.update(extra_metadata)

    return HoneyArtifact(
        artifact_id=artifact_id,
        kind=kind,
        path=path,
        owner=owner_persona["persona_id"],
        author=author_persona["persona_id"],
        created_at=_iso(created_dt),
        revised_at=_iso(revised_dt),
        content_sha256=content_sha256,
        metadata=metadata,
        revision_history=revisions,
    )


def _build_file(
    package_id: str, seed: str, as_of_dt: datetime, component_id: str, index: int
) -> HoneyArtifact:
    salt = (component_id, "file", str(index))
    base = (package_id, seed, *salt)
    ext = _choice(_FILE_EXTS, *base, "ext")
    name = _choice(_FILE_NAMES, *base, "name")
    directory = _choice(_FILE_DIRS, *base, "dir")
    path = f"/{directory}/{component_id}/{name}.{ext}"
    ip = _fake_ip(*base, "ip")
    port = _fake_port(*base, "port")
    build_ref = _digest_hex(*base, "build-ref")[:12]
    content = (
        f"# synthetic decoy configuration for component '{component_id}'\n"
        f"service_name={component_id}\n"
        f"bind_address={ip}\n"
        f"bind_port={port}\n"
        f"data_dir=/{directory}/{component_id}/data\n"
        f"build_ref={build_ref}\n"
    )
    return _build_artifact(
        "file", package_id, seed, as_of_dt, path, content, salt, {"component_id": component_id}
    )


def _build_config_breadcrumb(
    package_id: str, seed: str, as_of_dt: datetime, component_id: str, index: int
) -> HoneyArtifact:
    salt = (component_id, "config_breadcrumb", str(index))
    base = (package_id, seed, *salt)
    ext = _choice(_BREADCRUMB_EXTS, *base, "ext")
    name = _choice(_FILE_NAMES, *base, "name")
    directory = _choice(_FILE_DIRS, *base, "dir")
    path = f"/{directory}/{component_id}/.{name}.{ext}"
    ip = _fake_ip(*base, "legacy-ip")
    port = _fake_port(*base, "legacy-port")
    content = (
        f"# stale breadcrumb from a prior rotation of '{component_id}'\n"
        "# TODO: remove before next audit\n"
        f"legacy_bind_address={ip}\n"
        f"legacy_bind_port={port}\n"
        "note=superseded configuration retained for reference\n"
    )
    return _build_artifact(
        "config_breadcrumb",
        package_id,
        seed,
        as_of_dt,
        path,
        content,
        salt,
        {"component_id": component_id},
    )


def _build_document(package_id: str, seed: str, as_of_dt: datetime, purpose: str) -> HoneyArtifact:
    salt = ("document",)
    base = (package_id, seed, *salt)
    title = _choice(_DOC_TITLES, *base, "title")
    org = _choice(_ORG_NAMES, *base, "org")
    slug = title.lower().replace(" ", "-")
    path = f"/srv/{package_id}/docs/{slug}.md"
    content = (
        f"# {title}\n\n"
        f"Organization: {org}\n"
        f"Scope: {purpose}\n\n"
        "This note captures informal context for staff handoff. "
        "Refer to the shared drive for the current procedure index.\n"
    )
    return _build_artifact(
        "document", package_id, seed, as_of_dt, path, content, salt, {"title": title}
    )


def _build_metadata(
    package_id: str, seed: str, as_of_dt: datetime, environment_profile_id: str, locale: str, tz: str
) -> HoneyArtifact:
    salt = ("metadata",)
    base = (package_id, seed, *salt)
    asset_tag = "ASSET-" + _digest_hex(*base, "asset-tag")[:8].upper()
    path = f"/srv/{package_id}/inventory/{asset_tag}.json"
    payload = {
        "asset_tag": asset_tag,
        "package_id": package_id,
        "environment_profile_id": environment_profile_id,
        "locale": locale,
        "timezone": tz,
    }
    content = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    return _build_artifact(
        "metadata", package_id, seed, as_of_dt, path, content, salt, {"asset_tag": asset_tag}
    )


def _build_service_history(
    package_id: str, seed: str, as_of_dt: datetime, component_ids: Sequence[str]
) -> HoneyArtifact:
    salt = ("service_history",)
    base = (package_id, seed, *salt)
    node = "host-" + _digest_hex(*base, "node-id")[:8]
    path = f"/var/log/{package_id}/service-history.log"
    lines = []
    for index in range(6):
        offset_days = _int_from(*base, f"line-{index}-day", modulo=30)
        ts = as_of_dt - timedelta(days=offset_days)
        component_id = _choice(component_ids, *base, f"line-{index}-component")
        event = _choice(_SERVICE_EVENTS, *base, f"line-{index}-event")
        lines.append(f"{_iso(ts)} host={node} component={component_id} event={event}")
    lines.sort()
    content = "\n".join(lines) + "\n"
    return _build_artifact(
        "service_history", package_id, seed, as_of_dt, path, content, salt, {"host": node}
    )


def _build_revision(
    package_id: str, seed: str, as_of_dt: datetime, component_ids: Sequence[str]
) -> HoneyArtifact:
    salt = ("revision",)
    base = (package_id, seed, *salt)
    path = f"/srv/{package_id}/docs/CHANGELOG.md"
    lines = [f"# Change log for {package_id}", ""]
    for index in range(4):
        offset_days = _int_from(*base, f"entry-{index}-day", modulo=200) + 1
        ts = as_of_dt - timedelta(days=offset_days)
        component_id = _choice(component_ids, *base, f"entry-{index}-component")
        summary = _choice(_REVISION_SUMMARIES, *base, f"entry-{index}-summary")
        lines.append(f"- {_iso(ts)} ({component_id}): {summary}")
    content = "\n".join(lines) + "\n"
    return _build_artifact("revision", package_id, seed, as_of_dt, path, content, salt, {})


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _normalize_component_ids(package: Mapping[str, Any], package_id: str) -> list[str]:
    components_raw = package.get("components")
    if not isinstance(components_raw, list) or not components_raw:
        return [f"{package_id}-baseline-host"]

    component_ids: list[str] = []
    for index, component in enumerate(components_raw):
        if isinstance(component, Mapping):
            candidate = component.get("component_id") or component.get("id")
        else:
            candidate = None
        component_id = str(candidate) if candidate else f"{package_id}-component-{index}"
        assert_synthetic_only(component_id, context="package field components[].component_id")
        component_ids.append(component_id)
    return component_ids or [f"{package_id}-baseline-host"]


def generate_honey_artifacts(
    package: Mapping[str, Any], *, seed: str, as_of: str
) -> HoneyArtifactManifest:
    """Deterministically generate a synthetic honey-artifact manifest.

    ``package`` is the raw deception-package mapping as produced by
    :func:`azazel_deception.package.load_package` (canonical or bootstrap
    shape) -- only ``package_id``, ``narrative``, and ``components`` are read;
    the package is not otherwise validated or mutated here. ``seed`` and
    ``as_of`` (an ISO-8601 timestamp) are the only sources of variability:
    calling this twice with identical arguments always yields an equal
    manifest, and no wall-clock/process entropy is ever consulted.

    Raises :class:`HoneyArtifactError` (or its subclass
    :class:`SyntheticGuardViolation`) fail-closed if the package is malformed
    or if any package-authored text or generated content matches a banned
    real-secret/PII pattern.
    """

    if not isinstance(package, Mapping):
        raise HoneyArtifactError("package must be a mapping")

    package_id = package.get("package_id")
    if not isinstance(package_id, str) or not package_id.strip():
        raise HoneyArtifactError("package must declare a non-empty string package_id")

    if not isinstance(seed, str) or not seed.strip():
        raise HoneyArtifactError("seed must be a non-empty string")

    as_of_dt = _parse_as_of(as_of)
    as_of_iso = _iso(as_of_dt)

    narrative = package.get("narrative")
    if not isinstance(narrative, Mapping):
        narrative = {}
    purpose = str(narrative.get("purpose") or "internal decoy environment")
    environment_profile_id = str(
        narrative.get("environment_profile_id") or f"{package_id}-environment"
    )
    locale = str(narrative.get("locale") or "en-US")
    tz = str(narrative.get("timezone") or "UTC")

    # Fail-closed: reject an obviously mis-authored package *before* its text
    # is echoed into any generated artifact content.
    assert_synthetic_only(purpose, context="package field narrative.purpose")
    assert_synthetic_only(
        environment_profile_id, context="package field narrative.environment_profile_id"
    )

    component_ids = _normalize_component_ids(package, package_id)

    artifacts: list[HoneyArtifact] = [
        _build_document(package_id, seed, as_of_dt, purpose),
        _build_metadata(package_id, seed, as_of_dt, environment_profile_id, locale, tz),
        _build_service_history(package_id, seed, as_of_dt, component_ids),
        _build_revision(package_id, seed, as_of_dt, component_ids),
    ]
    for index, component_id in enumerate(component_ids):
        artifacts.append(_build_file(package_id, seed, as_of_dt, component_id, index))
        artifacts.append(_build_config_breadcrumb(package_id, seed, as_of_dt, component_id, index))

    manifest_id = "honey-manifest-" + _digest_hex(package_id, seed, as_of_iso, "manifest-id")[:16]

    return HoneyArtifactManifest(
        manifest_id=manifest_id,
        package_id=package_id,
        generated_as_of=as_of_iso,
        artifacts=artifacts,
    )
