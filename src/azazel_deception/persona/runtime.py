"""AZ-06 deception-host persona/activity runtime (Deception#6).

This module schedules *synthetic* persona activity for a deception host:
things like an emulated employee logging in, opening a document, sending a
message, and logging out again, on a plausible working-hours cadence. It
exists purely to make an environment look inhabited to an attacker -- it is
not a behavioral model and it does not decide anything about engagement,
containment, or authority. Those remain Edge/Fabric concerns.

Doctrine (non-negotiable for this module):

* **Deterministic and replayable.** ``PersonaRuntime.schedule`` is a pure
  function of ``(spec, window_start, window_end, seed)``. The same inputs
  always produce a byte-identical (field-for-field equal) list of events.
* **No wall-clock or hidden randomness.** There is no ``datetime.now()`` and
  no use of the :mod:`random` module anywhere in this file. All scheduling
  decisions are derived from :mod:`hashlib` digests over the caller-supplied
  ``seed`` plus the spec/window content, so a caller who wants a different
  outcome must ask for one explicitly by changing an input.
* **Bounded.** The produced schedule never exceeds ``spec.max_events``, and
  every event timestamp falls inside the caller-supplied window and inside
  the persona's declared working hours. There is no free-form or
  LLM-authored behavior: the activity vocabulary is a small closed set
  (:data:`ALLOWED_ACTIVITIES`), and transitions between activities are a
  small explicit finite-state machine (:meth:`PersonaRuntime.step`), not an
  open-ended generator.
* **Fail closed.** A malformed ``PersonaSpec`` (empty/unknown activities,
  non-positive or absurd ``max_events``, an inverted or out-of-range
  ``working_hours``) or a malformed scheduling window (``window_end`` not
  after ``window_start``, unparsable ISO 8601 timestamps, mismatched
  timezone-awareness, an absurdly long window) raises :class:`PersonaSpecError`
  -- a plain :class:`ValueError` subclass -- instead of guessing or silently
  clamping to something "close enough".

Fabric (``azazel_fabric``) does not yet define a persona/activity contract,
so the models here are intentionally small and local (``extra="forbid"``,
like every other Fabric-adjacent model in this codebase) rather than
anticipating a shape Fabric hasn't specified.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

__all__ = [
    "ALLOWED_ACTIVITIES",
    "PersonaActivityEvent",
    "PersonaRuntime",
    "PersonaSpec",
    "PersonaSpecError",
    "WorkingHours",
]


class PersonaSpecError(ValueError):
    """Raised when a persona spec, window, or seed is malformed.

    A plain :class:`ValueError` subclass (mirroring
    :class:`azazel_deception.package.PackageValidationError`) so callers can
    catch either this or a bare ``ValueError`` -- including the
    :class:`pydantic.ValidationError` that pydantic v2 itself raises (it is
    also a ``ValueError`` subclass) when a :class:`PersonaSpec` is
    constructed with malformed field values.
    """


# Bounded, closed vocabulary. Deliberately small: this is a deterministic
# state machine, not an open-ended activity generator.
ALLOWED_ACTIVITIES: frozenset[str] = frozenset(
    {"login", "read_file", "edit_document", "send_message", "idle", "logout"}
)

# Hard ceiling on `max_events` so a malformed/hostile spec cannot request an
# unbounded schedule. This is a sanity backstop, not the normal operating
# range (personas are expected to request small schedules).
_MAX_EVENTS_CEILING = 100_000

# Hard ceiling on the scheduling window span, guarding the per-day segment
# walk in `_working_hour_segments` against an unbounded loop.
_MAX_WINDOW_SPAN = timedelta(days=3650)


class WorkingHours(BaseModel):
    """A persona's daily active window, as local-to-the-window-timestamps hours."""

    model_config = ConfigDict(extra="forbid")

    start_hour: int
    end_hour: int

    @field_validator("start_hour")
    @classmethod
    def _check_start_hour(cls, value: int) -> int:
        if value < 0 or value > 23:
            raise ValueError("start_hour must be within [0, 23]")
        return value

    @field_validator("end_hour")
    @classmethod
    def _check_end_hour(cls, value: int) -> int:
        if value < 1 or value > 24:
            raise ValueError("end_hour must be within [1, 24]")
        return value

    @model_validator(mode="after")
    def _check_order(self) -> "WorkingHours":
        if self.end_hour <= self.start_hour:
            raise ValueError("working_hours.end_hour must be greater than start_hour")
        return self


class PersonaSpec(BaseModel):
    """Declarative description of a synthetic persona's activity envelope.

    ``activities`` must be a non-empty subset of :data:`ALLOWED_ACTIVITIES`.
    ``max_events`` is the hard bound on how many events a single
    :meth:`PersonaRuntime.schedule` call may emit for this spec.
    """

    model_config = ConfigDict(extra="forbid")

    persona_id: str
    role: str
    timezone: str
    activities: list[str]
    working_hours: WorkingHours
    max_events: int

    @field_validator("persona_id", "role", "timezone")
    @classmethod
    def _check_nonempty_str(cls, value: str, info: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        return value

    @field_validator("activities")
    @classmethod
    def _check_activities(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("activities must not be empty")
        unknown = sorted(set(value) - ALLOWED_ACTIVITIES)
        if unknown:
            raise ValueError(
                "activities must come from the bounded vocabulary "
                f"{sorted(ALLOWED_ACTIVITIES)}; got unknown activities {unknown}"
            )
        return value

    @field_validator("max_events")
    @classmethod
    def _check_max_events(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("max_events must be a positive bound")
        if value > _MAX_EVENTS_CEILING:
            raise ValueError(f"max_events must not exceed {_MAX_EVENTS_CEILING}")
        return value


class PersonaActivityEvent(BaseModel):
    """One scheduled synthetic activity event for a persona."""

    model_config = ConfigDict(extra="forbid")

    persona_id: str
    seq: int
    at: str
    activity: str
    detail: dict[str, Any]


def _digest(seed_material: str, tag: str) -> bytes:
    """Deterministic derivation helper: sha256 over seed material + a tag.

    This is the only source of pseudo-randomness anywhere in this module.
    No :mod:`random`, no :func:`datetime.now`.
    """

    return hashlib.sha256(f"{seed_material}|{tag}".encode("utf-8")).digest()


def _parse_iso8601(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise PersonaSpecError(f"{label} must be a non-empty ISO 8601 timestamp string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise PersonaSpecError(
            f"{label} is not a valid ISO 8601 timestamp: {value!r}"
        ) from exc


def _working_hour_segments(
    window_start: datetime, window_end: datetime, working_hours: WorkingHours
) -> list[tuple[datetime, datetime]]:
    """Return the [start, end) sub-intervals of `window` that fall inside working hours.

    Walks whole calendar days from `window_start`'s date through
    `window_end`'s date (inclusive), intersecting each day's working-hours
    interval with the overall window. Bounded by `_MAX_WINDOW_SPAN`, so this
    is always a finite walk.
    """

    segments: list[tuple[datetime, datetime]] = []
    day = datetime(
        window_start.year, window_start.month, window_start.day, tzinfo=window_start.tzinfo
    )
    one_day = timedelta(days=1)
    while day <= window_end:
        day_start = day + timedelta(hours=working_hours.start_hour)
        day_end = day + timedelta(hours=working_hours.end_hour)
        seg_start = max(day_start, window_start)
        seg_end = min(day_end, window_end)
        if seg_start < seg_end:
            segments.append((seg_start, seg_end))
        day += one_day
    return segments


def _offset_to_datetime(
    segments: list[tuple[datetime, datetime]], offset_seconds: int
) -> datetime:
    remaining = offset_seconds
    for seg_start, seg_end in segments:
        seg_len = int((seg_end - seg_start).total_seconds())
        if remaining < seg_len:
            return seg_start + timedelta(seconds=remaining)
        remaining -= seg_len
    # Defensive fallback: only reachable if `offset_seconds` was computed
    # against a different segment set than the one passed in here.
    return segments[-1][1]


class PersonaRuntime:
    """Deterministic, bounded scheduler for synthetic persona activity."""

    @staticmethod
    def step(state: str, roll: int, activities: Sequence[str]) -> tuple[str, str]:
        """Deterministic finite-state transition: pick the next activity.

        `state` is the persona's current session state, either
        ``"logged_out"`` or ``"logged_in"``. `roll` is a 0-255 byte derived
        deterministically (via :func:`_digest`) by the caller -- this
        function performs no hashing or randomness itself, it only maps
        `(state, roll)` to `(activity, next_state)`.

        When both ``"login"`` and ``"logout"`` are present in the persona's
        declared vocabulary, activity is constrained to a simple session
        shape: a logged-out persona can only ``login`` next; a logged-in
        persona can do anything except ``login`` again (including
        ``logout``, which returns it to ``logged_out``). When the
        vocabulary declares neither, `state` is inert and an activity is
        picked uniformly (via `roll`) from the full vocabulary.
        """

        if not activities:
            raise PersonaSpecError("activities must not be empty")

        has_login = "login" in activities
        has_logout = "logout" in activities

        if not has_login and not has_logout:
            return activities[roll % len(activities)], state

        if state == "logged_out":
            if has_login:
                return "login", "logged_in"
            others = [a for a in activities if a != "logout"] or list(activities)
            return others[roll % len(others)], state

        candidates = [a for a in activities if a != "login"] or list(activities)
        chosen = candidates[roll % len(candidates)]
        next_state = "logged_out" if chosen == "logout" else "logged_in"
        return chosen, next_state

    @classmethod
    def schedule(
        cls,
        spec: PersonaSpec,
        *,
        window_start: str,
        window_end: str,
        seed: str,
    ) -> list[PersonaActivityEvent]:
        """Produce a deterministic, bounded activity schedule.

        Pure function of `(spec, window_start, window_end, seed)`: calling
        it twice with identical arguments returns field-for-field equal
        event lists, and it never consults wall-clock time or any source of
        randomness other than the hashes derived from these arguments.

        Returns at most `spec.max_events` events, each with `at` inside
        `[window_start, window_end]` and inside the persona's declared
        working hours on that event's calendar day.

        Raises `PersonaSpecError` (a `ValueError`) if `window_start`/
        `window_end` are not parsable ISO 8601 timestamps, if their
        timezone-awareness disagrees, if the window is inverted or empty,
        if the window span is absurdly large, or if `seed` is empty.
        """

        if not isinstance(spec, PersonaSpec):
            raise PersonaSpecError("spec must be a PersonaSpec instance")
        if not isinstance(seed, str) or not seed.strip():
            raise PersonaSpecError("seed must be a non-empty string")

        start_dt = _parse_iso8601(window_start, "window_start")
        end_dt = _parse_iso8601(window_end, "window_end")

        if (start_dt.tzinfo is None) != (end_dt.tzinfo is None):
            raise PersonaSpecError(
                "window_start and window_end must both be naive or both be timezone-aware"
            )
        if end_dt <= start_dt:
            raise PersonaSpecError("window_end must be strictly after window_start")
        if (end_dt - start_dt) > _MAX_WINDOW_SPAN:
            raise PersonaSpecError(
                f"window span must not exceed {_MAX_WINDOW_SPAN.days} days"
            )

        segments = _working_hour_segments(start_dt, end_dt, spec.working_hours)
        total_seconds = sum(
            int((seg_end - seg_start).total_seconds()) for seg_start, seg_end in segments
        )
        if total_seconds <= 0:
            # Window never overlaps the persona's working hours: a valid,
            # bounded (empty) schedule, not a malformed spec.
            return []

        seed_material = "|".join(
            [
                "persona-activity/v1",
                seed,
                spec.persona_id,
                spec.role,
                spec.timezone,
                ",".join(spec.activities),
                str(spec.working_hours.start_hour),
                str(spec.working_hours.end_hour),
                str(spec.max_events),
                start_dt.isoformat(),
                end_dt.isoformat(),
            ]
        )

        count_digest = _digest(seed_material, "count")
        num_events = 1 + (int.from_bytes(count_digest[:4], "big") % spec.max_events)
        num_events = min(num_events, spec.max_events)

        offsets: list[tuple[int, int]] = []
        for i in range(num_events):
            offset_digest = _digest(seed_material, f"offset:{i}")
            offset = int.from_bytes(offset_digest[:8], "big") % total_seconds
            offsets.append((offset, i))
        offsets.sort()

        events: list[PersonaActivityEvent] = []
        state = "logged_out"
        for order_idx, (offset, _orig_i) in enumerate(offsets):
            roll = _digest(seed_material, f"activity:{order_idx}")[0]
            activity, state = cls.step(state, roll, spec.activities)

            at_dt = _offset_to_datetime(segments, offset)
            detail_digest = _digest(seed_material, f"detail:{order_idx}")
            detail = {
                "nonce": detail_digest.hex()[:16],
                "offset_seconds": offset,
            }

            events.append(
                PersonaActivityEvent(
                    persona_id=spec.persona_id,
                    seq=order_idx + 1,
                    at=at_dt.isoformat(),
                    activity=activity,
                    detail=detail,
                )
            )

        return events
