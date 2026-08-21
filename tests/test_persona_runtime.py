from datetime import datetime

import pytest

from azazel_deception.persona import (
    ALLOWED_ACTIVITIES,
    PersonaActivityEvent,
    PersonaRuntime,
    PersonaSpec,
    PersonaSpecError,
    WorkingHours,
)

WINDOW_START = "2026-08-17T00:00:00"  # a Monday
WINDOW_END = "2026-08-21T23:59:59"  # through Friday


def make_spec(**overrides):
    fields = dict(
        persona_id="persona-analyst-01",
        role="analyst",
        timezone="UTC",
        activities=["login", "read_file", "edit_document", "send_message", "idle", "logout"],
        working_hours=WorkingHours(start_hour=9, end_hour=17),
        max_events=12,
    )
    fields.update(overrides)
    return PersonaSpec(**fields)


def test_schedule_is_deterministic_and_replayable():
    spec = make_spec()
    first = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed="seed-alpha"
    )
    second = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed="seed-alpha"
    )
    assert first == second
    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]
    assert len(first) > 0


def test_different_seed_yields_different_schedule():
    spec = make_spec()
    a = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed="seed-alpha"
    )
    b = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed="seed-beta"
    )
    assert a != b


def test_different_window_yields_different_schedule():
    spec = make_spec()
    a = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed="seed-alpha"
    )
    b = PersonaRuntime.schedule(
        spec,
        window_start="2026-09-14T00:00:00",
        window_end="2026-09-18T23:59:59",
        seed="seed-alpha",
    )
    assert a != b


def test_schedule_is_bounded_by_max_events():
    spec = make_spec(max_events=3)
    events = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed="seed-gamma"
    )
    assert len(events) <= 3
    assert len(events) <= spec.max_events


@pytest.mark.parametrize("seed", ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"])
def test_schedule_never_exceeds_max_events_across_many_seeds(seed):
    spec = make_spec(max_events=5)
    events = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed=seed
    )
    assert len(events) <= 5


def test_events_fall_within_window_and_working_hours():
    spec = make_spec(working_hours=WorkingHours(start_hour=9, end_hour=17), max_events=25)
    events = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed="seed-delta"
    )
    assert events, "expected at least one event for a multi-day working-hours window"

    window_start_dt = datetime.fromisoformat(WINDOW_START)
    window_end_dt = datetime.fromisoformat(WINDOW_END)

    for event in events:
        at_dt = datetime.fromisoformat(event.at)
        assert window_start_dt <= at_dt <= window_end_dt
        assert 9 <= at_dt.hour < 17


def test_events_are_sequential_and_chronological():
    spec = make_spec(max_events=25)
    events = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed="seed-epsilon"
    )
    assert [e.seq for e in events] == list(range(1, len(events) + 1))
    timestamps = [datetime.fromisoformat(e.at) for e in events]
    assert timestamps == sorted(timestamps)


def test_window_outside_working_hours_yields_empty_bounded_schedule():
    spec = make_spec(working_hours=WorkingHours(start_hour=9, end_hour=17))
    events = PersonaRuntime.schedule(
        spec,
        window_start="2026-08-17T18:00:00",
        window_end="2026-08-17T20:00:00",
        seed="seed-zeta",
    )
    assert events == []


def test_activities_come_only_from_declared_vocabulary():
    spec = make_spec(
        activities=["login", "read_file", "logout"], max_events=30
    )
    events = PersonaRuntime.schedule(
        spec, window_start=WINDOW_START, window_end=WINDOW_END, seed="seed-eta"
    )
    for event in events:
        assert event.activity in spec.activities
        assert event.activity in ALLOWED_ACTIVITIES


def test_empty_activities_fails_closed():
    with pytest.raises(ValueError):
        make_spec(activities=[])


def test_unknown_activity_fails_closed():
    with pytest.raises(ValueError):
        make_spec(activities=["login", "hack_the_mainframe"])


def test_working_hours_end_before_start_fails_closed():
    with pytest.raises(ValueError):
        WorkingHours(start_hour=17, end_hour=9)


def test_working_hours_negative_bound_fails_closed():
    with pytest.raises(ValueError):
        WorkingHours(start_hour=-1, end_hour=17)


def test_negative_max_events_fails_closed():
    with pytest.raises(ValueError):
        make_spec(max_events=0)
    with pytest.raises(ValueError):
        make_spec(max_events=-5)


def test_extra_field_on_spec_fails_closed():
    with pytest.raises(ValueError):
        PersonaSpec(
            persona_id="p1",
            role="analyst",
            timezone="UTC",
            activities=["login", "logout"],
            working_hours=WorkingHours(start_hour=9, end_hour=17),
            max_events=5,
            unexpected_field="nope",
        )


def test_malformed_window_fails_closed():
    spec = make_spec()
    with pytest.raises(PersonaSpecError):
        PersonaRuntime.schedule(
            spec, window_start=WINDOW_END, window_end=WINDOW_START, seed="seed-theta"
        )
    with pytest.raises(PersonaSpecError):
        PersonaRuntime.schedule(
            spec, window_start="not-a-timestamp", window_end=WINDOW_END, seed="seed-theta"
        )
    with pytest.raises(PersonaSpecError):
        PersonaRuntime.schedule(
            spec, window_start=WINDOW_START, window_end=WINDOW_END, seed=""
        )


def test_step_is_a_bounded_deterministic_state_machine():
    activities = ["login", "read_file", "edit_document", "send_message", "idle", "logout"]
    for roll in range(256):
        activity, next_state = PersonaRuntime.step("logged_out", roll, activities)
        assert activity == "login"
        assert next_state == "logged_in"
        activity2, next_state2 = PersonaRuntime.step("logged_in", roll, activities)
        assert activity2 in activities
        assert activity2 != "login"
        assert next_state2 in ("logged_in", "logged_out")


def test_persona_activity_event_model_forbids_extra_fields():
    with pytest.raises(ValueError):
        PersonaActivityEvent(
            persona_id="p1",
            seq=1,
            at="2026-08-17T09:00:00",
            activity="login",
            detail={},
            extra="nope",
        )
