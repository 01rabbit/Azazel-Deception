"""The human checklist and the machine-readable gate registry must agree.

`docs/live-gate-checklist.md` is what an operator reads before a live flip;
`azazel_deception.runtime.live_gate.LIVE_GATES` is what code checks. When those
two drift, the failure is silent and in the dangerous direction: reopening a
checklist item without adding its gate id leaves
`evaluate_live_gate_readiness` reporting ``ready=True`` while the page an
operator reads still shows the gate open. That happened (Azazel-Deception#38
items 2 and 3) and prose alone did not prevent it.

These tests make the correspondence a build failure instead of a habit. They
assert nothing about whether a gate *should* be open — only that both records
say the same thing about it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from azazel_deception.runtime.live_gate import (
    LIVE_GATES,
    REQUIRED_LIVE_GATE_IDS,
    evaluate_live_gate_readiness,
)

CHECKLIST = Path(__file__).resolve().parents[1] / "docs" / "live-gate-checklist.md"

# The one exemption, named here so it cannot quietly grow: the Phase-2 gate is a
# meta-gate over every other item and closes only when the rest of the file does.
# It is not a live-flip gate of its own, so it carries no id.
EXEMPT_SECTIONS = frozenset({"Phase-2 gate"})

_ITEM = re.compile(r"^- \[(?P<state>x| |n/a)\] (?P<text>.*)$")
_GATE_ID = re.compile(r"`LIVE_GATES` id `(?P<gate_id>[a-z0-9_]+)`")
_HEADING = re.compile(r"^## (?P<title>.+)$")


class Item:
    __slots__ = ("state", "section", "text", "gate_ids", "line_no")

    def __init__(self, state: str, section: str, text: str, gate_ids: list[str], line_no: int):
        self.state = state
        self.section = section
        self.text = text
        self.gate_ids = gate_ids
        self.line_no = line_no

    def __repr__(self) -> str:  # pragma: no cover - failure messages only
        return f"{CHECKLIST.name}:{self.line_no} [{self.state}] {self.text[:70]}"


def _parse_items() -> list[Item]:
    """Return every checklist item with its section and any gate ids it names."""

    items: list[Item] = []
    section = ""
    current: Item | None = None
    for line_no, raw in enumerate(CHECKLIST.read_text(encoding="utf-8").splitlines(), 1):
        heading = _HEADING.match(raw)
        if heading:
            section = heading.group("title").strip()
            current = None
            continue
        match = _ITEM.match(raw)
        if match:
            current = Item(
                state=match.group("state"),
                section=section,
                text=match.group("text"),
                gate_ids=[m.group("gate_id") for m in _GATE_ID.finditer(raw)],
                line_no=line_no,
            )
            items.append(current)
            continue
        # Indented prose belongs to the item above it; a blank or unindented
        # line ends the item so the next section's text is never absorbed.
        if current is not None and raw.startswith("    "):
            current.gate_ids.extend(m.group("gate_id") for m in _GATE_ID.finditer(raw))
        elif not raw.startswith("    "):
            current = None
    return items


@pytest.fixture(scope="module")
def items() -> list[Item]:
    parsed = _parse_items()
    assert parsed, "parsed no checklist items — the parser or the file format changed"
    return parsed


def test_every_open_item_names_a_gate_id(items: list[Item]) -> None:
    """An open box with no gate id is exactly the #38 item-2 defect."""

    offenders = [
        i
        for i in items
        if i.state == " " and i.section not in EXEMPT_SECTIONS and not i.gate_ids
    ]
    assert not offenders, (
        "open checklist items with no `LIVE_GATES` id — readiness would report "
        f"ready=True while these are open: {offenders}"
    )


def test_every_named_gate_id_exists_in_the_registry(items: list[Item]) -> None:
    known = set(REQUIRED_LIVE_GATE_IDS)
    unknown = sorted(
        {gid for i in items for gid in i.gate_ids if gid not in known}
    )
    assert not unknown, f"checklist names gate ids that LIVE_GATES does not define: {unknown}"


def test_every_registry_gate_has_a_checklist_line(items: list[Item]) -> None:
    """A gate only code knows about is invisible to the operators who read the page."""

    named = {gid for i in items for gid in i.gate_ids}
    missing = [g for g in REQUIRED_LIVE_GATE_IDS if g not in named]
    assert not missing, f"LIVE_GATES ids with no line in the checklist: {missing}"


def test_no_gate_id_is_claimed_by_two_items(items: list[Item]) -> None:
    """One gate, one line — otherwise a flip to [x] on one line hides the other."""

    seen: dict[str, Item] = {}
    duplicates = []
    for item in items:
        for gid in item.gate_ids:
            if gid in seen:
                duplicates.append((gid, seen[gid], item))
            else:
                seen[gid] = item
    assert not duplicates, f"gate ids claimed by more than one checklist item: {duplicates}"


def test_the_exempt_section_is_the_only_one_that_needs_the_exemption(
    items: list[Item],
) -> None:
    """Keep the exemption honest: it must still be load-bearing and still be small."""

    exempt_open = [i for i in items if i.section in EXEMPT_SECTIONS and i.state == " "]
    assert exempt_open, (
        "the exemption no longer covers any open item — delete it rather than "
        "leaving a standing hole in the rule"
    )
    assert all(not i.gate_ids for i in exempt_open), (
        "an exempt item names a gate id, so it is not a meta-gate after all"
    )


def test_readiness_still_fails_closed_with_every_gate_the_checklist_shows_open(
    items: list[Item],
) -> None:
    """Certifying only the closed gates must not produce ready=True.

    This is the property the drift broke. It is asserted against the checklist's
    own view of what is open, so it keeps holding as gates close one by one.
    """

    open_ids = {
        gid
        for i in items
        if i.state == " "
        for gid in i.gate_ids
    }
    assert open_ids, "no gate is open — this test has outlived its purpose, delete it"

    certifications = [
        {
            "gate_id": gate_id,
            "certified": True,
            "evidence_ref": "https://example.invalid/evidence",
        }
        for gate_id in REQUIRED_LIVE_GATE_IDS
        if gate_id not in open_ids
    ]
    readiness = evaluate_live_gate_readiness(certifications)
    assert readiness.ready is False
    assert set(readiness.missing_gate_ids) == open_ids


RUNBOOK = Path(__file__).resolve().parents[1] / "docs" / "live-flip-runbook.md"

_RUNBOOK_ROW = re.compile(r"^\| `(?P<gate_id>[a-z0-9_]+)` \| (?P<category>[^|]+)\|")


def _runbook_rows() -> dict[str, str]:
    rows: dict[str, str] = {}
    for raw in RUNBOOK.read_text(encoding="utf-8").splitlines():
        match = _RUNBOOK_ROW.match(raw)
        if match:
            rows[match.group("gate_id")] = match.group("category").strip()
    return rows


def test_the_runbook_table_lists_exactly_the_registry_gates() -> None:
    """The runbook is the third hand-maintained copy; hold it to the same rule."""

    rows = _runbook_rows()
    assert rows, "parsed no gate rows from the runbook — the table format changed"
    assert set(rows) == set(REQUIRED_LIVE_GATE_IDS), (
        f"runbook only: {sorted(set(rows) - set(REQUIRED_LIVE_GATE_IDS))}; "
        f"registry only: {sorted(set(REQUIRED_LIVE_GATE_IDS) - set(rows))}"
    )


def test_the_runbook_states_each_gates_real_category() -> None:
    rows = _runbook_rows()
    for gate_id, category, _summary in LIVE_GATES:
        # The runbook annotates some rows ("software (done)"), so compare the
        # leading word rather than demanding an exact string.
        assert rows[gate_id].split()[0].lower() == category, (
            f"{gate_id}: runbook says {rows[gate_id]!r}, registry says {category!r}"
        )


def test_registry_entries_are_well_formed() -> None:
    """Shape guard: ids unique, categories known, summaries non-empty."""

    ids = [g[0] for g in LIVE_GATES]
    assert len(ids) == len(set(ids)), "duplicate gate id in LIVE_GATES"
    for gate_id, category, summary in LIVE_GATES:
        assert category in {"hil", "portability", "deployment", "software"}, gate_id
        assert summary.strip(), gate_id
