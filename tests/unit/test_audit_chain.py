"""Tamper detection and portable export/restore for the stdlib audit sink."""

import json

import pytest

from onprem_dlp.adapters.local import JsonlAuditSink
from onprem_dlp.adapters.local.audit import EXPORT_FORMAT
from onprem_dlp.domain.models import AuditEvent


def _sink_with(tmp_path, name: str, count: int) -> JsonlAuditSink:
    sink = JsonlAuditSink(str(tmp_path / name))
    for index in range(count):
        sink.record(AuditEvent("decision", "fictional", {"action": "BLOCK", "index": index}))
    return sink


def test_chain_export_restore_and_tail_anchor(tmp_path) -> None:
    sink = JsonlAuditSink(str(tmp_path / "audit.jsonl"))
    sink.record(AuditEvent("scan", "fictional", {"findings": {"SG_NRIC": 1}}))
    sink.record(AuditEvent("decision", "fictional", {"action": "BLOCK"}))
    exported = sink.export_jsonl()
    assert "S1234567D" not in exported
    restored = JsonlAuditSink.restore_jsonl(str(tmp_path / "restored.jsonl"), exported)
    assert restored.export_jsonl() == exported

    records = exported.splitlines()[1:]  # line 1 is the anchor header
    (tmp_path / "audit.jsonl").write_text(records[0] + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="head anchor"):
        sink.verify_chain()


def test_the_export_carries_the_head_anchor(tmp_path) -> None:
    """The witness has to travel with the evidence, or it guards only its own directory."""
    sink = _sink_with(tmp_path, "audit.jsonl", 3)
    lines = sink.export_jsonl().splitlines()

    header = json.loads(lines[0])
    assert header["format"] == EXPORT_FORMAT
    assert header["records"] == 3
    assert header["anchor"] == sink.verify_chain()
    assert "hash" not in header  # told apart from a record by shape, not by position alone
    assert all("hash" in json.loads(line) for line in lines[1:])
    # The restored log file itself stays a pure record log: the header is export framing.
    JsonlAuditSink.restore_jsonl(str(tmp_path / "restored.jsonl"), "\n".join(lines))
    assert (tmp_path / "restored.jsonl").read_text(encoding="utf-8").splitlines() == lines[1:]


def test_a_truncated_export_is_refused_on_restore(tmp_path) -> None:
    """The whole point. Drop the newest decisions from an export and the receiver must say so.

    RED before the anchor-header fix: export_jsonl() returned the record lines only, so the
    head anchor stayed behind in the source directory. restore_jsonl() then walked the payload
    it was handed, took that shorter chain's own last hash as the head, and wrote it out as a
    fresh anchor, so the truncated trail arrived self-consistent and verify_chain() confirmed
    it. Nothing in that path could detect the truncation even in principle.
    """
    sink = _sink_with(tmp_path, "audit.jsonl", 5)
    exported = sink.export_jsonl()
    truncated = "\n".join(exported.splitlines()[:-2]) + "\n"

    restored_path = tmp_path / "restored.jsonl"
    with pytest.raises(ValueError, match="anchored"):
        JsonlAuditSink.restore_jsonl(str(restored_path), truncated)

    # Refusing means nothing lands: no restored evidence, and no anchor minted for it.
    assert not restored_path.exists()
    assert not (tmp_path / "restored.jsonl.head").exists()


def test_a_truncation_with_a_doctored_record_count_is_still_refused(tmp_path) -> None:
    """Fixing up the header's record count does not help: the head is the real check."""
    sink = _sink_with(tmp_path, "audit.jsonl", 5)
    lines = sink.export_jsonl().splitlines()[:-2]
    header = json.loads(lines[0])
    header["records"] = len(lines) - 1  # made consistent with what is left
    lines[0] = json.dumps(header, ensure_ascii=False, sort_keys=True)

    with pytest.raises(ValueError, match="missing from the tail"):
        JsonlAuditSink.restore_jsonl(str(tmp_path / "restored.jsonl"), "\n".join(lines) + "\n")


def test_restore_adopts_the_exported_anchor_rather_than_minting_one(tmp_path) -> None:
    sink = _sink_with(tmp_path, "audit.jsonl", 3)
    restored = JsonlAuditSink.restore_jsonl(str(tmp_path / "restored.jsonl"), sink.export_jsonl())

    source_anchor = (tmp_path / "audit.jsonl.head").read_text(encoding="ascii")
    assert (tmp_path / "restored.jsonl.head").read_text(encoding="ascii") == source_anchor
    assert restored.verify_chain() == sink.verify_chain()


def test_a_pre_anchor_export_restores_but_is_reported_unanchored(tmp_path) -> None:
    """Backward compatibility, without laundering: old exports load, and say what they are.

    An export written before the header existed is still a valid chain, so it must still
    restore. What it can never be is verified: nothing in it witnesses the tail, so minting an
    anchor for it would recreate the same false negative under a new name.
    """
    sink = _sink_with(tmp_path, "audit.jsonl", 3)
    legacy = "\n".join(sink.export_jsonl().splitlines()[1:]) + "\n"

    restored_path = tmp_path / "restored.jsonl"
    restored = JsonlAuditSink.restore_jsonl(str(restored_path), legacy)

    assert restored_path.read_text(encoding="utf-8") == legacy  # it still restores
    assert restored.restored_unanchored is True
    assert not (tmp_path / "restored.jsonl.head").exists()  # and no anchor was minted
    with pytest.raises(ValueError, match="head anchor is missing"):
        restored.verify_chain()

    restored.reanchor()  # the deliberate operator action, after checking out of band
    assert restored.verify_chain() == sink.verify_chain()
    assert restored.restored_unanchored is False


def test_an_unanchored_restore_can_neither_be_appended_to_nor_re_exported(tmp_path) -> None:
    """Being unwitnessed does not wear off. Every path through the sink says so until an
    operator settles it, so one hop cannot launder "nothing witnesses this" into a fresh
    export that carries a head of its own.
    """
    sink = _sink_with(tmp_path, "audit.jsonl", 2)
    legacy = "\n".join(sink.export_jsonl().splitlines()[1:]) + "\n"
    restored = JsonlAuditSink.restore_jsonl(str(tmp_path / "restored.jsonl"), legacy)

    for attempt in (
        restored.export_jsonl,
        lambda: restored.record(AuditEvent("decision", "fictional", {"index": 9})),
    ):
        with pytest.raises(ValueError, match="head anchor is missing"):
            attempt()

    restored.reanchor()
    assert restored.export_jsonl().splitlines()[0].startswith('{"anchor"')


def test_a_mid_chain_tamper_in_the_payload_is_refused(tmp_path) -> None:
    sink = _sink_with(tmp_path, "audit.jsonl", 4)
    lines = sink.export_jsonl().splitlines()
    doctored = json.loads(lines[2])
    doctored["action"] = "ALLOW"
    lines[2] = json.dumps(doctored, ensure_ascii=False, sort_keys=True)

    with pytest.raises(ValueError, match="hash mismatch"):
        JsonlAuditSink.restore_jsonl(str(tmp_path / "restored.jsonl"), "\n".join(lines) + "\n")
    assert not (tmp_path / "restored.jsonl").exists()


def test_an_interior_deletion_from_the_payload_is_refused(tmp_path) -> None:
    sink = _sink_with(tmp_path, "audit.jsonl", 4)
    lines = sink.export_jsonl().splitlines()

    with pytest.raises(ValueError, match="broken audit predecessor"):
        JsonlAuditSink.restore_jsonl(
            str(tmp_path / "restored.jsonl"), "\n".join(lines[:2] + lines[3:]) + "\n"
        )


def test_modified_record_is_rejected(tmp_path) -> None:
    sink = JsonlAuditSink(str(tmp_path / "audit.jsonl"))
    sink.record(AuditEvent("scan", "fictional", {"count": 1}))
    record = json.loads(sink.export_jsonl().splitlines()[1])
    record["count"] = 2
    (tmp_path / "audit.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        sink.verify_chain()


def test_invalid_restore_does_not_replace_existing_evidence(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(str(path))
    sink.record(AuditEvent("scan", "fictional", {"count": 1}))
    original = sink.export_jsonl()
    with pytest.raises(ValueError, match="invalid audit record"):
        JsonlAuditSink.restore_jsonl(str(path), "not-json\n")
    assert sink.export_jsonl() == original


@pytest.mark.parametrize("replacement", ["", "shorter"])
def test_restore_refuses_empty_or_shorter_overwrite_by_default(tmp_path, replacement) -> None:
    path = tmp_path / "audit.jsonl"
    sink = _sink_with(tmp_path, "audit.jsonl", 2)
    original = sink.export_jsonl()
    # A shorter but perfectly valid export from somewhere else: refusing it is about not
    # overwriting evidence, so it must not depend on the replacement being malformed.
    payload = "" if replacement == "" else _sink_with(tmp_path, "other.jsonl", 1).export_jsonl()
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        JsonlAuditSink.restore_jsonl(str(path), payload)
    assert sink.export_jsonl() == original


# --------------------------------------------------------------------------- #
# The record owns its attribution; a payload cannot supply it.
#
# `record()` built the row as a dict literal placing "ts", "kind" and "source_id" BEFORE
# `**event.payload`. Later keys win in a dict literal, so a payload carrying those names
# replaced them, and the replaced values were then hashed into the chain. The chain verified,
# the anchor matched, and the ledger attested the forged attribution: the integrity mechanism
# working perfectly over corrupted content. In an append-only evidence store those three fields
# are what answer who did what and when.
#
# "prev_hash" and "hash" were never reachable, because they are written after the payload. A
# collision is not one finding: it is a question about ordering, and the answer differs per key.
#
# Both tests below were red against that form: the first one stored the forged values, and the
# second raised nothing at all.
# --------------------------------------------------------------------------- #

_RESERVED = ("ts", "kind", "source_id", "prev_hash", "hash")


def test_a_payload_cannot_overwrite_the_records_own_attribution(tmp_path) -> None:
    """Ordering: the server-established fields are written last, so they always win."""
    sink = JsonlAuditSink(str(tmp_path / "audit.jsonl"))
    sink.record(AuditEvent("classify_columns", "hr.employees", {"columns": 3}))
    row = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip())

    assert row["kind"] == "classify_columns"
    assert row["source_id"] == "hr.employees"
    assert row["columns"] == 3
    # The chain still closes over the record the server wrote.
    assert sink.verify_chain() == row["hash"]


@pytest.mark.parametrize("reserved", _RESERVED)
def test_a_payload_naming_a_reserved_field_is_refused_rather_than_dropped(
    tmp_path, reserved: str
) -> None:
    """Refusal: ordering alone would silently discard the caller's value instead.

    Writing the attribution last makes forgery impossible, but on its own it turns a payload
    key called ``ts`` into data that vanishes with no signal. The record refuses instead, so
    neither the attribution nor the caller's field is quietly lost.
    """
    sink = JsonlAuditSink(str(tmp_path / "audit.jsonl"))
    with pytest.raises(ValueError, match="reserved"):
        sink.record(AuditEvent("scan", "fictional", {reserved: "supplied-by-the-caller"}))
    # Nothing was written, so the refusal cannot itself corrupt the trail.
    assert (
        not (tmp_path / "audit.jsonl").exists()
        or not (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
    )
