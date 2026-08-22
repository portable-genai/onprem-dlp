"""Tamper-evident, append-only JSONL audit sink using only the standard library.

The hash chain detects modification, deletion and reordering inside the log. The sidecar head
anchor detects truncation of the tail when it is protected independently by the mounted store or
SIEM. It cannot stop an administrator who can rewrite both files; that operational limit is
deliberate and documented rather than presented as WORM storage.

The anchor travels with the export. A head anchor that only ever sits beside its own log guards
that directory and nothing downstream: hand someone the record lines with the newest ones deleted
and the shorter chain verifies perfectly, because the head it should have ended on stayed behind.
So an export is an anchor header line, ``{"anchor": <head>, "format", "records"}``, followed by
the record lines exactly as they sit in the log, and a restore checks the records it was handed
against the head that came with them and refuses a mismatch. A restore never derives a head from
its own payload: an anchor minted from a truncated payload witnesses only the truncation. An
export written before the header existed still restores, and is left with no anchor at all, so
:meth:`JsonlAuditSink.verify_chain` reports it as unanchored until an operator who has checked the
trail out of band calls :meth:`JsonlAuditSink.reanchor`.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ...domain.kernel import AuditEvent, utcnow

GENESIS = "0" * 64

EXPORT_FORMAT = "onprem-dlp.audit-jsonl.v1"

#: Record fields the SERVER establishes. A caller's payload may not supply any of them.
#:
#: These are the fields that answer who did what and when, plus the two chain fields. Building
#: the row with ``ts``, ``kind`` and ``source_id`` BEFORE ``**payload`` lets later keys win in
#: the dict literal, so a payload carrying those names replaces the server's values and the
#: replacement is hashed into the chain. The result is worse than a lost field: the chain
#: verifies, the anchor matches, and the ledger attests the forged attribution. In this system
#: the payload derives from scanned content, so that path is plausibly influenced rather than
#: purely internal.
#:
#: ``prev_hash`` and ``hash`` are unreachable that way, being written after the payload, and are
#: listed anyway so the set is the full record vocabulary rather than the subset that happens to
#: be exploitable under one field ordering.
_RESERVED_FIELDS = frozenset({"ts", "kind", "source_id", "prev_hash", "hash"})


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _walk_records(lines: list[str], *, first_line_no: int = 1) -> str:
    """Re-derive every hash over ``lines`` in order and return the head they end on.

    The one place that says what a broken chain looks like, so the stored log and an arriving
    export payload can never be checked to different standards.
    """
    previous = GENESIS
    for line_no, line in enumerate(lines, first_line_no):
        try:
            record = json.loads(line)
            claimed = record.pop("hash")
        except (json.JSONDecodeError, KeyError, AttributeError) as exc:
            raise ValueError(f"invalid audit record at line {line_no}") from exc
        if record.get("prev_hash") != previous:
            raise ValueError(f"broken audit predecessor at line {line_no}")
        if hashlib.sha256(_canonical(record)).hexdigest() != claimed:
            raise ValueError(f"audit hash mismatch at line {line_no}")
        previous = claimed
    return previous


def _split_export(payload: str) -> tuple[dict | None, list[str], int]:
    """Separate an export's anchor header from its record lines.

    A header is told apart from a record by shape: every record carries ``hash``, and the
    header carries ``anchor`` and no ``hash``. That matters here because a record flattens the
    event payload into the top-level object, so an event field happening to be called "anchor"
    must not be mistaken for a witness. A payload with no header is a pre-anchor export, which
    still restores; an anchor line anywhere but the first line has no ``hash``, so the record
    walk rejects it as an invalid record.
    """
    lines = payload.splitlines()
    if not lines:
        return None, [], 1
    try:
        first = json.loads(lines[0])
    except json.JSONDecodeError:
        return None, lines, 1  # not JSON at all: let the record walk report the bad line
    if not isinstance(first, dict) or "hash" in first or "anchor" not in first:
        return None, lines, 1
    return _anchor_header(first), lines[1:], 2


def _anchor_header(header: dict) -> dict:
    """Validate the header and return ``{"anchor": <head>, "records": <count>}``."""
    if header.get("format") != EXPORT_FORMAT:
        raise ValueError(
            f"unsupported audit export format {header.get('format')!r}: expected "
            f"{EXPORT_FORMAT!r}, so the anchor cannot be interpreted"
        )
    head, records = header.get("anchor"), header.get("records")
    if not isinstance(head, str) or not isinstance(records, int):
        raise ValueError("malformed audit export anchor header")
    return {"anchor": head, "records": records}


class JsonlAuditSink:
    """Hash-chained JSONL with verification, export and fail-closed restore."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.anchor_path = f"{path}.head"
        self.lock_path = f"{path}.lock"
        # Set by restore_jsonl() when the payload carried no anchor header: the trail loaded,
        # but nothing witnesses its tail. The absent anchor file records the same fact on disk,
        # which is what makes verify_chain() keep saying so in a later process.
        self.restored_unanchored = False
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: AuditEvent) -> None:
        reserved = _RESERVED_FIELDS.intersection(event.payload)
        if reserved:
            raise ValueError(
                "audit payload names reserved record fields "
                f"{sorted(reserved)}: these are established by the server and a caller may "
                "not supply them. Rename the payload key."
            )
        with self._exclusive_lock():
            previous = self._verify_unlocked()
            body = {
                **event.payload,
                # Written AFTER the payload, because later keys win in a dict literal. This
                # is the structural half of the guard: the attribution cannot be forged even
                # if the refusal above is ever removed or bypassed.
                "ts": utcnow().isoformat(),
                "kind": event.kind,
                "source_id": event.source_id,
                "prev_hash": previous,
            }
            body["hash"] = hashlib.sha256(_canonical(body)).hexdigest()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, ensure_ascii=False, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._write_anchor(body["hash"])

    def verify_chain(self) -> str:
        """Verify every record and the external head; return the verified head hash."""
        with self._file_lock(fcntl.LOCK_SH):
            return self._verify_unlocked()

    def _verify_unlocked(self) -> str:
        previous = self._walk_log()
        if os.path.exists(self.anchor_path):
            anchored = Path(self.anchor_path).read_text(encoding="ascii").strip()
            if anchored != previous:
                raise ValueError("audit head anchor does not match the log")
        elif previous != GENESIS:
            raise ValueError(
                "audit head anchor is missing: the tail of this trail has no external witness, "
                "so records dropped from the end cannot be detected. Check the trail out of "
                "band against its source, then call reanchor()"
            )
        return previous

    def _walk_log(self) -> str:
        """The chain head the stored log ends on, with no external cross-check."""
        if not os.path.exists(self.path):
            return GENESIS
        return _walk_records(Path(self.path).read_text(encoding="utf-8").splitlines())

    def reanchor(self) -> str:
        """Deliberately establish the head anchor from the log as it now stands.

        The operator escape hatch, never reached from the append path and never from a
        restore: it asserts nothing about the past, so use it only after checking the trail out
        of band (against the source system, or an export held elsewhere).
        """
        with self._exclusive_lock():
            previous = self._walk_log()
            self._write_anchor(previous)
            self.restored_unanchored = False
            return previous

    def export_jsonl(self) -> str:
        """Return a verified, open-format export: anchor header line, then the record lines.

        Line 1 is ``{"anchor": <head hash>, "format": ..., "records": <count>}``, the head this
        export commits to. A receiving team verifies the whole file with SHA-256 and a JSON
        parser and nothing from this codebase: walk the records deriving each
        ``SHA-256(canonical record without its "hash")``, check each ``prev_hash`` against the
        one before, and check the last hash against the header. An export with lines dropped
        from the end fails that last check, which is the one case the chain alone cannot see.
        A rewrite of the whole file, header included, remains undetectable from the file alone;
        that needs the head over a second channel, and is the same documented limit as before.
        """
        with self._file_lock(fcntl.LOCK_SH):
            head = self._verify_unlocked()
            body = Path(self.path).read_text(encoding="utf-8") if os.path.exists(self.path) else ""
        header = {"anchor": head, "format": EXPORT_FORMAT, "records": len(body.splitlines())}
        return json.dumps(header, ensure_ascii=False, sort_keys=True) + "\n" + body

    @classmethod
    def restore_jsonl(cls, path: str, payload: str, *, overwrite: bool = False) -> JsonlAuditSink:
        """Restore a valid chain; refuse replacement of non-empty evidence by default.

        The records are checked against the anchor that travelled in the export, and a payload
        whose records do not end on that head is refused: it lost (or gained) records after the
        export was written. The restored log keeps its own anchor file from that same travelled
        head, never from a walk of the payload, because a head derived from the payload agrees
        with the payload by construction and so witnesses nothing.

        A pre-anchor payload (no header) still restores, and is deliberately left with no anchor
        file: ``verify_chain`` then reports the trail as unanchored, which is the honest answer
        until an operator checks it out of band and calls :meth:`reanchor`.
        """
        target = cls(path)
        anchor, records, first_line_no = _split_export(payload)
        head = _walk_records(records, first_line_no=first_line_no)
        if anchor is not None:
            # The head is the cryptographic check and answers first; the count is a cheap
            # cross-check that also lets a human read the file and see what it should hold.
            if anchor["anchor"] != head:
                raise ValueError(
                    f"restored records end at {head} but the export is anchored to "
                    f"{anchor['anchor']}: records are missing from the tail (the export was "
                    "truncated or rewritten in transit)"
                )
            if anchor["records"] != len(records):
                raise ValueError(
                    f"audit export carries {len(records)} record(s) but is anchored to "
                    f"{anchor['records']}: records were added or removed in transit"
                )
        body = "".join(f"{line}\n" for line in records)
        parent = str(Path(path).parent)
        with target._exclusive_lock():
            if os.path.exists(path) and os.path.getsize(path) > 0 and not overwrite:
                raise FileExistsError(
                    "refusing to overwrite a non-empty audit log; pass overwrite=True "
                    "only after preserving the existing evidence"
                )
            fd, temporary = tempfile.mkstemp(prefix=".audit-restore-", dir=parent, text=True)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(body)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(temporary, path)
                if anchor is None:
                    # No witness arrived, so leave none behind: any anchor still sitting here
                    # belongs to the log this restore just replaced.
                    Path(target.anchor_path).unlink(missing_ok=True)
                    target.restored_unanchored = True
                else:
                    target._write_anchor(anchor["anchor"])
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        if anchor is not None:
            target.verify_chain()
        return target

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        """Serialize writers across threads and worker processes on the mounted filesystem."""
        with self._file_lock(fcntl.LOCK_EX):
            yield

    @contextmanager
    def _file_lock(self, operation: int) -> Iterator[None]:
        with open(self.lock_path, "a", encoding="ascii") as lock:
            fcntl.flock(lock.fileno(), operation)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _write_anchor(self, value: str) -> None:
        parent = str(Path(self.anchor_path).parent)
        fd, temporary = tempfile.mkstemp(prefix=".audit-head-", dir=parent, text=True)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(value + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temporary, self.anchor_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
