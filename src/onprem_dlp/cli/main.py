"""`onprem-dlp` CLI — the operator surface for both solutions.

Exit codes are CI-gate friendly:
  0 = clean / ALLOW,  3 = REDACT needed,  4 = BLOCK (or --fail-on-pii hit),  2 = usage.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from ..config import Container, load_settings
from ..domain.models import (
    ColumnCategory,
    DatasetClassification,
    EgressAction,
    EgressDecision,
    RedactedText,
    TextScanResult,
)
from ..netguard import ConfiguredEmptyError

EXIT_ALLOW, EXIT_REDACT, EXIT_BLOCK = 0, 3, 4


def _read_text(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.file == "-" or args.file is None:
        return sys.stdin.read()
    return Path(args.file).read_text(encoding="utf-8")


def _to_jsonable(obj):  # dataclasses -> plain dicts, enums -> values
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    if hasattr(obj, "value") and not isinstance(obj, (int, float, str, bool)):
        return obj.value
    return obj


def _print_scan(scan: TextScanResult) -> None:
    if not scan.findings:
        print("no findings")
        return
    print(f"{len(scan.findings)} finding(s) in {scan.source_id or 'input'}:")
    for f in scan.findings:
        marks = "".join(m for m, on in (("✓", f.validated), ("~", f.context_boosted)) if on)
        print(
            f"  [{f.start:>5}:{f.end:<5}] {f.entity_type.value:<16} conf={f.confidence:.2f} "
            f"{marks:<2} via {f.recognizer}  {f.text!r}"
        )


def _print_decision(decision: EgressDecision) -> None:
    print(f"egress decision for {decision.source_id or 'input'}: {decision.action.value}")
    for r in decision.reasons:
        print(f"  [{r.severity.value:<6}] {r.summary} — {r.detail}")
    if decision.escalates:
        print("  → BLOCK escalates to human review; nothing was sent.")


def _print_dataset(ds: DatasetClassification) -> None:
    width = max((len(f"{c.profile.table}.{c.profile.name}") for c in ds.columns), default=10)
    print(f"column classification for {ds.source}:")
    print(f"  {'column'.ljust(width)}  {'category':<12} {'score':<6} {'entity':<16} action")
    for c in ds.columns:
        flag = " ⚠ needs human review" if c.needs_review else ""
        name = f"{c.profile.table}.{c.profile.name}"
        print(
            f"  {name.ljust(width)}  {c.category.value:<12} {c.score:<6.2f} "
            f"{(c.entity_type.value if c.entity_type else '-'):<16} {c.recommended_action}{flag}"
        )
        for s in c.signals:
            print(f"      {'+' if s.weight >= 0 else ''}{s.weight:.2f}  {s.detail}")


def _decision_exit(decision: EgressDecision) -> int:
    return {
        EgressAction.ALLOW: EXIT_ALLOW,
        EgressAction.REDACT: EXIT_REDACT,
        EgressAction.BLOCK: EXIT_BLOCK,
    }[decision.action]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="onprem-dlp",
        description="On-prem DLP gate: scrub text, images and schemas before cloud egress.",
    )
    parser.add_argument("--config", help="settings file (default: config/settings.yaml)")
    parser.add_argument("--profile", help="adapter profile (default from settings)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_text_source(p: argparse.ArgumentParser) -> None:
        group = p.add_mutually_exclusive_group()
        group.add_argument("--text", help="literal text to process")
        group.add_argument("--file", help="path to a UTF-8 text file, or - for stdin")

    p = sub.add_parser("scan-text", help="detect PII in free text")
    add_text_source(p)

    p = sub.add_parser("redact-text", help="detect and redact PII in free text")
    add_text_source(p)
    p.add_argument("--out", help="write redacted text here instead of stdout")

    p = sub.add_parser("decide", help="egress decision: ALLOW(0) / REDACT(3) / BLOCK(4)")
    add_text_source(p)

    p = sub.add_parser("scan-image", help="OCR an image and detect PII")
    p.add_argument("image")

    p = sub.add_parser("redact-image", help="black out PII regions in an image copy")
    p.add_argument("image")
    p.add_argument("--out", required=True, help="output image path")

    p = sub.add_parser(
        "classify-columns",
        help="classify CSV / SQLite / Postgres / MySQL / BigQuery columns as PII vs non-PII",
    )
    p.add_argument(
        "source",
        help=".csv, .db/.sqlite, postgres:// or mysql:// DSN, or bigquery://project/dataset",
    )
    p.add_argument("--sample", type=int, default=None, help="values sampled per column")
    p.add_argument(
        "--fail-on-pii",
        action="store_true",
        help="exit 4 if any PII_DIRECT or SENSITIVE column is found (CI gate)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        container = Container(load_settings(args.config), profile=args.profile)
    except (ConfiguredEmptyError, FileNotFoundError, ValueError) as exc:
        # A refused configuration read is a usage error, not a crash: an operator whose
        # Secret rendered empty should see the variable name, not a traceback. Exit 2 keeps
        # the documented contract, and it is NOT 0, so a CI gate never reads a refusal as a
        # clean scan.
        print(f"onprem-dlp: {exc}", file=sys.stderr)
        return 2
    orch = container.orchestrator()

    if args.command == "scan-text":
        scan = orch.scan_text(_read_text(args), source_id=args.file or "text")
        print(json.dumps(_to_jsonable(scan), indent=2)) if args.json else _print_scan(scan)
        return EXIT_ALLOW

    if args.command == "redact-text":
        redacted: RedactedText = orch.redact_text(_read_text(args), source_id=args.file or "text")
        if args.json:
            print(json.dumps(_to_jsonable(redacted), indent=2))
        elif args.out:
            Path(args.out).write_text(redacted.text, encoding="utf-8")
            print(f"wrote {args.out} ({len(redacted.applied)} redaction(s))")
        else:
            print(redacted.text)
        return EXIT_ALLOW

    if args.command == "decide":
        decision = orch.decide_egress(_read_text(args), source_id=args.file or "text")
        print(json.dumps(_to_jsonable(decision), indent=2)) if args.json else _print_decision(
            decision
        )
        return _decision_exit(decision)

    if args.command in ("scan-image", "redact-image"):
        ocr = container.ocr()
        result = orch.scan_image(args.image, ocr)
        if args.command == "scan-image":
            if args.json:
                print(json.dumps(_to_jsonable(result), indent=2))
            else:
                _print_scan(result.scan)
                print(f"{len(result.boxes)} pixel box(es) cover the findings")
            return EXIT_ALLOW
        redactor = container.image_redactor()
        out = redactor.redact(args.image, result.boxes, args.out)
        print(f"wrote {out}: {len(result.boxes)} region(s) blacked out, metadata stripped")
        return EXIT_ALLOW

    if args.command == "classify-columns":
        sampler = container.sampler(args.source)
        try:
            sample_limit = args.sample if args.sample is not None else container.sample_limit()
            dataset = orch.classify_columns(sampler, sample_limit=sample_limit)
        finally:
            close = getattr(sampler, "close", None)
            if close is not None:
                close()
        print(json.dumps(_to_jsonable(dataset), indent=2)) if args.json else _print_dataset(dataset)
        if args.fail_on_pii and any(
            c.category in (ColumnCategory.PII_DIRECT, ColumnCategory.SENSITIVE)
            for c in dataset.columns
        ):
            return EXIT_BLOCK
        return EXIT_ALLOW

    return 2  # pragma: no cover — argparse enforces the command set


if __name__ == "__main__":
    raise SystemExit(main())
