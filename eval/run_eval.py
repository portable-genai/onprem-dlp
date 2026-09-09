"""Quality gate over the golden sets. Runs offline on the local profile.

    python eval/run_eval.py

Gates (tuned to the deterministic stack; model profiles should only raise recall):
  unstructured English   precision >= 0.90, recall >= 0.85
  unstructured Japanese  precision >= 0.90, recall >= 0.85
  structured             column-category accuracy >= 0.85
  block-entity safety    recall >= 0.99 (strictest threshold)

Every metric here is scored through ``DlpOrchestrator.scan_text``, the SAME entry point the
product runs, and over the golden set's WHOLE label set.

It used to be scored through ``TextDetectionService.scan`` with an ``evaluated_entities`` filter
built from ``detector.recognizers``, which quietly restricted both the expected labels and the
predicted findings to the entity types the regex stack declares. That filter took the Presidio
NER analyzer, the Tesseract OCR path, the image redactor and the Gemma adjudicator out of the
measurement on both sides at once, so a false positive from a model path could not lower
precision and a label only a model path can produce could not lower recall. The README
meanwhile said those paths RAISE recall. A claim about a path is not evidence while the path is
filtered out of the measurement of it.

So the filter is gone, and what remains unmeasured is now PRINTED as unmeasured rather than
silently excluded. :func:`path_coverage` reports every detection path, what this profile binds
it to, and whether the corpus exercises it. A path bound to a null adapter contributes nothing
and is reported as such; a path bound to a real adapter with no labelled corpus behind it is
reported UNMEASURED, which is the honest state and the thing a reader has to be able to see.

Exit code 0 = pass, 1 = fail. Wire it into CI next to pytest.
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter
from collections.abc import Callable

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from onprem_dlp.adapters.local import CsvSampler  # noqa: E402
from onprem_dlp.config import Container, load_settings  # noqa: E402
from onprem_dlp.domain.detection_service import TextDetectionService  # noqa: E402
from onprem_dlp.domain.models import TextScanResult  # noqa: E402
from onprem_dlp.domain.orchestrator_service import DlpOrchestrator  # noqa: E402
from onprem_dlp.ports import ColumnSampler  # noqa: E402

#: What a scorer is handed: the product's own text-scan entry point. Typed as a callable so the
#: eval can be pointed at `DlpOrchestrator.scan_text` (the composed path, what the product runs)
#: or at `TextDetectionService.scan` (the regex stack alone) without either one being privileged
#: by the signature. It used to be the second, permanently.
Scanner = Callable[[str], "TextScanResult"]

P_MIN, R_MIN, ACC_MIN, BLOCK_RECALL_MIN = 0.90, 0.85, 0.85, 0.99
BLOCK_ENTITIES = frozenset(
    {
        "AU_MEDICARE",
        "AU_TFN",
        "CREDIT_CARD",
        "HK_HKID",
        "JP_MY_NUMBER",
        "PASSPORT",
        "SG_NRIC",
        "US_SSN",
    }
)


def eval_text_path(
    path: pathlib.Path,
    scanner: Scanner | None = None,
) -> tuple[float, float, list[str]]:
    """Precision and recall over EVERY label in the golden set, scored by ``scanner``.

    ``scanner`` is the callable the product runs (``DlpOrchestrator.scan_text``), not the regex
    service underneath it, so a finding contributed by a bound NER analyzer counts as a true or
    a false positive exactly as a regex finding does. There is deliberately no entity filter:
    filtering the predicted set hid false positives from every non-regex path, and filtering the
    expected set hid the labels only those paths can find.
    """
    scan = scanner or TextDetectionService().scan
    tp = fp = fn = 0
    failures: list[str] = []
    cases = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]

    positive_cases = sum(bool(case.get("expected")) for case in cases)
    negative_cases = len(cases) - positive_cases
    if not cases:
        return 0.0, 0.0, [f"  DATASET {path.name}: golden set is empty"]
    if not positive_cases:
        failures.append(f"  DATASET {path.name}: golden set has no positive case")
    if not negative_cases:
        failures.append(f"  DATASET {path.name}: golden set has no negative case")

    for case in cases:
        expected = Counter((item["type"], item["text"]) for item in case["expected"])
        predicted = Counter(
            (finding.entity_type.value, finding.text) for finding in scan(case["text"]).findings
        )
        tp += sum((expected & predicted).values())
        fp += sum((predicted - expected).values())
        fn += sum((expected - predicted).values())
        if predicted != expected:
            failures.append(
                f"  {case['id']}: missed={sorted((expected - predicted).elements())} "
                f"spurious={sorted((predicted - expected).elements())}"
            )
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    if not positive_cases:
        recall = 0.0
    if not negative_cases:
        precision = 0.0
    return precision, recall, failures


def eval_text(
    golden_file: str = "text_golden.jsonl",
    scanner: Scanner | None = None,
) -> tuple[float, float, list[str]]:
    return eval_text_path(REPO / "eval" / "golden" / golden_file, scanner)


def eval_block_entity_recall(
    scanner: Scanner | None = None,
    block_entities: frozenset[str] | None = None,
) -> tuple[float, list[str]]:
    """Measure release-critical identifiers with the golden labels as the independent oracle."""
    if scanner is None or block_entities is None:
        orchestrator, configured_blocks = configured_eval_runtime()
        scanner = scanner or orchestrator.scan_text
        block_entities = block_entities or configured_blocks
    expected_total = detected_total = 0
    failures: list[str] = []
    for path in sorted((REPO / "eval" / "golden").glob("text*_golden.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            case = json.loads(line)
            expected = Counter(
                (item["type"], item["text"])
                for item in case["expected"]
                if item["type"] in block_entities
            )
            predicted = Counter(
                (finding.entity_type.value, finding.text)
                for finding in scanner(case["text"]).findings
                if finding.entity_type.value in block_entities
            )
            expected_total += sum(expected.values())
            detected_total += sum((expected & predicted).values())
            missed = expected - predicted
            if missed:
                failures.append(
                    f"  {case['id']}: missed block entities={sorted(missed.elements())}"
                )
    if expected_total == 0:
        return 0.0, ["  DATASET: no block-listed positive examples"]
    return detected_total / expected_total, failures


def configured_eval_runtime() -> tuple[DlpOrchestrator, frozenset[str]]:
    """Build the eval stack through the exact runtime config/profile resolution path."""
    settings = load_settings()
    orchestrator = Container(settings).orchestrator()
    return orchestrator, frozenset(
        entity.value for entity in orchestrator.egress.policy.block_entities
    )


def configured_eval_policy() -> tuple[TextDetectionService, frozenset[str]]:
    """Compatibility helper returning configured detection and the configured block list."""
    orchestrator, block_entities = configured_eval_runtime()
    return orchestrator.detection, block_entities


#: Every detection path this service composes, with the label kind each one contributes and
#: the corpus that would have to exist to measure it. The point of the table is that a path
#: with nothing behind it says so, out loud, in the gate's own output: the previous runner
#: filtered these four out of both the expected and the predicted set, which made a path with
#: no measurement indistinguishable from a path that passed.
DETECTION_PATHS: tuple[tuple[str, str, str], ...] = (
    (
        "regex recognizers",
        "detection",
        "eval/golden/text*_golden.jsonl, labelled per span",
    ),
    (
        "NER analyzer",
        "ner",
        "no labelled corpus: person and address spans are not labelled in the golden set",
    ),
    (
        "LLM adjudicator",
        "adjudicator",
        "no labelled corpus: no case carries a hand-written adjudication verdict",
    ),
    (
        "OCR + image redactor",
        "ocr",
        "no labelled corpus: no image fixture carries labelled pixel boxes",
    ),
)


def path_coverage(orchestrator: DlpOrchestrator) -> list[tuple[str, str, str]]:
    """One ``(path, binding, status)`` row per detection path, measured or not.

    ``status`` is one of:

    * ``MEASURED``   the golden set labels what this path contributes and the numbers above
      include it, false positives included;
    * ``inactive``   this profile binds a null adapter, so the path contributes nothing here
      and there is nothing to measure. Not a gap, a configuration;
    * ``UNMEASURED`` the path is bound to a real adapter and no labelled corpus scores it. This
      is the honest state, and it is printed rather than filtered away, because the README's
      claim that these paths raise recall is exactly the claim nothing here can support yet.
    """
    rows: list[tuple[str, str, str]] = []
    for name, attribute, corpus in DETECTION_PATHS:
        if attribute == "detection":
            rows.append((name, type(orchestrator.detection).__name__, f"MEASURED ({corpus})"))
            continue
        if attribute == "ocr":
            # OCR is not held on the orchestrator: `scan_image` takes the engine per call, so
            # what a profile configures is only reachable through the container.
            rows.append((name, "per-call OcrEngine", f"UNMEASURED ({corpus})"))
            continue
        bound = getattr(orchestrator, attribute, None)
        binding = type(bound).__name__ if bound is not None else "unbound"
        if bound is None or binding.startswith("Null"):
            rows.append((name, binding, "inactive on this profile: contributes nothing"))
        else:
            rows.append((name, binding, f"UNMEASURED ({corpus})"))
    return rows


def eval_columns(
    orchestrator: DlpOrchestrator | None = None,
    sampler: ColumnSampler | None = None,
    expected: dict[str, str] | None = None,
) -> tuple[float, list[str]]:
    """Evaluate structured classification through the configured runtime profiler."""
    if orchestrator is None:
        orchestrator, _ = configured_eval_runtime()
    if expected is None:
        expected = json.loads((REPO / "eval" / "golden" / "columns_expected.json").read_text())
    sampler = sampler or CsvSampler(str(REPO / "demo" / "customers.csv"))
    dataset = orchestrator.classify_columns(sampler)
    got = {c.profile.name: c.category.value for c in dataset.columns}
    failures = [
        f"  {col}: expected {want}, got {got.get(col, 'MISSING')}"
        for col, want in expected.items()
        if got.get(col) != want
    ]
    accuracy = 1 - len(failures) / len(expected) if expected else 1.0
    return accuracy, failures


def main() -> int:
    orchestrator, block_entities = configured_eval_runtime()
    # The COMPOSED path, which is what the product runs. Scoring `orchestrator.detection.scan`
    # measured the regex stack and called the result a measurement of the service.
    scanner = orchestrator.scan_text
    precision, recall, text_failures = eval_text(scanner=scanner)
    ja_precision, ja_recall, ja_failures = eval_text("text_ja_golden.jsonl", scanner)
    accuracy, column_failures = eval_columns(orchestrator)
    block_recall, block_failures = eval_block_entity_recall(scanner, block_entities)

    print(
        f"unstructured/en: precision={precision:.3f} (gate {P_MIN}) "
        f"recall={recall:.3f} (gate {R_MIN})"
    )
    print(*text_failures, sep="\n") if text_failures else None
    print(
        f"unstructured/ja: precision={ja_precision:.3f} (gate {P_MIN}) "
        f"recall={ja_recall:.3f} (gate {R_MIN})"
    )
    print(*ja_failures, sep="\n") if ja_failures else None
    print(f"structured:   column accuracy={accuracy:.3f} (gate {ACC_MIN})")
    print(*column_failures, sep="\n") if column_failures else None
    print(f"safety/block: recall={block_recall:.3f} (gate {BLOCK_RECALL_MIN})")
    print(*block_failures, sep="\n") if block_failures else None

    print("\ndetection paths (what the numbers above do and do not cover):")
    width = max(len(name) for name, _, _ in DETECTION_PATHS)
    for name, binding, status in path_coverage(orchestrator):
        print(f"  {name.ljust(width)}  {binding:<24} {status}")

    ok = (
        precision >= P_MIN
        and recall >= R_MIN
        and ja_precision >= P_MIN
        and ja_recall >= R_MIN
        and accuracy >= ACC_MIN
        and block_recall >= BLOCK_RECALL_MIN
    )
    print("EVAL", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
