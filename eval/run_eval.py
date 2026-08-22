"""Quality gate over the golden sets. Runs offline on the local profile.

    python eval/run_eval.py

Gates (tuned to the deterministic stack; model profiles should only raise recall):
  unstructured English   precision >= 0.90, recall >= 0.85
  unstructured Japanese  precision >= 0.90, recall >= 0.85
  structured             column-category accuracy >= 0.85
  block-entity safety    recall >= 0.99 (strictest threshold)

Exit code 0 = pass, 1 = fail — wire it into CI next to pytest.
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from onprem_dlp.adapters.local import CsvSampler  # noqa: E402
from onprem_dlp.config import Container, load_settings  # noqa: E402
from onprem_dlp.domain.detection_service import TextDetectionService  # noqa: E402
from onprem_dlp.domain.orchestrator_service import DlpOrchestrator  # noqa: E402
from onprem_dlp.ports import ColumnSampler  # noqa: E402

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
    detector: TextDetectionService | None = None,
    evaluated_entities: frozenset[str] | None = None,
) -> tuple[float, float, list[str]]:
    detector = detector or TextDetectionService()
    tp = fp = fn = 0
    failures: list[str] = []
    cases = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]

    def in_scope(item: dict) -> bool:
        return evaluated_entities is None or item["type"] in evaluated_entities

    positive_cases = sum(any(in_scope(item) for item in case.get("expected", ())) for case in cases)
    negative_cases = len(cases) - positive_cases
    if not cases:
        return 0.0, 0.0, [f"  DATASET {path.name}: golden set is empty"]
    if not positive_cases:
        failures.append(f"  DATASET {path.name}: golden set has no positive case")
    if not negative_cases:
        failures.append(f"  DATASET {path.name}: golden set has no negative case")

    for case in cases:
        expected = Counter(
            (item["type"], item["text"]) for item in case["expected"] if in_scope(item)
        )
        predicted = Counter(
            (finding.entity_type.value, finding.text)
            for finding in detector.scan(case["text"]).findings
            if evaluated_entities is None or finding.entity_type.value in evaluated_entities
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
    detector: TextDetectionService | None = None,
    evaluated_entities: frozenset[str] | None = None,
) -> tuple[float, float, list[str]]:
    return eval_text_path(
        REPO / "eval" / "golden" / golden_file,
        detector,
        evaluated_entities,
    )


def eval_block_entity_recall(
    detector: TextDetectionService | None = None,
    block_entities: frozenset[str] | None = None,
) -> tuple[float, list[str]]:
    """Measure release-critical identifiers with the golden labels as the independent oracle."""
    if detector is None or block_entities is None:
        configured_detector, configured_blocks = configured_eval_policy()
        detector = detector or configured_detector
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
                for finding in detector.scan(case["text"]).findings
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
    detector = orchestrator.detection
    evaluated_entities = frozenset(
        recognizer.entity_type.value for recognizer in detector.recognizers
    )
    precision, recall, text_failures = eval_text(
        detector=detector,
        evaluated_entities=evaluated_entities,
    )
    ja_precision, ja_recall, ja_failures = eval_text(
        "text_ja_golden.jsonl",
        detector,
        evaluated_entities,
    )
    accuracy, column_failures = eval_columns(orchestrator)
    block_recall, block_failures = eval_block_entity_recall(detector, block_entities)

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
