import json
from pathlib import Path

from eval.run_eval import (
    BLOCK_RECALL_MIN,
    configured_eval_runtime,
    eval_block_entity_recall,
    eval_columns,
    eval_text_path,
)

from onprem_dlp.adapters.local.samplers import InlineSampler


def _write_cases(path: Path, cases: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(case) + "\n" for case in cases),
        encoding="utf-8",
    )


def test_eval_rejects_empty_and_one_sided_golden_sets(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    precision, recall, failures = eval_text_path(empty)
    assert (precision, recall) == (0.0, 0.0)
    assert "golden set is empty" in failures[0]

    positive_only = tmp_path / "positive.jsonl"
    _write_cases(
        positive_only,
        [
            {
                "id": "positive",
                "text": "email a@example.invalid",
                "expected": [{"type": "EMAIL_ADDRESS", "text": "a@example.invalid"}],
            }
        ],
    )
    precision, _, failures = eval_text_path(positive_only)
    assert precision == 0.0
    assert any("no negative case" in failure for failure in failures)

    negative_only = tmp_path / "negative.jsonl"
    _write_cases(
        negative_only,
        [{"id": "negative", "text": "clean text", "expected": []}],
    )
    _, recall, failures = eval_text_path(negative_only)
    assert recall == 0.0
    assert any("no positive case" in failure for failure in failures)


def test_eval_counts_duplicate_findings_as_a_multiset(tmp_path):
    golden = tmp_path / "duplicates.jsonl"
    _write_cases(
        golden,
        [
            {
                "id": "duplicate",
                "text": "a@example.invalid and a@example.invalid",
                "expected": [{"type": "EMAIL_ADDRESS", "text": "a@example.invalid"}],
            },
            {"id": "negative", "text": "clean text", "expected": []},
        ],
    )
    precision, recall, failures = eval_text_path(golden)
    assert precision == 0.5
    assert recall == 1.0
    assert any(
        "spurious=[('EMAIL_ADDRESS', 'a@example.invalid')]" in failure for failure in failures
    )


def test_block_entity_safety_is_strictest_and_can_go_red(monkeypatch):
    recall, failures = eval_block_entity_recall()
    assert BLOCK_RECALL_MIN >= 0.99
    assert recall >= BLOCK_RECALL_MIN, failures

    from eval import run_eval

    def finds_nothing(text):
        return type("Result", (), {"findings": ()})()

    planted_recall, _ = run_eval.eval_block_entity_recall(finds_nothing, run_eval.BLOCK_ENTITIES)
    assert planted_recall == 0.0


def test_eval_policy_is_composed_from_runtime_config() -> None:
    from eval.run_eval import configured_eval_policy

    detector, block_entities = configured_eval_policy()
    assert "SG_NRIC" in block_entities
    assert any(recognizer.jurisdiction == "SG" for recognizer in detector.recognizers)


def test_eval_honours_runtime_config_env_and_structured_jurisdiction_pack(
    tmp_path, monkeypatch
) -> None:
    config = tmp_path / "site-policy.yaml"
    config.write_text(
        """
profile: local
detection:
  jurisdictions: [SG]
policy:
  block_entities: [SG_NRIC]
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("ONPREM_DLP_CONFIG", str(config))
    orchestrator, block_entities = configured_eval_runtime()
    assert block_entities == frozenset({"SG_NRIC"})
    assert {r.jurisdiction for r in orchestrator.detection.recognizers} == {"GLOBAL", "SG"}

    # A neutral-name column of valid HKIDs is pattern-classified only when the HK pack
    # is selected. This proves structured eval uses the configured profiler instead of
    # silently constructing the all-jurisdiction default orchestrator.
    sampler = InlineSampler({"identifier": ["A123456(3)"] * 20})
    accuracy, failures = eval_columns(
        orchestrator,
        sampler=sampler,
        expected={"identifier": "NON_PII"},
    )
    assert accuracy == 1.0, failures


# --------------------------------------------------------------------------- #
# Every detection path is scored, and what is not scored says so
# --------------------------------------------------------------------------- #
def test_a_non_regex_false_positive_now_lowers_precision() -> None:
    """The filter's removal, proved by the case it used to hide.

    ``evaluated_entities`` was built from ``detector.recognizers``, so a finding whose entity
    type no regex recognizer declares was dropped from the PREDICTED set before precision was
    computed. A model path could invent any number of them and the gate stayed at 1.000. The
    same filter dropped such labels from the EXPECTED set, so recall could not fall either.

    ``PERSON_NAME`` is the shape: it is a real entity type in the redact list, and no regex
    recognizer produces it, so it is precisely what the old scorer could not see.
    """
    from eval import run_eval

    from onprem_dlp.domain.kernel import Finding
    from onprem_dlp.domain.models import EntityType

    golden = run_eval.REPO / "eval" / "golden" / "text_golden.jsonl"
    orchestrator, _ = run_eval.configured_eval_runtime()

    def hallucinating(text: str):
        scan = orchestrator.scan_text(text)
        invented = Finding(
            entity_type=EntityType.PERSON_NAME,
            start=0,
            end=12,
            text="Nobody Atall",
            confidence=0.99,
            recognizer="ner:a-model-that-invented-it",
        )
        return type("Result", (), {"findings": (*scan.findings, invented)})()

    clean_precision, _, _ = run_eval.eval_text_path(golden, orchestrator.scan_text)
    noisy_precision, _, _ = run_eval.eval_text_path(golden, hallucinating)

    assert clean_precision == 1.0
    assert noisy_precision < clean_precision, (
        "a finding from outside the regex stack did not lower precision, which means the "
        "predicted set is still being filtered and non-regex paths are unmeasurable"
    )


def test_path_coverage_names_every_path_and_marks_the_unmeasured_ones() -> None:
    """An unmeasured path must be visible as unmeasured, not absent.

    The defect this replaces was not a wrong number, it was a missing row: four detection paths
    were filtered out of the measurement while the README said they raise recall. A reader saw
    ``EVAL PASS`` and had no way to learn which paths that verdict covered.
    """
    from eval import run_eval

    orchestrator, _ = run_eval.configured_eval_runtime()
    rows = run_eval.path_coverage(orchestrator)

    assert [name for name, _, _ in rows] == [name for name, _, _ in run_eval.DETECTION_PATHS]
    statuses = {name: status for name, _, status in rows}
    assert statuses["regex recognizers"].startswith("MEASURED")
    # OCR has no labelled corpus on any profile, so it is UNMEASURED and never silently absent.
    assert statuses["OCR + image redactor"].startswith("UNMEASURED")
    # Every row resolves to one of the three states; a blank status would be the old defect
    # wearing a table.
    for _, _, status in rows:
        assert status.startswith(("MEASURED", "UNMEASURED", "inactive")), status
