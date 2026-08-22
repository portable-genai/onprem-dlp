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

    class EmptyDetector:
        def scan(self, text):
            return type("Result", (), {"findings": ()})()

    planted_recall, _ = run_eval.eval_block_entity_recall(EmptyDetector(), run_eval.BLOCK_ENTITIES)
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
