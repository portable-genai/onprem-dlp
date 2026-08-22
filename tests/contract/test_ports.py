"""Contract tests: every shipped adapter satisfies its Protocol at runtime.

Optional-dependency adapters are constructed (their heavy imports are lazy), so the
shape check runs even where Presidio/Tesseract/psycopg are not installed.
"""

from onprem_dlp.adapter_settings import AdapterSettings
from onprem_dlp.adapters.db import BigQuerySampler, MySqlSampler, PostgresSampler
from onprem_dlp.adapters.gemma import LlamaCppGemmaClient, OllamaGemmaClient
from onprem_dlp.adapters.local import (
    CsvSampler,
    JsonlAuditSink,
    NullAdjudicator,
    NullNer,
    SqliteSampler,
)
from onprem_dlp.adapters.local.samplers import InlineSampler
from onprem_dlp.adapters.ner import PresidioNer
from onprem_dlp.adapters.ocr import PillowImageRedactor, TesseractOcr
from onprem_dlp.config import _instantiate, load_settings
from onprem_dlp.ports import (
    AuditSink,
    ColumnSampler,
    ImageRedactor,
    LlmAdjudicator,
    NerAnalyzer,
    OcrEngine,
)


def test_ner_analyzers():
    empty = AdapterSettings()
    model = AdapterSettings({"model_path": "/tmp/x.gguf"})
    assert isinstance(NullNer(empty), NerAnalyzer)
    assert isinstance(OllamaGemmaClient(empty), NerAnalyzer)
    assert isinstance(LlamaCppGemmaClient(model), NerAnalyzer)
    assert isinstance(PresidioNer(empty), NerAnalyzer)


def test_adjudicators():
    empty = AdapterSettings()
    model = AdapterSettings({"model_path": "/tmp/x.gguf"})
    assert isinstance(NullAdjudicator(empty), LlmAdjudicator)
    assert isinstance(OllamaGemmaClient(empty), LlmAdjudicator)
    assert isinstance(LlamaCppGemmaClient(model), LlmAdjudicator)


def test_samplers(tmp_path):
    csv_path = tmp_path / "t.csv"
    csv_path.write_text("a,b\n1,2\n", encoding="utf-8")
    assert isinstance(CsvSampler(str(csv_path)), ColumnSampler)
    assert isinstance(SqliteSampler(str(tmp_path / "t.db")), ColumnSampler)
    assert isinstance(InlineSampler({"a": ["1"]}), ColumnSampler)
    assert isinstance(
        PostgresSampler(
            "postgresql://u@h/db?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca.pem"
        ),
        ColumnSampler,
    )
    assert isinstance(MySqlSampler("mysql://u@h/db"), ColumnSampler)
    assert isinstance(BigQuerySampler("project", "dataset"), ColumnSampler)


def test_ocr_and_image_redactor():
    assert isinstance(TesseractOcr(AdapterSettings()), OcrEngine)
    assert isinstance(PillowImageRedactor(AdapterSettings()), ImageRedactor)


def test_audit_sink(tmp_path):
    assert isinstance(JsonlAuditSink(str(tmp_path / "a.jsonl")), AuditSink)


def test_config_binding_sets_cannot_drift_and_all_use_one_settings_argument():
    settings = load_settings("config/settings.yaml")
    assert set(settings["profiles"]) == {"local", "gemma-ollama", "gemma-llamacpp", "full"}
    for profile, bindings in settings["profiles"].items():
        assert set(bindings) == {"ner", "adjudicator"}, profile
        assert isinstance(_instantiate(bindings["ner"]), NerAnalyzer)
        assert isinstance(_instantiate(bindings["adjudicator"]), LlmAdjudicator)
    assert isinstance(_instantiate(settings["ocr"]), OcrEngine)
    assert isinstance(_instantiate(settings["image_redactor"]), ImageRedactor)


def test_local_profile_behavior_is_deterministic_across_independent_containers():
    from onprem_dlp.config import Container

    text = "Fictional NRIC S1234567D and email demo@example.test"
    first = Container(load_settings("config/settings.yaml"), profile="local").orchestrator()
    second = Container(load_settings("config/settings.yaml"), profile="local").orchestrator()
    assert first.scan_text(text) == second.scan_text(text)
    assert first.decide_egress(text) == second.decide_egress(text)
