import json

import pytest

from onprem_dlp.config import Container, load_settings
from onprem_dlp.domain.models import EntityType, RedactionStrategy
from onprem_dlp.netguard import ConfiguredEmptyError


def test_entity_taxonomy_accepts_safe_config_only_extensions():
    extension = EntityType("BANK_CUSTOMER_ID")
    assert extension.value == "BANK_CUSTOMER_ID"
    assert EntityType("BANK_CUSTOMER_ID") is extension


def test_default_settings_build_a_working_local_orchestrator():
    container = Container(load_settings("/nonexistent/nothing.yaml"))
    orch = container.orchestrator()
    scan = orch.scan_text("NRIC S1234567D")
    assert scan.findings[0].entity_type is EntityType.SG_NRIC
    assert container.profile == "local"


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError, match="unknown profile"):
        Container(profile="does-not-exist")


def test_json_config_overrides_without_yaml_dependency(tmp_path):
    cfg = tmp_path / "settings.json"
    cfg.write_text(
        json.dumps(
            {
                "detection": {"min_confidence": 0.9},
                "redaction": {"default_strategy": "hash", "hash_salt": "site-a"},
            }
        ),
        encoding="utf-8",
    )
    container = Container(load_settings(str(cfg)))
    orch = container.orchestrator()
    assert orch.detection.min_confidence == 0.9
    assert orch.redaction.default_strategy is RedactionStrategy.HASH


def test_secret_and_retention_environment_overrides(monkeypatch):
    monkeypatch.setenv("ONPREM_DLP_REDACTION_HASH_SALT", "injected-secret")
    monkeypatch.setenv("ONPREM_DLP_AUDIT_RETENTION_DAYS", "180")
    settings = load_settings("/nonexistent/nothing.yaml")
    assert settings["redaction"]["hash_salt"] == "injected-secret"
    assert settings["audit_retention_days"] == 180


def test_a_configured_empty_salt_refuses_instead_of_reverting_to_the_public_default(monkeypatch):
    """The built-in salt is in the source tree, so a silent revert makes tokens re-linkable."""
    monkeypatch.setenv("ONPREM_DLP_REDACTION_HASH_SALT", "")
    with pytest.raises(ConfiguredEmptyError, match="ONPREM_DLP_REDACTION_HASH_SALT"):
        load_settings("/nonexistent/nothing.yaml")


def test_a_configured_empty_audit_path_refuses_instead_of_disabling_the_trail(monkeypatch):
    monkeypatch.setenv("ONPREM_DLP_AUDIT_LOG", "   ")
    with pytest.raises(ConfiguredEmptyError, match="ONPREM_DLP_AUDIT_LOG"):
        load_settings("/nonexistent/nothing.yaml")


@pytest.mark.parametrize("value", ["", "  ", "not-a-number", "0", "-5"])
def test_retention_rejects_empty_and_nonsensical_values(monkeypatch, value):
    monkeypatch.setenv("ONPREM_DLP_AUDIT_RETENTION_DAYS", value)
    with pytest.raises((ConfiguredEmptyError, ValueError)):
        load_settings("/nonexistent/nothing.yaml")


def test_a_configured_settings_path_that_is_missing_refuses_to_fall_back(monkeypatch):
    """A policy file that fails to load is a fail-open: the enforced policy would not be it."""
    monkeypatch.setenv("ONPREM_DLP_CONFIG", "/nonexistent/site-policy.yaml")
    with pytest.raises(FileNotFoundError, match="site-policy.yaml"):
        load_settings()


def test_a_configured_empty_settings_path_refuses(monkeypatch):
    monkeypatch.setenv("ONPREM_DLP_CONFIG", "")
    with pytest.raises(ConfiguredEmptyError, match="ONPREM_DLP_CONFIG"):
        load_settings()


def test_a_configured_empty_profile_refuses_instead_of_downgrading_the_gate(monkeypatch):
    monkeypatch.setenv("ONPREM_DLP_PROFILE", "")
    with pytest.raises(ConfiguredEmptyError, match="ONPREM_DLP_PROFILE"):
        Container(load_settings("/nonexistent/nothing.yaml"))


def test_a_configured_profile_is_honoured_after_stripping(monkeypatch):
    monkeypatch.setenv("ONPREM_DLP_PROFILE", " local\n")
    assert Container(load_settings("/nonexistent/nothing.yaml")).profile == "local"


def test_the_cli_turns_a_refused_config_read_into_exit_two_not_a_traceback(monkeypatch, capsys):
    """Exit 2 is 'usage'. Critically it is not 0, so a CI gate cannot read a refusal as clean."""
    from onprem_dlp.cli.main import main

    monkeypatch.setenv("ONPREM_DLP_REDACTION_HASH_SALT", "")
    assert main(["scan-text", "--text", "NRIC S1234567D"]) == 2
    assert "ONPREM_DLP_REDACTION_HASH_SALT" in capsys.readouterr().err


def test_repo_settings_yaml_matches_defaults_profile_set(tmp_path, monkeypatch):
    yaml = pytest.importorskip("yaml")  # noqa: F841
    import pathlib

    repo_yaml = pathlib.Path(__file__).resolve().parents[2] / "config" / "settings.yaml"
    settings = load_settings(str(repo_yaml))
    assert set(settings["profiles"]) >= {"local", "gemma-ollama", "gemma-llamacpp", "full"}
    Container(settings).orchestrator()  # local profile must instantiate cleanly


def test_sampler_inference(tmp_path):
    container = Container()
    csv_file = tmp_path / "x.csv"
    csv_file.write_text("a\n1\n", encoding="utf-8")
    assert container.sampler(str(csv_file)).source_name == str(csv_file)
    assert container.sampler("mysql://user@host/core").source_name == "mysql:core"
    assert (
        container.sampler("bigquery://sample-project/customer_data").source_name
        == "bigquery:sample-project.customer_data"
    )
    with pytest.raises(ValueError, match="cannot infer"):
        container.sampler("file.parquet")


def test_sampler_error_redacts_uri_userinfo():
    with pytest.raises(ValueError) as error:
        Container().sampler("oracle://admin:super-secret@db.example/core?token=also-secret")
    message = str(error.value)
    assert "admin" not in message
    assert "super-secret" not in message
    assert "also-secret" not in message
    assert "oracle://***@db.example/core" in message


def test_sampler_error_strips_query_and_fragment_without_userinfo():
    with pytest.raises(ValueError) as error:
        Container().sampler("oracle://db.example/core?token=query-secret#fragment-secret")
    message = str(error.value)
    assert "query-secret" not in message
    assert "fragment-secret" not in message
    assert "oracle://db.example/core" in message


@pytest.mark.parametrize(
    ("source", "safe_display"),
    [
        (
            "oracle:admin:opaque-secret@db.example/core?token=query-secret#fragment-secret",
            "oracle:<redacted>",
        ),
        ("file.parquet?token=query-secret#fragment-secret", "file.parquet"),
        ("relative-user@db.example/core?token=query-secret", "<redacted source>"),
    ],
)
def test_sampler_error_never_reflects_relative_or_opaque_credentials(source, safe_display):
    with pytest.raises(ValueError) as error:
        Container().sampler(source)
    message = str(error.value)
    assert "opaque-secret" not in message
    assert "query-secret" not in message
    assert "fragment-secret" not in message
    assert safe_display in message
