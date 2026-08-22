"""End-to-end CLI tests over the real demo fixtures — the offline gate."""

import json
import pathlib

from onprem_dlp.cli.main import EXIT_ALLOW, EXIT_BLOCK, EXIT_REDACT, main

REPO = pathlib.Path(__file__).resolve().parents[2]
EMAIL = str(REPO / "demo" / "sample_support_email.txt")
CSV = str(REPO / "demo" / "customers.csv")
DB = str(REPO / "demo" / "customers.db")


def test_scan_text_finds_the_planted_entities(capsys):
    code = main(["--json", "scan-text", "--file", EMAIL])
    assert code == EXIT_ALLOW
    scan = json.loads(capsys.readouterr().out)
    types = {f["entity_type"] for f in scan["findings"]}
    assert {
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "SG_NRIC",
        "CREDIT_CARD",
        "IBAN",
        "JP_MY_NUMBER",
        "HK_HKID",
        "AU_TFN",
        "AU_ABN",
        "AU_MEDICARE",
        "PASSPORT",
        "DATE_OF_BIRTH",
        "IP_ADDRESS",
    } <= types


def test_decide_blocks_the_support_email(capsys):
    assert main(["decide", "--file", EMAIL]) == EXIT_BLOCK
    out = capsys.readouterr().out
    assert "BLOCK" in out and "human review" in out


def test_decide_redacts_email_only_content(capsys):
    assert main(["decide", "--text", "reach me at jane@example.com"]) == EXIT_REDACT


def test_decide_allows_clean_text(capsys):
    assert main(["decide", "--text", "revenue grew 12% quarter on quarter"]) == EXIT_ALLOW


def test_redact_text_output_is_clean(capsys):
    code = main(["redact-text", "--file", EMAIL])
    assert code == EXIT_ALLOW
    redacted = capsys.readouterr().out
    for secret in ("S8712345F", "4111 1111 1111 1111", "weiming.tan@example.com"):
        assert secret not in redacted
    # a second pass over the redacted text must be quiet on those entities
    code = main(["--json", "scan-text", "--text", redacted])
    rescan = json.loads(capsys.readouterr().out)
    assert {f["entity_type"] for f in rescan["findings"]} & {
        "SG_NRIC",
        "CREDIT_CARD",
        "EMAIL_ADDRESS",
    } == set()


def test_classify_columns_csv(capsys):
    code = main(["--json", "classify-columns", CSV])
    assert code == EXIT_ALLOW
    dataset = json.loads(capsys.readouterr().out)
    by_name = {c["profile"]["name"]: c for c in dataset["columns"]}
    assert by_name["email"]["category"] == "PII_DIRECT"
    assert by_name["nric"]["category"] == "PII_DIRECT"
    assert by_name["phone"]["category"] == "PII_DIRECT"
    assert by_name["date_of_birth"]["category"] == "PII_QUASI"
    assert by_name["salary_sgd"]["category"] == "SENSITIVE"
    assert by_name["account_balance"]["category"] == "NON_PII"
    assert by_name["product_code"]["category"] == "NON_PII"
    assert by_name["customer_id"]["needs_review"] is True


def test_classify_columns_sqlite_matches_csv(capsys):
    main(["--json", "classify-columns", DB])
    db_dataset = json.loads(capsys.readouterr().out)
    main(["--json", "classify-columns", CSV])
    csv_dataset = json.loads(capsys.readouterr().out)
    db_cats = {c["profile"]["name"]: c["category"] for c in db_dataset["columns"]}
    csv_cats = {c["profile"]["name"]: c["category"] for c in csv_dataset["columns"]}
    assert db_cats == csv_cats


def test_fail_on_pii_gate(capsys):
    assert main(["classify-columns", CSV, "--fail-on-pii"]) == EXIT_BLOCK


def test_zero_sample_limit_is_honored(capsys):
    assert main(["--json", "classify-columns", CSV, "--sample", "0"]) == EXIT_ALLOW
    dataset = json.loads(capsys.readouterr().out)
    assert {column["profile"]["sample_size"] for column in dataset["columns"]} == {0}


def test_audit_trail_is_written(tmp_path, capsys):
    cfg = tmp_path / "settings.json"
    audit = tmp_path / "audit.jsonl"
    cfg.write_text(json.dumps({"audit_log": str(audit)}), encoding="utf-8")
    main(["--config", str(cfg), "decide", "--text", "NRIC S1234567D"])
    lines = [json.loads(line) for line in audit.read_text().splitlines()]
    kinds = [entry["kind"] for entry in lines]
    assert "scan_text" in kinds and "egress_decision" in kinds
    assert lines[-1]["action"] == "BLOCK"
    # audit carries entity COUNTS, never raw values
    assert "S1234567D" not in audit.read_text()
