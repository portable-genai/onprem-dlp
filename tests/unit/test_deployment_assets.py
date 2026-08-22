from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "deploy" / "helm" / "onprem-dlp"


def test_the_image_entry_point_goes_through_the_bind_guard():
    """The bind decision must not live in a Dockerfile string no guard can see."""
    dockerfile = (REPO / "Dockerfile").read_text(encoding="utf-8")
    assert 'CMD ["python", "-m", "onprem_dlp.api.serve"]' in dockerfile
    assert "--host" not in dockerfile, "a hard-coded uvicorn bind bypasses netguard entirely"
    assert "127.0.0.1:8484/healthz" in dockerfile, "the healthcheck must work in either posture"


def test_the_chart_accepts_the_exposure_explicitly_and_compensates_for_it():
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    deployment = (CHART / "templates" / "deployment.yaml").read_text(encoding="utf-8")
    schema = yaml.safe_load((CHART / "values.schema.json").read_text(encoding="utf-8"))

    # A pod must bind its pod IP, so the acceptance is declared, not defaulted, and the
    # default-deny NetworkPolicy is the boundary that makes it defensible.
    assert values["api"]["acceptUnauthenticatedExposure"] is True
    assert values["networkPolicy"]["enabled"] is True
    assert values["api"]["corsOrigins"] == []
    assert "ONPREM_DLP_API_HOST" in deployment
    assert "ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE" in deployment
    assert "acceptUnauthenticatedExposure=true requires networkPolicy.enabled=true" in deployment
    assert "{{- fail" in deployment, "the render must fail, not warn, on the uncompensated combo"
    assert schema["properties"]["api"]["required"] == ["host", "acceptUnauthenticatedExposure"]
    assert schema["properties"]["api"]["properties"]["corsOrigins"]["items"]["not"] == {
        "const": "*"
    }


def test_helm_defaults_are_secure_and_retention_is_six_months():
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    assert values["profile"] == "local"
    assert values["audit"]["retentionDays"] == 180
    assert values["podSecurityContext"]["runAsNonRoot"] is True
    assert values["podSecurityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    assert values["containerSecurityContext"]["readOnlyRootFilesystem"] is True
    assert values["containerSecurityContext"]["allowPrivilegeEscalation"] is False
    assert values["containerSecurityContext"]["capabilities"]["drop"] == ["ALL"]
    assert values["networkPolicy"]["enabled"] is True
    assert values["networkPolicy"]["additionalEgress"] == []
    schema = yaml.safe_load((CHART / "values.schema.json").read_text(encoding="utf-8"))
    assert schema["properties"]["profile"]["enum"] == ["local"]


def test_deployment_uses_probes_existing_secret_and_no_service_account_token():
    deployment = (CHART / "templates" / "deployment.yaml").read_text(encoding="utf-8")
    service_account = (CHART / "templates" / "serviceaccount.yaml").read_text(encoding="utf-8")
    assert "readinessProbe:" in deployment
    assert "livenessProbe:" in deployment
    assert "secretKeyRef:" in deployment
    assert "ONPREM_DLP_REDACTION_HASH_SALT" in deployment
    assert "automountServiceAccountToken: false" in deployment
    assert "automountServiceAccountToken: false" in service_account


def test_real_environment_files_are_ignored_and_examples_separate_secrets():
    ignored = (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in ignored
    assert ".env.secrets" in ignored
    nonsecret = (REPO / ".env.example").read_text(encoding="utf-8")
    secrets = (REPO / ".env.secrets.example").read_text(encoding="utf-8")
    assert "ONPREM_DLP_REDACTION_HASH_SALT" not in nonsecret
    assert "ONPREM_DLP_REDACTION_HASH_SALT" in secrets
