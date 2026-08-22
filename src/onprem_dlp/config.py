"""Settings + DI container: one YAML file decides which adapters fill which ports.

``profile`` selects a named binding set (``local`` by default — stdlib only, always
works). Every binding is a dotted path ``package.module:Class`` plus kwargs, so
swapping Presidio for Gemma, or Ollama for llama.cpp, is a config edit, not a code
change.

Every environment override below is resolved in THREE states by
:func:`onprem_dlp.netguard.read_env_setting`. Each of these variables carries a decision where
"nobody set it" and "an operator set it to nothing" must not mean the same thing: a salt that
arrives empty from a misprovisioned secret would otherwise revert to the built-in public
default and make every pseudonymous token re-linkable; an empty audit path would silently
disable the evidence trail; an empty profile would silently drop back to the weakest detection
profile. All of those are refusals now, not fallbacks.
"""

from __future__ import annotations

import copy
import importlib
import json
import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .adapter_settings import AdapterSettings
from .domain.models import EgressPolicy, EntityType, RedactionStrategy
from .domain.services import (
    ColumnClassifierService,
    ColumnProfileService,
    DlpOrchestrator,
    EgressPolicyService,
    RedactionService,
    TextDetectionService,
)
from .netguard import read_env_setting

DEFAULT_SETTINGS: dict[str, Any] = {
    "profile": "local",
    "audit_log": None,  # e.g. ./audit/onprem-dlp.jsonl ; None disables the sink
    "audit_retention_days": 180,  # enforced by the mounted store/SIEM lifecycle policy
    "detection": {
        "min_confidence": 0.35,
        "jurisdictions": ["SG", "HK", "JP", "AU", "US"],
    },
    "redaction": {
        "default_strategy": "tag",
        "hash_salt": "onprem-dlp",
        "strategies": {"CREDIT_CARD": "mask", "IBAN": "mask"},
    },
    "policy": {
        "min_confidence": 0.5,
        "block_at_or_above": 1,
        "block_entities": sorted(e.value for e in EgressPolicy.default().block_entities),
        "redact_entities": sorted(e.value for e in EgressPolicy.default().redact_entities),
    },
    "classifier": {
        "pii_threshold": 0.6,
        "review_threshold": 0.3,
        "sample_limit": 500,
    },
    "profiles": {
        "local": {
            "ner": {"class": "onprem_dlp.adapters.local:NullNer"},
            "adjudicator": {"class": "onprem_dlp.adapters.local:NullAdjudicator"},
        },
        "gemma-ollama": {
            "ner": {
                "class": "onprem_dlp.adapters.gemma:OllamaGemmaClient",
                "kwargs": {"base_url": "http://127.0.0.1:11434", "model": "gemma3:1b"},
            },
            "adjudicator": {
                "class": "onprem_dlp.adapters.gemma:OllamaGemmaClient",
                "kwargs": {"base_url": "http://127.0.0.1:11434", "model": "gemma3:1b"},
            },
        },
        "gemma-llamacpp": {
            "ner": {
                "class": "onprem_dlp.adapters.gemma:LlamaCppGemmaClient",
                "kwargs": {"model_path": "/models/gemma-3-1b-it-Q4_K_M.gguf"},
            },
            "adjudicator": {
                "class": "onprem_dlp.adapters.gemma:LlamaCppGemmaClient",
                "kwargs": {"model_path": "/models/gemma-3-1b-it-Q4_K_M.gguf"},
            },
        },
        "full": {
            "ner": {"class": "onprem_dlp.adapters.ner:PresidioNer"},
            "adjudicator": {
                "class": "onprem_dlp.adapters.gemma:OllamaGemmaClient",
                "kwargs": {"base_url": "http://127.0.0.1:11434", "model": "gemma3:1b"},
            },
        },
    },
    "ocr": {"class": "onprem_dlp.adapters.ocr:TesseractOcr", "kwargs": {"lang": "eng"}},
    "image_redactor": {"class": "onprem_dlp.adapters.ocr:PillowImageRedactor"},
}


def _deep_merge(base: dict, override: Mapping) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _configured_settings_path() -> list[str]:
    """Config-file candidates, honouring ``ONPREM_DLP_CONFIG`` in three states.

    Set and empty raises: an empty string is not a path, and inheriting the working-directory
    candidate would run the gate on a policy file nobody chose. Set to a path that does not
    exist also raises, rather than silently falling through to the built-in defaults: a
    tightened block list that fails to load is a fail-open, and a DLP gate must not quietly
    downgrade its own policy. An unset variable keeps the documented working-directory lookup.
    """
    setting = read_env_setting("ONPREM_DLP_CONFIG").require_not_configured_empty(
        "a settings file path"
    )
    if setting.has_value:
        if not os.path.exists(setting.value):
            raise FileNotFoundError(
                f"ONPREM_DLP_CONFIG points at {setting.value!r}, which does not exist. Refusing "
                "to fall back to the built-in defaults: the policy you configured would not be "
                "the policy enforced."
            )
        return [setting.value]
    return [os.path.join(os.getcwd(), "config", "settings.yaml")]


def load_settings(path: str | None = None) -> dict[str, Any]:
    """Defaults, overlaid with config/settings.yaml (or JSON) when present.

    An explicit ``path`` argument stays a candidate (a missing file leaves the defaults
    standing), because it is a programmatic override chosen in-process by the caller. The
    environment override is stricter: see :func:`_configured_settings_path`.
    """
    settings = copy.deepcopy(DEFAULT_SETTINGS)
    candidates = [path] if path else _configured_settings_path()
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            with open(candidate, encoding="utf-8") as fh:
                raw = fh.read()
            if candidate.endswith(".json"):
                data = json.loads(raw)
            else:
                import yaml  # lazy: only needed when a YAML file is actually used

                data = yaml.safe_load(raw) or {}
            settings = _deep_merge(settings, data)
            break

    # Secret values stay out of tracked YAML. Operators may source
    # .env.secrets locally or inject these names from a Kubernetes Secret.
    # Each read is three-state: set-and-empty is an expressed intent that names nothing, and
    # for all three of these the honest answer is to refuse rather than inherit the default.
    salt = read_env_setting("ONPREM_DLP_REDACTION_HASH_SALT").require_not_configured_empty(
        "a redaction salt (the built-in default is public, so an empty injection would make "
        "every pseudonymous token re-linkable)"
    )
    if salt.has_value:
        settings["redaction"]["hash_salt"] = salt.value
    audit_log = read_env_setting("ONPREM_DLP_AUDIT_LOG").require_not_configured_empty(
        "an audit log path (an empty value would silently disable the evidence trail)"
    )
    if audit_log.has_value:
        settings["audit_log"] = audit_log.value
    retention = read_env_setting("ONPREM_DLP_AUDIT_RETENTION_DAYS").require_not_configured_empty(
        "an audit retention period"
    )
    if retention.has_value:
        settings["audit_retention_days"] = _positive_int(retention.name, retention.value)
    return settings


def _positive_int(name: str, value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError(f"{name} must be a whole number of days, got {value!r}") from None
    if parsed < 1:
        raise ValueError(f"{name} must be at least 1 day, got {parsed}")
    return parsed


def _instantiate(binding: Mapping[str, Any] | None) -> Any:
    if not binding or not binding.get("class"):
        return None
    module_path, _, class_name = str(binding["class"]).partition(":")
    cls = getattr(importlib.import_module(module_path), class_name)
    return cls(AdapterSettings(dict(binding.get("kwargs", {}))))


def _redact_source(source: str) -> str:
    """Remove URI userinfo before reflecting an invalid source in an error."""
    try:
        parsed = urlsplit(source)
    except ValueError:
        return "<invalid source>"
    if parsed.scheme and parsed.netloc:
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = f"***@{netloc.rsplit('@', 1)[1]}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    if parsed.scheme:
        # Opaque/malformed URI forms can carry credentials in their path
        # (``scheme:user:secret@host``). Do not attempt to selectively echo it.
        return f"{parsed.scheme}:<redacted>"
    if "@" in parsed.path:
        return "<redacted source>"
    # Relative/local sources may still carry query/fragment secrets. Only the
    # path is useful for a configuration error.
    return parsed.path or "<invalid source>"


class Container:
    """Builds the orchestrator and adapters for the active profile."""

    def __init__(self, settings: dict[str, Any] | None = None, profile: str | None = None):
        self.settings = settings or load_settings()
        # Three states: an explicitly empty ONPREM_DLP_PROFILE refuses rather than falling back
        # to the settings default, because the fallback is the weakest detection profile and a
        # silent downgrade of a DLP gate releases data the operator meant to catch.
        env_profile = read_env_setting("ONPREM_DLP_PROFILE").require_not_configured_empty(
            "a profile name (the fallback is the weakest detection profile, so an empty value "
            "would silently downgrade the gate)"
        )
        self.profile = profile or env_profile.value or self.settings["profile"]
        if self.profile not in self.settings["profiles"]:
            raise ValueError(
                f"unknown profile '{self.profile}'; configured: {sorted(self.settings['profiles'])}"
            )

    # ------------------------------------------------------------------ domain wiring

    def orchestrator(self) -> DlpOrchestrator:
        s = self.settings
        bindings = s["profiles"][self.profile]
        policy_cfg = s["policy"]
        policy = EgressPolicy(
            block_entities=frozenset(EntityType(e) for e in policy_cfg["block_entities"]),
            redact_entities=frozenset(EntityType(e) for e in policy_cfg["redact_entities"]),
            min_confidence=float(policy_cfg["min_confidence"]),
            block_at_or_above=int(policy_cfg["block_at_or_above"]),
        )
        redaction_cfg = s["redaction"]
        audit_path = s.get("audit_log")
        audit = None
        if audit_path:
            from .adapters.local import JsonlAuditSink

            audit = JsonlAuditSink(audit_path)
        from .domain.recognizers import recognizers_for_jurisdictions

        recognizers = recognizers_for_jurisdictions(s["detection"]["jurisdictions"])
        return DlpOrchestrator(
            detection=TextDetectionService(
                recognizers=recognizers,
                min_confidence=float(s["detection"]["min_confidence"]),
            ),
            redaction=RedactionService(
                strategies={
                    EntityType(k): RedactionStrategy(v)
                    for k, v in redaction_cfg.get("strategies", {}).items()
                },
                default_strategy=RedactionStrategy(redaction_cfg["default_strategy"]),
                hash_salt=str(redaction_cfg["hash_salt"]),
            ),
            profiler=ColumnProfileService(recognizers=recognizers),
            classifier=ColumnClassifierService(
                pii_threshold=float(s["classifier"]["pii_threshold"]),
                review_threshold=float(s["classifier"]["review_threshold"]),
            ),
            egress=EgressPolicyService(policy=policy),
            ner=_instantiate(bindings.get("ner")),
            adjudicator=_instantiate(bindings.get("adjudicator")),
            audit=audit,
        )

    # ---------------------------------------------------------------- adapter helpers

    def ocr(self):
        return _instantiate(self.settings.get("ocr"))

    def image_redactor(self):
        return _instantiate(self.settings.get("image_redactor"))

    def sampler(self, source: str):
        """Select a sampler from a local path or an explicit database URI."""
        lowered = source.lower()
        if lowered.startswith(("postgres://", "postgresql://")):
            from .adapters.db import PostgresSampler

            return PostgresSampler(source)
        if lowered.startswith("mysql://"):
            from .adapters.db import MySqlSampler

            return MySqlSampler(source)
        if lowered.startswith("bigquery://"):
            from .adapters.db import BigQuerySampler

            return BigQuerySampler.from_uri(source)
        if lowered.endswith(".csv"):
            from .adapters.local import CsvSampler

            return CsvSampler(source)
        if lowered.endswith((".db", ".sqlite", ".sqlite3")):
            from .adapters.local import SqliteSampler

            return SqliteSampler(source)
        raise ValueError(
            f"cannot infer a sampler for '{_redact_source(source)}' "
            "(expected .csv, .db/.sqlite, postgres://, mysql://, or bigquery://)"
        )

    def sample_limit(self) -> int:
        return int(self.settings["classifier"]["sample_limit"])
