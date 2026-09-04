"""Static evidence for documentation and portability practice closures."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_authority_boundary_crosswalk_and_extension_lists() -> None:
    authority = (ROOT / "docs/doc-authority.md").read_text(encoding="utf-8")
    spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
    compliance = (ROOT / "COMPLIANCE.md").read_text(encoding="utf-8")
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert authority.index("`SPEC.md`") < authority.index("`ARCHITECTURE.md`")
    assert "reusable kernel" in spec
    assert "Adopter-owned regulatory crosswalk" in compliance
    assert "Adding an adapter" in contributing
    assert "Adding a port or sub-service" in contributing


def test_markdown_has_no_em_dash_and_no_unvalidated_mermaid() -> None:
    docs = [
        path
        for path in ROOT.rglob("*.md")
        if not any(part.startswith(".") for part in path.relative_to(ROOT).parts)
    ]
    assert not [path for path in docs if "—" in path.read_text(encoding="utf-8")]
    # onprem-dlp intentionally uses text/tables and ships no Mermaid diagram requiring a Node parser.
    assert not [path for path in docs if "```mermaid" in path.read_text(encoding="utf-8")]
