# FAQ index

Answers to the questions different teams ask when evaluating, adopting, or reviewing this
repository as a common base for an on-prem DLP egress gate. Each file is written for a
specific audience; skim the one that matches your role.

| FAQ | For | Answers |
|---|---|---|
| [security-faq.md](security-faq.md) | AppSec / security review | attack surface, the fail-closed egress policy, supply chain, the audit sink, what is in vs out of scope |
| [portability-faq.md](portability-faq.md) | Architecture / air-gap / exit planning | zero mandatory deps, the profile swap, air-gapped operation, why the commons are not adopted |
| [features-faq.md](features-faq.md) | Product / compliance / delivery | the two solutions, what is deterministic vs advisory, and the boundary with sibling catalog systems |
| [adoption-faq.md](adoption-faq.md) | Engineering leads forking the repo | rename, upstream fixes, adding a recognizer or adapter, jurisdiction packs |
| [compliance-faq.md](compliance-faq.md) | Compliance / DPO / model risk | regulatory posture, PII handling, human-in-the-loop, residency, model-risk evidence |

These FAQs deliberately do **not** re-document capabilities owned by sibling systems in the
[catalog](https://github.com/portable-genai). Where a concern belongs to
another repo (the cloud guardrail gateway, the enterprise WORM audit system, ...), the FAQ
points at it and explains the boundary rather than duplicating it. See
[features-faq.md](features-faq.md) for the full "what this repo owns vs what it integrates"
map. Note that, being air-gapped by design, this gate consumes no sibling service at
runtime; the references are about where it sits, not what it calls.
