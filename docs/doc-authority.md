# Documentation authority

When repository documents differ, apply this order:

1. `SPEC.md`: behavior and safety contract.
2. `ARCHITECTURE.md`: boundaries and deployment design.
3. `COMPLIANCE.md`: control mapping and adopter-owned regulatory interpretation.
4. `README.md`: operator quick start.
5. `DEMO.md`, runbooks, FAQs and supporting guides.

`docs/practices-audit.md` records evidence. It does not override
the current contract. Changes reconcile lower-authority documents in the same change.
