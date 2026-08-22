"""Pure domain layer: stdlib only, no SDKs, no I/O, no network.

Everything consequential (what counts as PII, what gets redacted, whether an egress is
allowed) is decided here, deterministically. Optional model adapters only contribute
candidate findings or advisory verdicts that these services weigh with fixed rules.
"""
