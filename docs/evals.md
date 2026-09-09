# Evals

What the gate measures, what it deliberately does not, and why the second list is printed by
the runner rather than kept in a document nobody re-reads.

This repository has the only real precision and recall corpus in the fleet: 22 English and 19
Japanese labelled spans plus 14 labelled columns, with true positives, false positives and
false negatives counted per span rather than per document. Everything else here scores an
accuracy against an expected answer. That makes this page shorter than most and its limits
sharper.

## What is measured, and against what bar

Every bar lives in `eval/rubrics/*.yaml` next to the argument for it, read through
`agent_eval_kit.load_rubrics` with no fallback. A metric scored with no reviewed bar fails the
build, and so does a bar that names no scored metric.

| Metric | Bar | What it measures |
|---|---|---|
| `unstructured_en_precision` | 0.90 | Of the spans the scan flagged in English text, the share that are labelled. |
| `unstructured_en_recall` | 0.85 | Of the labelled English spans, the share the scan found. |
| `unstructured_ja_precision` | 0.90 | The same, over Japanese text, which is a different problem: no spaces, and the identifier forms are grouped. |
| `unstructured_ja_recall` | 0.85 | |
| `structured_column_accuracy` | 0.85 | Of the labelled columns, the share classified into the right category from a sample of values. |
| `block_entity_recall` | 0.99 | The strictest bar here. Of the entity kinds policy says must BLOCK egress, the share the scan found. A missed block-entity is the failure this control exists to prevent. |

Precision is barred above recall on purpose and it is the asymmetry a reader should question.
A pre-egress control that over-blocks is turned off by the people it obstructs, and a control
that is turned off has a recall of zero. The bars encode that trade rather than pretending it
does not exist.

Scored over 55 examples across the three corpora.

## Where the numbers come from, and the filter that used to be there

Every metric is scored through `DlpOrchestrator.scan_text`, the same entry point the product
runs, over the golden set's whole label set.

It used to be scored through `TextDetectionService.scan` with an `evaluated_entities` filter
built from `detector.recognizers`, which quietly restricted both the expected labels and the
predicted findings to the entity types the regex stack declares. That filter took the Presidio
NER analyzer, the Tesseract OCR path, the image redactor and the Gemma adjudicator out of the
measurement **on both sides at once**: a false positive from a model path could not lower
precision, and a label only a model path can produce could not lower recall. The README said
those paths raise recall.

A claim about a path is not evidence while the path is filtered out of the measurement of it.
The filter is gone.

## What is not measured, printed by the runner

`make eval` ends with a path-coverage table rather than a passing table, because what is
excluded from a measurement is the half a reader cannot infer:

```
detection paths (what the numbers above do and do not cover):
  regex recognizers     TextDetectionService     MEASURED (eval/golden/text*_golden.jsonl, labelled per span)
  NER analyzer          NullNer                  inactive on this profile: contributes nothing
  LLM adjudicator       NullAdjudicator          inactive on this profile: contributes nothing
  OCR + image redactor  per-call OcrEngine       UNMEASURED (no labelled corpus: no image fixture carries labelled pixel boxes)
```

Three states, and the difference between them matters:

- **MEASURED** names the corpus that measures it.
- **inactive on this profile** is a path bound to a null adapter. It contributes nothing to the
  scores because it contributes nothing at all, which is a true statement about this profile
  and not about the path.
- **UNMEASURED** is the honest one and the uncomfortable one: a path bound to a REAL adapter,
  running in the product, with no labelled corpus behind it. The OCR and image-redaction path
  is in that state because no image fixture in this repository carries labelled pixel boxes.
  It is not excluded from the product; it is excluded from the evidence.

An unmeasured path and a perfect path produce the same number, which is none. Printing the
distinction is the only thing that stops the first being read as the second.

## What nothing here measures

- **The model paths, on any profile.** Enabling Presidio or the Gemma adjudicator would change
  both precision and recall and there is no corpus that would show by how much. The README's
  claim that they raise recall is a design intent, not a result.
- **Latency and throughput under load.** A pre-egress control sits in the request path, and a
  control that adds a second to every send is a control with a different failure mode entirely.
- **Languages beyond English and Japanese.** The recognizers cover more; the corpus does not.
- **Whether the policy is right.** The block list is bank-owned configuration. The gate scores
  whether the scan finds what the list names, never whether the list names the right things.

## Running it

```
make gate               # lint, tests, eval, portability. Air-gap runnable, no network.
make dependency-audit   # the networked supply-chain check, deliberately separate
```

`make gate` performs no network calls and imports no optional database or cloud SDK, which is
the property that makes this repository's claim about air-gapped operation checkable rather
than asserted.
