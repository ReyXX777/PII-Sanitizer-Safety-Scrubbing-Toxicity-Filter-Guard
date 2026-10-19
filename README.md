# PII & Toxicity Guard

An implementation for detecting and redacting personally identifiable information (PII), then independently filtering toxicity.

## Features

- Microsoft Presidio Analyzer + Anonymizer for PII.
- Precompiled custom regex recognizers for email, IPv4, phone, SSN, and credit-card candidates.
- Luhn checksum validation for credit-card candidates.
- Pydantic schemas for request, settings, detections, and response boundaries.
- Configurable masking operator.
- Separate toxicity interface; includes a safe no-op default and an optional Detoxify adapter.
- Batch generator API for bounded-memory processing.
- Unit tests for ordinary and obfuscated inputs.

## Quick start

Python 3.10+ recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate

pip install -e ".[dev]"
python -m spacy download en_core_web_sm
```

The Presidio analyzer uses an NLP engine for contextual entities. If the spaCy model is not installed, structured custom recognizers may still be usable, but default NER recognizers may not initialize correctly. Install the model for the full experience.

Run tests:

```bash
pytest
```

Run the CLI:

```bash
python -m pii_toxicity_guard.cli "Contact alice@example.com or call +1 212 555 0188"
```

Use as a library:

```python
from pii_toxicity_guard import Guard, GuardSettings
from pii_toxicity_guard.toxicity import NoOpToxicityFilter

guard = Guard(settings=GuardSettings(), toxicity_filter=NoOpToxicityFilter())
result = guard.process("Email alice@example.com. You are an idiot.")
print(result.output_text)
print(result.pii_findings)
print(result.toxicity.status)
```

## Design decisions

1. **PII and toxicity are separate stages.** The PII stage uses Presidio; toxicity is an independent interface and can be replaced with a model or service.
2. **Original input remains immutable during detection.** Presidio findings are applied by its anonymizer rather than mutating the source string while offsets are being discovered.
3. **Credit-card candidates use Luhn validation.** This reduces false positives but does not prove that a number is an active card or that every card format is detected.
4. **Fail explicitly.** Model errors raise exceptions by default rather than returning an unqualified “clean” result.
5. **No universal cleanliness guarantee.** The tool reduces risk; recall depends on recognizers, model choice, language, context, and configuration.
6. **Toxicity default is disabled.** `NoOpToxicityFilter` makes no toxicity claims. Install and configure the optional adapter when toxicity analysis is required.

## Scope and limitations

- The built-in Presidio recognizers and the custom recognizers are a starting point, not a complete global PII taxonomy.
- Phone numbers and locations can be ambiguous. Tune recognizers and thresholds for your target countries and use cases.
- Toxicity detection is language- and context-dependent. Do not use a toxicity score as a universal judgment of intent.
- Redaction placeholders are not encryption or reversible tokenization.
- For production use, add access controls, audit logging that avoids raw PII, model/version pinning, monitoring, and a representative labeled evaluation set.

## Project layout

```text
pii_toxicity_guard/
  __init__.py
  cli.py
  config.py
  schemas.py
  guard.py
  pii/
    __init__.py
    recognizers.py
    checksums.py
    detector.py
    redactor.py
  toxicity/
    __init__.py
    base.py
    detoxify_adapter.py
    pipeline.py
tests/
  test_checksums.py
  test_recognizers.py
  test_toxicity.py
  test_guard.py
```
