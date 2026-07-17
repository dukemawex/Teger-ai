# Teger AI — Open Phishing-Pattern Dataset

An open, extensible dataset of social-engineering and phishing **patterns** — the
linguistic tactics behind modern attacks, each with concrete cues and a plain-language
explanation of *why* it is manipulation. It is the "open dataset of phishing patterns"
half of the Teger AI proposal, and it shares one taxonomy with the detector so a
detected tactic maps directly to a documented pattern.

This is a **pattern** dataset, not a dump of real victims' messages. Examples are
sanitized or synthetic representations of well-documented tactics — safe to publish,
useful for training, detection rules, and user education.

## Format
JSONL, one `PhishingPattern` per line, under `patterns/*.jsonl`:

| field | meaning |
|---|---|
| `id` | stable unique id (e.g. `TP-0012`) |
| `tactic` | a slug from [`taxonomy.py`](taxonomy.py) |
| `title` | short human label |
| `example_text` | representative (sanitized/synthetic) excerpt |
| `linguistic_cues` | the concrete surface signals to point at |
| `severity` | low / medium / high / critical |
| `source_type` | email / sms / chat / web / voice / synthetic |
| `explanation` | why it's manipulation — the reasoning shown to users |
| `tags` | free-form labels |

## Use it
```bash
python dataset/schema.py     # validate the whole dataset
python dataset/stats.py      # coverage by tactic / severity / source
python dataset/stats.py --json  # export a flat dataset/export.json
```

```python
import sys; sys.path.insert(0, "dataset")
from schema import load_patterns
patterns = load_patterns()
```

## Contribute
See [../CONTRIBUTING.md](../CONTRIBUTING.md#contributing-phishing-patterns). New tactics
go in `taxonomy.py` first; new examples are appended to a `patterns/*.jsonl` file and must
pass `python dataset/schema.py`.

## License
Released under the repository's MIT license for open research and defensive use.
