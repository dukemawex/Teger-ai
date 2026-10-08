# Phishing Evaluation Harness

Measures what Teger's **deterministic** layer (`packages/security-core`) does on a
labelled sample set. It runs with **no reputation provider**, so URL-only samples
without heuristic hits come out `unknown` and are counted as abstentions.

```bash
python ml/evaluation/harness.py --check-only   # schema, provenance and leakage checks (CI gate)
python ml/evaluation/harness.py                # + evaluation, writes ml/evaluation/reports/latest.json
python -m pytest -q ml/evaluation/tests
```

## Sample format

`samples/malicious.jsonl` and `samples/benign.jsonl` (labels kept in separate files):

| field | notes |
|---|---|
| `id` | unique (`MAL-###`, `BEN-###`) |
| `label` | must match the file |
| `split` | `dev` (may be used while writing rules) or `test` (held out — never tune on it) |
| `content_type` | `email` / `chat` / `sms` / `web` / `other` |
| `content`, `url`, `sender`, `subject` | at least one of `content` / `url` |
| `provenance` | `source` (`synthetic` / `public-dataset` / `contributed`), `author`, `created`, `license`; non-synthetic also needs `reference` |

## Leakage and safety checks (all enforced)

- Unique IDs; both splits contain both labels.
- No near-duplicates (character 5-gram Jaccard ≥ 0.8) between any two samples, across splits or labels.
- No near-duplicates of `dataset/patterns/*.jsonl` examples (the material detector rules were written from).
- Malicious samples may only reference reserved names (`.test`, `.example`, `.invalid`,
  `example.com/net/org`, RFC 5737 documentation IPs). No live malicious links.
- Benign samples may not share a domain with any malicious sample.

## Honest reading of results

The current set is 32 synthetic samples written by the same maintainers who wrote the
detector rules. Results are a regression signal, **not** a benchmark of real-world
accuracy. Expand with independently sourced, licensed data before quoting any metric.
