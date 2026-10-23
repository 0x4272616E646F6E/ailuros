> Produced with the categories before 0.3.0 (`sqli`, `rce`, `path_traversal`, `scanner`, …). Illustrative example of decision-waf-eval output: hosted Jev `jev-latest` (`https://api.typesafe.ai`, `jev` backend) on the 24-request shipped sample. The sample is far too small to choose a threshold with; this is not a recommendation.

# decision-waf-eval report

| | |
|---|---|
| Dataset | sample (`eval/datasets/sample.jsonl`, sha256 `565c26f0da6e`, 24 requests) |
| Backend | jev, model `jev-latest` |
| Policy | default |
| Threshold | 0.80 (run: 0.80) |
| decision-waf | d16b286 |
| Started | 2026-10-13T23:59:57Z |
| Requests | 24 (24 scored, 0 errors) |

> **Warning:** only 10 benign and 14 attack requests were scored; the sweep and recommendations need at least 100 of each to be meaningful

## Detection

Attack vs benign; errors excluded.

| Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|
| 1.000 | 1.000 | 1.000 | 0.000 | 14 | 0 | 10 | 0 |

## Attacks by label

| Label | Total | Detected | Recall | Attributed | Errors |
|---|---|---|---|---|---|
| path_traversal | 2 | 2 | 1.000 | 2 | 0 |
| rce | 3 | 3 | 1.000 | 3 | 0 |
| scanner | 4 | 4 | 1.000 | 4 | 0 |
| sqli | 3 | 3 | 1.000 | 3 | 0 |
| xss | 2 | 2 | 1.000 | 2 | 0 |

Category attribution: 1.000 (detected attacks whose top category is the label).

## Benign

| Scored | Blocked | FPR | Lookalikes | Lookalikes blocked | Errors |
|---|---|---|---|---|---|
| 10 | 0 | 0.000 | 5 | 0 | 0 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 |
|---|---|---|---|---|
| 0.05 | 0.875 | 1.000 | 0.200 | 0.933 |
| 0.10 | 0.933 | 1.000 | 0.100 | 0.966 |
| 0.15 | 0.933 | 1.000 | 0.100 | 0.966 |
| 0.20 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.25 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.30 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.35 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.40 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.45 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.50 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.55 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.60 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.65 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.70 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.75 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.80 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.85 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.90 | 1.000 | 1.000 | 0.000 | 1.000 |
| 0.95 | 1.000 | 1.000 | 0.000 | 1.000 |

- Best F1: threshold 0.95 (precision 1.000, recall 1.000, fpr 0.000, f1 1.000)
- Best recall with FPR ≤ 0.010: threshold 0.95 (precision 1.000, recall 1.000, fpr 0.000, f1 1.000)

## Latency and errors

- Latency: p50 138 ms, p95 188 ms, p99 210 ms
- Errors: none

## By tag

| Tag | Precision | Recall | FPR | F1 | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| header | 1.000 | 1.000 | n/a | 1.000 | 1 | 0 | 0 | 0 |
| lookalike | n/a | n/a | 0.000 | n/a | 0 | 0 | 5 | 0 |
| path | 1.000 | 1.000 | 0.000 | 1.000 | 5 | 0 | 5 | 0 |
| query | 1.000 | 1.000 | 0.000 | 1.000 | 8 | 0 | 5 | 0 |
