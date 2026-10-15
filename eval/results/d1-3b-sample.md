> Illustrative example of ailuros-eval output: d1-3b (LM Studio, `jev` backend) on the 24-request shipped sample. The sample is far too small to choose a threshold with; this is not a recommendation.

# ailuros-eval report

| | |
|---|---|
| Dataset | sample (`eval/datasets/sample.jsonl`, sha256 `565c26f0da6e`, 24 requests) |
| Backend | jev, model `d1-3b` |
| Policy | default |
| Threshold | 0.80 (run: 0.80) |
| Ailuros | 35b85b5 |
| Started | 2026-10-13T22:11:03Z |
| Requests | 24 (24 scored, 0 errors) |

> **Warning:** only 10 benign and 14 attack requests were scored; the sweep and recommendations need at least 100 of each to be meaningful

## Detection

Attack vs benign; errors excluded.

| Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|
| 1.000 | 0.714 | 0.833 | 0.000 | 10 | 0 | 10 | 4 |

## Attacks by label

| Label | Total | Detected | Recall | Attributed | Errors |
|---|---|---|---|---|---|
| path_traversal | 2 | 2 | 1.000 | 2 | 0 |
| rce | 3 | 2 | 0.667 | 1 | 0 |
| scanner | 4 | 3 | 0.750 | 3 | 0 |
| sqli | 3 | 2 | 0.667 | 1 | 0 |
| xss | 2 | 1 | 0.500 | 1 | 0 |

Category attribution: 0.800 (detected attacks whose top category is the label).

## Benign

| Scored | Blocked | FPR | Lookalikes | Lookalikes blocked | Errors |
|---|---|---|---|---|---|
| 10 | 0 | 0.000 | 5 | 0 | 0 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 |
|---|---|---|---|---|
| 0.05 | 0.667 | 1.000 | 0.700 | 0.800 |
| 0.10 | 0.737 | 1.000 | 0.500 | 0.848 |
| 0.15 | 0.812 | 0.929 | 0.300 | 0.867 |
| 0.20 | 0.929 | 0.929 | 0.100 | 0.929 |
| 0.25 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.30 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.35 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.40 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.45 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.50 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.55 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.60 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.65 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.70 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.75 | 1.000 | 0.929 | 0.000 | 0.963 |
| 0.80 | 1.000 | 0.714 | 0.000 | 0.833 |
| 0.85 | 1.000 | 0.714 | 0.000 | 0.833 |
| 0.90 | 1.000 | 0.500 | 0.000 | 0.667 |
| 0.95 | 1.000 | 0.429 | 0.000 | 0.600 |

- Best F1: threshold 0.75 (precision 1.000, recall 0.929, fpr 0.000, f1 0.963)
- Best recall with FPR ≤ 0.010: threshold 0.75 (precision 1.000, recall 0.929, fpr 0.000, f1 0.963)

## Latency and errors

- Latency: p50 2299 ms, p95 2580 ms, p99 2598 ms
- Errors: none

## By tag

| Tag | Precision | Recall | FPR | F1 | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| header | 1.000 | 1.000 | n/a | 1.000 | 1 | 0 | 0 | 0 |
| lookalike | n/a | n/a | 0.000 | n/a | 0 | 0 | 5 | 0 |
| path | 1.000 | 0.800 | 0.000 | 0.889 | 4 | 0 | 5 | 1 |
| query | 1.000 | 0.625 | 0.000 | 0.769 | 5 | 0 | 5 | 3 |
