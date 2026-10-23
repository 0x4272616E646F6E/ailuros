# decision-waf-eval report

| | |
|---|---|
| Dataset | fixture (`eval/datasets/fixture.jsonl`, sha256 `aaaaaaaaaaaa`, 11 requests) |
| Backend | jev, model `d1-3b` |
| Policy | default |
| Threshold | 0.8 (run: 0.8) |
| decision-waf | dev |
| Started | 2026-10-13T12:00:00Z |
| Requests | 11 (9 scored, 2 errors) |

> **Warning:** 2 of 11 requests failed and are excluded from detection metrics (rate_limited 1, timeout 1)

> **Warning:** only 5 benign and 4 attack requests were scored; the sweep and recommendations need at least 100 of each to be meaningful

## Detection

Attack vs benign; errors excluded.

| Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|
| 0.750 | 0.750 | 0.750 | 0.200 | 3 | 1 | 4 | 1 |

## Attacks by label

| Label | Total | Detected | Recall | Attributed | Errors |
|---|---|---|---|---|---|
| injection | 3 | 2 | 0.667 | 1 | 1 |
| xss | 1 | 1 | 1.000 | 1 | 0 |

Category attribution: 0.667 (detected attacks whose top category is the label).

## Benign

| Scored | Blocked | FPR | Lookalikes | Lookalikes blocked | Errors |
|---|---|---|---|---|---|
| 5 | 1 | 0.200 | 2 | 1 | 1 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 |
|---|---|---|---|---|
| 0.05 | 0.500 | 1.000 | 0.800 | 0.667 |
| 0.10 | 0.571 | 1.000 | 0.600 | 0.727 |
| 0.15 | 0.667 | 1.000 | 0.400 | 0.800 |
| 0.20 | 0.667 | 1.000 | 0.400 | 0.800 |
| 0.25 | 0.667 | 1.000 | 0.400 | 0.800 |
| 0.30 | 0.667 | 1.000 | 0.400 | 0.800 |
| 0.35 | 0.800 | 1.000 | 0.200 | 0.889 |
| 0.40 | 0.800 | 1.000 | 0.200 | 0.889 |
| 0.45 | 0.750 | 0.750 | 0.200 | 0.750 |
| 0.50 | 0.750 | 0.750 | 0.200 | 0.750 |
| 0.55 | 0.750 | 0.750 | 0.200 | 0.750 |
| 0.60 | 0.750 | 0.750 | 0.200 | 0.750 |
| 0.65 | 0.750 | 0.750 | 0.200 | 0.750 |
| 0.70 | 0.750 | 0.750 | 0.200 | 0.750 |
| 0.75 | 0.750 | 0.750 | 0.200 | 0.750 |
| 0.80 | 0.750 | 0.750 | 0.200 | 0.750 |
| 0.85 | 0.750 | 0.750 | 0.200 | 0.750 |
| 0.90 | 1.000 | 0.500 | 0.000 | 0.667 |
| 0.95 | 1.000 | 0.250 | 0.000 | 0.400 |

- Best F1: threshold 0.40 (precision 0.800, recall 1.000, fpr 0.200, f1 0.889)
- Best recall with FPR ≤ 0.010: threshold 0.90 (precision 1.000, recall 0.500, fpr 0.000, f1 0.667)

## Latency and errors

- Latency: p50 600 ms, p95 1100 ms, p99 1100 ms
- Errors: 2 of 11 (18.2%): rate_limited 1, timeout 1

## By tag

| Tag | Precision | Recall | FPR | F1 | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| lookalike | 0.000 | n/a | 0.500 | n/a | 0 | 1 | 1 | 0 |
| path | n/a | 0.000 | n/a | n/a | 0 | 0 | 0 | 1 |
| query | 1.000 | 1.000 | n/a | 1.000 | 3 | 0 | 0 | 0 |
