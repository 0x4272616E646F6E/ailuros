> Illustrative example of decision-waf-eval output: `mradermacher/h2o-lightning-4b` (a GGUF build of H2O.ai's h2o-lightning-4b, served by LM Studio, `openai` backend, `DECISION_WAF_CLASSIFIER_TIMEOUT=60s`) on the 24-request shipped sample. Through a chat API it reasons before answering, so each call includes its thinking time; served by llama.cpp server through the `jev` backend it does not (see `h2o-lightning-4b-selfhosted.md`). The sample is far too small to choose a threshold with; this is not a recommendation.

# decision-waf-eval report

| | |
|---|---|
| Dataset | sample (`eval/datasets/sample.jsonl`, sha256 `565c26f0da6e`, 24 requests) |
| Backend | openai, model `mradermacher/h2o-lightning-4b` |
| Policy | default |
| Threshold | 0.80 (run: 0.80) |
| decision-waf | 5571447 |
| Started | 2026-10-14T02:44:31Z |
| Requests | 24 (23 scored, 1 errors) |

> **Warning:** 1 of 24 requests failed and are excluded from detection metrics (timeout 1)

> **Warning:** only 9 benign and 14 attack requests were scored; the sweep and recommendations need at least 100 of each to be meaningful

## Detection

Attack vs benign; errors excluded.

| Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|
| 0.875 | 0.500 | 0.636 | 0.111 | 7 | 1 | 8 | 7 |

## Attacks by label

| Label | Total | Detected | Recall | Attributed | Errors |
|---|---|---|---|---|---|
| path_traversal | 2 | 2 | 1.000 | 2 | 0 |
| rce | 3 | 1 | 0.333 | 1 | 0 |
| scanner | 4 | 4 | 1.000 | 4 | 0 |
| sqli | 3 | 0 | 0.000 | 0 | 0 |
| xss | 2 | 0 | 0.000 | 0 | 0 |

Category attribution: 1.000 (detected attacks whose top category is the label).

## Benign

| Scored | Blocked | FPR | Lookalikes | Lookalikes blocked | Errors |
|---|---|---|---|---|---|
| 9 | 1 | 0.111 | 4 | 1 | 1 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 |
|---|---|---|---|---|
| 0.05 | 0.824 | 1.000 | 0.333 | 0.903 |
| 0.10 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.15 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.20 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.25 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.30 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.35 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.40 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.45 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.50 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.55 | 0.933 | 1.000 | 0.111 | 0.966 |
| 0.60 | 0.929 | 0.929 | 0.111 | 0.929 |
| 0.65 | 0.923 | 0.857 | 0.111 | 0.889 |
| 0.70 | 0.900 | 0.643 | 0.111 | 0.750 |
| 0.75 | 0.900 | 0.643 | 0.111 | 0.750 |
| 0.80 | 0.875 | 0.500 | 0.111 | 0.636 |
| 0.85 | 0.875 | 0.500 | 0.111 | 0.636 |
| 0.90 | 1.000 | 0.500 | 0.000 | 0.667 |
| 0.95 | 1.000 | 0.357 | 0.000 | 0.526 |

- Best F1: threshold 0.55 (precision 0.933, recall 1.000, fpr 0.111, f1 0.966)
- Best recall with FPR ≤ 0.010: threshold 0.90 (precision 1.000, recall 0.500, fpr 0.000, f1 0.667)

## Latency and errors

- Latency: p50 5108 ms, p95 13294 ms, p99 60001 ms
- Errors: 1 of 24 (4.2%): timeout 1
