> `LiquidAI/d1-3B-GGUF` (Q8_0), a decision model, served by llama.cpp server build 11822 on an Apple M4 (Metal) through the `jev` backend (`/v1/systemone`), `DECISION_WAF_INSPECTION_MODE=lite`, default categories, one request at a time. Latency is the M4's; on an RTX 4000 SFF Ada the same model answers in about 0.1 s.

# decision-waf-eval report

| | |
|---|---|
| Dataset | selfhosted-2026-10b (`eval/datasets/selfhosted.jsonl`, sha256 `3dc08d6d1527`, 299 requests) |
| Backend | jev, model `d1-3B` at http://127.0.0.1:18080, timeout 30s |
| Policy | default |
| Threshold | 0.8 (run: 0.8) |
| decision-waf | v0.2.0-5-ge1e7244 |
| Started | 2026-10-23T03:10:38Z |
| Requests | 299 (299 scored, 0 errors) |

## Detection

Attack vs benign; errors excluded.

| Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|
| 0.989 | 0.565 | 0.719 | 0.007 | 87 | 1 | 144 | 67 |

## Attacks by label

| Label | Total | Detected | Recall | Attributed | Errors |
|---|---|---|---|---|---|
| auth_abuse | 8 | 8 | 1.000 | 8 | 0 |
| file_access | 20 | 18 | 0.900 | 18 | 0 |
| injection | 63 | 29 | 0.460 | 25 | 0 |
| recon | 30 | 12 | 0.400 | 9 | 0 |
| ssrf_redirect | 10 | 7 | 0.700 | 3 | 0 |
| xss | 23 | 13 | 0.565 | 13 | 0 |

Category attribution: 0.874 (detected attacks whose top category is the label).

## Benign

| Scored | Blocked | FPR | Lookalikes | Lookalikes blocked | Errors |
|---|---|---|---|---|---|
| 145 | 1 | 0.007 | 24 | 1 | 0 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 |
|---|---|---|---|---|
| 0.05 | 0.515 | 1.000 | 1.000 | 0.680 |
| 0.10 | 0.529 | 1.000 | 0.945 | 0.692 |
| 0.15 | 0.586 | 1.000 | 0.752 | 0.739 |
| 0.20 | 0.630 | 0.994 | 0.621 | 0.771 |
| 0.25 | 0.699 | 0.981 | 0.448 | 0.816 |
| 0.30 | 0.783 | 0.961 | 0.283 | 0.863 |
| 0.35 | 0.859 | 0.909 | 0.159 | 0.883 |
| 0.40 | 0.882 | 0.870 | 0.124 | 0.876 |
| 0.45 | 0.913 | 0.818 | 0.083 | 0.863 |
| 0.50 | 0.939 | 0.799 | 0.055 | 0.863 |
| 0.55 | 0.934 | 0.740 | 0.055 | 0.826 |
| 0.60 | 0.957 | 0.727 | 0.034 | 0.827 |
| 0.65 | 0.954 | 0.675 | 0.034 | 0.791 |
| 0.70 | 0.961 | 0.636 | 0.028 | 0.766 |
| 0.75 | 0.969 | 0.617 | 0.021 | 0.754 |
| 0.80 | 0.989 | 0.565 | 0.007 | 0.719 |
| 0.85 | 0.987 | 0.506 | 0.007 | 0.670 |
| 0.90 | 1.000 | 0.461 | 0.000 | 0.631 |
| 0.95 | 1.000 | 0.338 | 0.000 | 0.505 |

- Best F1: threshold 0.35 (precision 0.859, recall 0.909, fpr 0.159, f1 0.883)
- Best recall with FPR ≤ 0.010: threshold 0.80 (precision 0.989, recall 0.565, fpr 0.007, f1 0.719)

## Latency and errors

- Latency: p50 3476 ms, p95 4613 ms, p99 4786 ms
- Errors: none
