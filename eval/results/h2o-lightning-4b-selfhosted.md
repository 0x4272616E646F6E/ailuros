> `h2oai/h2o-lightning-4b-gguf` (Q8_0), a decision model, served by llama.cpp server build 11822 on an Apple M4 (Metal) through the `jev` backend (`/v1/systemone`), `DECISION_WAF_INSPECTION_MODE=lite`, default categories, one request at a time. Latency is the M4's; on an RTX 4000 SFF Ada the same model answers in about 0.2 s.

# decision-waf-eval report

| | |
|---|---|
| Dataset | selfhosted-2026-10b (`eval/datasets/selfhosted.jsonl`, sha256 `3dc08d6d1527`, 299 requests) |
| Backend | jev, model `h2o-lightning-4b` at http://127.0.0.1:18080, timeout 30s |
| Policy | default |
| Threshold | 0.8 (run: 0.8) |
| decision-waf | v0.2.0-5-ge1e7244 |
| Started | 2026-10-23T02:42:35Z |
| Requests | 299 (299 scored, 0 errors) |

## Detection

Attack vs benign; errors excluded.

| Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|
| 0.880 | 0.903 | 0.891 | 0.131 | 139 | 19 | 126 | 15 |

## Attacks by label

| Label | Total | Detected | Recall | Attributed | Errors |
|---|---|---|---|---|---|
| auth_abuse | 8 | 5 | 0.625 | 5 | 0 |
| file_access | 20 | 20 | 1.000 | 20 | 0 |
| injection | 63 | 60 | 0.952 | 56 | 0 |
| recon | 30 | 21 | 0.700 | 20 | 0 |
| ssrf_redirect | 10 | 10 | 1.000 | 9 | 0 |
| xss | 23 | 23 | 1.000 | 23 | 0 |

Category attribution: 0.957 (detected attacks whose top category is the label).

## Benign

| Scored | Blocked | FPR | Lookalikes | Lookalikes blocked | Errors |
|---|---|---|---|---|---|
| 145 | 19 | 0.131 | 24 | 10 | 0 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 |
|---|---|---|---|---|
| 0.05 | 0.515 | 1.000 | 1.000 | 0.680 |
| 0.10 | 0.671 | 0.994 | 0.517 | 0.801 |
| 0.15 | 0.780 | 0.968 | 0.290 | 0.864 |
| 0.20 | 0.805 | 0.968 | 0.248 | 0.879 |
| 0.25 | 0.814 | 0.968 | 0.234 | 0.884 |
| 0.30 | 0.823 | 0.968 | 0.221 | 0.890 |
| 0.35 | 0.822 | 0.961 | 0.221 | 0.886 |
| 0.40 | 0.822 | 0.961 | 0.221 | 0.886 |
| 0.45 | 0.831 | 0.955 | 0.207 | 0.888 |
| 0.50 | 0.831 | 0.955 | 0.207 | 0.888 |
| 0.55 | 0.844 | 0.948 | 0.186 | 0.893 |
| 0.60 | 0.842 | 0.935 | 0.186 | 0.886 |
| 0.65 | 0.845 | 0.922 | 0.179 | 0.882 |
| 0.70 | 0.866 | 0.922 | 0.152 | 0.893 |
| 0.75 | 0.870 | 0.909 | 0.145 | 0.889 |
| 0.80 | 0.880 | 0.903 | 0.131 | 0.891 |
| 0.85 | 0.908 | 0.896 | 0.097 | 0.902 |
| 0.90 | 0.945 | 0.896 | 0.055 | 0.920 |
| 0.95 | 0.957 | 0.857 | 0.041 | 0.904 |

- Best F1: threshold 0.90 (precision 0.945, recall 0.896, fpr 0.055, f1 0.920)
- Best recall with FPR ≤ 0.010: none

## Latency and errors

- Latency: p50 4851 ms, p95 8066 ms, p99 8434 ms
- Errors: none
