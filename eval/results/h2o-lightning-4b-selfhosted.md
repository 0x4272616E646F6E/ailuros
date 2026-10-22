> `h2oai/h2o-lightning-4b-gguf` (Q8_0), a decision model, served by llama.cpp server build 11822 on an Apple M4 (Metal) through the `jev` backend (`/v1/systemone`), `AILUROS_INSPECTION_MODE=lite`, one request at a time. Latency is the M4's; on an RTX 4000 SFF Ada the same model answers in about 0.2 s.

# ailuros-eval report

| | |
|---|---|
| Dataset | selfhosted-2026-10 (`eval/datasets/selfhosted.jsonl`, sha256 `cb93cc8dfc33`, 271 requests) |
| Backend | jev, model `h2o-lightning-4b` at http://127.0.0.1:18080, timeout 30s |
| Policy | default |
| Threshold | 0.8 (run: 0.8) |
| Ailuros | v0.1.0-1-g847564d |
| Started | 2026-10-22T18:48:30Z |
| Requests | 271 (271 scored, 0 errors) |

## Detection

Attack vs benign; errors excluded.

| Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|
| 0.932 | 0.899 | 0.915 | 0.068 | 124 | 9 | 124 | 14 |

## Attacks by label

| Label | Total | Detected | Recall | Attributed | Errors |
|---|---|---|---|---|---|
| credential_stuffing | 8 | 7 | 0.875 | 7 | 0 |
| path_traversal | 20 | 20 | 1.000 | 20 | 0 |
| rce | 30 | 26 | 0.867 | 22 | 0 |
| scanner | 30 | 21 | 0.700 | 21 | 0 |
| sqli | 27 | 27 | 1.000 | 26 | 0 |
| xss | 23 | 23 | 1.000 | 23 | 0 |

Category attribution: 0.960 (detected attacks whose top category is the label).

## Benign

| Scored | Blocked | FPR | Lookalikes | Lookalikes blocked | Errors |
|---|---|---|---|---|---|
| 133 | 9 | 0.068 | 24 | 8 | 0 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 |
|---|---|---|---|---|
| 0.05 | 0.521 | 1.000 | 0.955 | 0.685 |
| 0.10 | 0.692 | 0.993 | 0.459 | 0.815 |
| 0.15 | 0.773 | 0.964 | 0.293 | 0.858 |
| 0.20 | 0.831 | 0.964 | 0.203 | 0.893 |
| 0.25 | 0.853 | 0.964 | 0.173 | 0.905 |
| 0.30 | 0.864 | 0.964 | 0.158 | 0.911 |
| 0.35 | 0.887 | 0.964 | 0.128 | 0.924 |
| 0.40 | 0.893 | 0.964 | 0.120 | 0.927 |
| 0.45 | 0.898 | 0.957 | 0.113 | 0.926 |
| 0.50 | 0.904 | 0.957 | 0.105 | 0.930 |
| 0.55 | 0.904 | 0.957 | 0.105 | 0.930 |
| 0.60 | 0.910 | 0.957 | 0.098 | 0.933 |
| 0.65 | 0.910 | 0.949 | 0.098 | 0.929 |
| 0.70 | 0.915 | 0.942 | 0.090 | 0.929 |
| 0.75 | 0.920 | 0.913 | 0.083 | 0.916 |
| 0.80 | 0.932 | 0.899 | 0.068 | 0.915 |
| 0.85 | 0.938 | 0.877 | 0.060 | 0.906 |
| 0.90 | 0.945 | 0.877 | 0.053 | 0.910 |
| 0.95 | 0.958 | 0.833 | 0.038 | 0.891 |

- Best F1: threshold 0.60 (precision 0.910, recall 0.957, fpr 0.098, f1 0.933)
- Best recall with FPR ≤ 0.010: none

## Latency and errors

- Latency: p50 6027 ms, p95 6707 ms, p99 7146 ms
- Errors: none
