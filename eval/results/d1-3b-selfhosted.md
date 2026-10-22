> `LiquidAI/d1-3B-GGUF` (Q8_0), a decision model, served by llama.cpp server build 11822 on an Apple M4 (Metal) through the `jev` backend (`/v1/systemone`), `AILUROS_INSPECTION_MODE=lite`, one request at a time. Latency is the M4's; on an RTX 4000 SFF Ada the same model answers in about 0.1 s.

# ailuros-eval report

| | |
|---|---|
| Dataset | selfhosted-2026-10 (`eval/datasets/selfhosted.jsonl`, sha256 `cb93cc8dfc33`, 271 requests) |
| Backend | jev, model `d1-3B` at http://127.0.0.1:18080, timeout 30s |
| Policy | default |
| Threshold | 0.8 (run: 0.8) |
| Ailuros | v0.1.0-1-g847564d |
| Started | 2026-10-22T18:33:28Z |
| Requests | 271 (271 scored, 0 errors) |

## Detection

Attack vs benign; errors excluded.

| Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|
| 0.985 | 0.486 | 0.650 | 0.008 | 67 | 1 | 132 | 71 |

## Attacks by label

| Label | Total | Detected | Recall | Attributed | Errors |
|---|---|---|---|---|---|
| credential_stuffing | 8 | 7 | 0.875 | 7 | 0 |
| path_traversal | 20 | 18 | 0.900 | 18 | 0 |
| rce | 30 | 8 | 0.267 | 6 | 0 |
| scanner | 30 | 10 | 0.333 | 8 | 0 |
| sqli | 27 | 11 | 0.407 | 6 | 0 |
| xss | 23 | 13 | 0.565 | 13 | 0 |

Category attribution: 0.866 (detected attacks whose top category is the label).

## Benign

| Scored | Blocked | FPR | Lookalikes | Lookalikes blocked | Errors |
|---|---|---|---|---|---|
| 133 | 1 | 0.008 | 24 | 1 | 0 |

## Threshold sweep

| Threshold | Precision | Recall | FPR | F1 |
|---|---|---|---|---|
| 0.05 | 0.511 | 1.000 | 0.992 | 0.676 |
| 0.10 | 0.563 | 1.000 | 0.805 | 0.721 |
| 0.15 | 0.673 | 0.986 | 0.496 | 0.800 |
| 0.20 | 0.786 | 0.957 | 0.271 | 0.863 |
| 0.25 | 0.816 | 0.899 | 0.211 | 0.855 |
| 0.30 | 0.885 | 0.841 | 0.113 | 0.862 |
| 0.35 | 0.935 | 0.833 | 0.060 | 0.881 |
| 0.40 | 0.949 | 0.812 | 0.045 | 0.875 |
| 0.45 | 0.963 | 0.746 | 0.030 | 0.841 |
| 0.50 | 0.970 | 0.703 | 0.023 | 0.815 |
| 0.55 | 0.969 | 0.674 | 0.023 | 0.795 |
| 0.60 | 0.977 | 0.623 | 0.015 | 0.761 |
| 0.65 | 0.977 | 0.609 | 0.015 | 0.750 |
| 0.70 | 0.976 | 0.580 | 0.015 | 0.727 |
| 0.75 | 0.973 | 0.529 | 0.015 | 0.685 |
| 0.80 | 0.985 | 0.486 | 0.008 | 0.650 |
| 0.85 | 1.000 | 0.442 | 0.000 | 0.613 |
| 0.90 | 1.000 | 0.362 | 0.000 | 0.532 |
| 0.95 | 1.000 | 0.239 | 0.000 | 0.386 |

- Best F1: threshold 0.35 (precision 0.935, recall 0.833, fpr 0.060, f1 0.881)
- Best recall with FPR ≤ 0.010: threshold 0.80 (precision 0.985, recall 0.486, fpr 0.008, f1 0.650)

## Latency and errors

- Latency: p50 3408 ms, p95 3808 ms, p99 3988 ms
- Errors: none
