# Evaluating models (decision-waf-eval)

`decision-waf-eval` measures how well a decision model separates benign from malicious requests on a labelled dataset the operator supplies, and where `DECISION_WAF_BLOCK_THRESHOLD` should sit for it. It runs each request in-process through the same decision engine the server uses, records one result per request in a results file, and computes every metric from that file afterwards. decision-waf ships the tool and a 24-request sample. It does not ship an attack corpus. Usage is in [Evaluating models](../evaluation.md); this note explains the choices behind it.

## Context

The threshold and the choice of model decide how many real users get blocked and how many attacks get through, and nothing else in the repo answers either question. Operators need a repeatable measurement for their own backend (hosted Jev, a local d1 model, or an OpenAI-compatible LLM), on data that resembles their own traffic. The measurement has to be trustworthy: a run full of timeouts must not look like a clean run, and two backends must be comparable only when they saw the same requests.

The integration tests ([testing.md](testing.md)) use a stub model and check plumbing, not detection. Evaluation is the opposite: real models, no proxies.

## Decisions

### Run in-process through the production engine, not through a proxy

`decision-waf-eval run` builds a `decision.Engine` with `backend.Engine` (`internal/backend`), the same function the server uses. That package holds only the backend and engine wiring, so `decision-waf-eval` does not pull in the server's listeners, frontends or gRPC, and a test in `cmd/decision-waf-eval` keeps it that way. Backend client, guard (timeout and breaker), policy, redaction, prompt rendering, the attack-score rule, threshold and failure mode are therefore the production ones, and a test asserts both paths decide identically. Configuration comes from the usual `DECISION_WAF_*` variables through `internal/config`; only classifier, policy, threshold, and body-limit settings matter here.

Why: a proxy adds Docker, ports and frontend quirks that have nothing to do with model quality, and it makes a 1,000-request run slow and flaky. A separate scoring path would drift from production. Rejected: driving Envoy or NGINX (slow, measures the wrong thing); a second, simplified evaluator pipeline (would not catch policy or redaction changes).

The score is read from the `decision.Decision`: `Verdict.AttackScore()` (1 minus P(benign)) when the request was classified, otherwise the decision's reason is recorded as the error. The engine needed no new accessor. Requests are built as `standard` mode builds them: bodies are cut to `DECISION_WAF_BODY_MAX_BYTES` with `BodyTruncated` set, and gRPC entries set service and method.

### A strict, small JSONL dataset format

`internal/eval/dataset`: line 1 is a header (`decision_waf_eval_dataset: 1`, optional `name` and `description`); each other line is one request with `id`, `label`, `method`, `path` and optional `scheme`, `host`, `query`, `headers` (name to list of values, names lower-cased), `body_b64`, `grpc`, `tags` and `note`. Labels must be `benign` or a category of the active policy, so a dataset is validated against the policy it will be run with.

Loading fails with every problem listed, each with its line number: unknown fields (catches typos such as `quary`), field names in another case and repeated keys (`encoding/json` would read `"LABEL"` as the label, and the last of two `label` keys, silently; `internal/eval/strictjson`), missing required fields, a path without a leading `/`, duplicate IDs, labels outside the policy, invalid base64, and a `grpc` value that is not `package.Service/Method` or does not match `path`. An unknown header version, an empty file and a file with no requests are also refused. Lines may be up to 64 MiB (bodies) and may end in CRLF. Strictness matters because a silently ignored field produces a plausible but wrong report. JSON Lines was chosen over one JSON array so datasets can be appended to, diffed and streamed.

### Ship a small hand-written sample, not an attack corpus

`eval/datasets/sample.jsonl` holds 24 requests: 10 benign (five tagged `lookalike`, benign requests that resemble attacks) and 14 classic, illustrative attacks across `injection`, `xss`, `file_access` and `recon`. It exists so the tool runs out of the box and the tests have data. It is far too small to tune a threshold on, and the usage guide and every report say so.

decision-waf does not generate or ship a larger attack corpus, and does not redistribute third-party datasets. Operators evaluate on their own labelled traffic, or on public labelled HTTP datasets they obtain under those datasets' own licences; the usage guide has a recipe for converting one. An earlier design had a `generate` command that would author a 1,200-request corpus; it was dropped. The repo should not be a store of attack payloads, a synthetic corpus would flatter or punish a model in ways real traffic does not, and the people who need an answer have better data than we could invent.

### Results are a self-describing file; everything else is computed from it

`internal/eval/results`: line 1 is a header, then one line per request: `id`, `label`, `tags`, `attack_score`, `category`, `outcome`, `error`, `latency_ms`. The header records the dataset (path, name, SHA-256, entry count), backend, base URL (without any user and password), model, classifier timeout, run threshold, policy (path or `default`, plus the SHA-256 of the policy file), body limit, sample size and seed, decision-waf version (`internal/version.Version`, set by ldflags, default `dev`) and start time.

Metrics can then be recomputed at any threshold without calling a model, and `report` and `compare` never need the dataset or a backend. A classifier failure has no `attack_score` and records its reason in `error`; it is never counted as benign or as an attack.

`Header.SameRun` decides whether a file may be resumed: everything must match except the start time and the dataset's path (the file may have moved). That includes the dataset hash, backend, base URL, model, classifier timeout, threshold, policy hash and version, body limit, sample and seed, and decision-waf version. The base URL and timeout were added after a review found that a resume against another server with the same model name, or with a longer timeout (and so a different error rate), was accepted. Changing any of them mid-file would mix two experiments.

### Resume by truncating a partial last line

`--resume` skips IDs already in the file. An interrupted run can leave a partial last line, because each result is written in one `Write` call and only the final line can be cut. The reader ignores a final line with no newline, and `openResults` (`cmd/decision-waf-eval/run.go`) truncates the file to the length of its complete lines before appending, so the partial line is never glued to the next one. An existing file is refused without `--resume`, and with it unless the header is the same run.

### Sampling is stratified and seeded

`run.Sample` takes `--sample N` entries, keeps each label's share of the dataset (largest remainder), and keeps at least one entry per label when N allows. It depends only on the entries, N and the seed (`--seed`, default 1; PCG), so two backends can be given the same sample, and `compare` can tell they were. A plain random sample of a mostly-benign dataset would often contain no sample of a rare category.

### An evaluator breaker that never opens

The server's circuit breaker turns a burst of timeouts into fast `circuit_open` failures. In an evaluation that would make everything after the first few timeouts look like a different kind of error and hide how the model really behaved. `run.NewBreaker` is a breaker with an unreachable threshold (`math.MaxInt`); timeouts and panic handling in the guard are unchanged.

### Detection uses the global threshold; the sweep is a fixed grid

A request counts as flagged when its attack score is at least the threshold, the engine's rule. Per-route policy thresholds are not applied: every result is judged at one threshold. This is what `--threshold` and the recommendations refer to.

The sweep covers 0.05 to 0.95 in steps of 0.05, each computed as `i/20` rather than by repeated addition, so 0.8 is exactly the float an operator types and lands on the same side of a score of 0.8 as the engine does. Two recommended points are reported: best F1, and best recall with false-positive rate at most `--max-fpr` (default 0.01). Ties go to the higher threshold, the more conservative choice (fewer blocks). If no point has F1 above 0, or no point meets the ceiling with recall above 0, the recommendation is absent ("none").

### Undefined rates and small datasets

A rate with a zero denominator (no attacks, nothing flagged) is 0 in the JSON output, so consumers get a number, and `n/a` in the text and Markdown reports, so people are not told a model has 0% recall when there was nothing to measure. F1 is `n/a` when precision or recall is undefined. Reports warn when fewer than 100 benign or 100 attack requests were scored (`metrics.MinPerClass`), when the results cover fewer requests than the run intended, and when any requests failed.

### compare refuses mismatched datasets

`compare A B` puts the main metrics of two runs side by side at one threshold (A's run threshold unless `--threshold` is given) with each run's recommended points. Runs with different dataset hashes, or different samples or seeds of one dataset, are refused unless `--allow-different-datasets`: a difference in F1 between two datasets says little about the models.

## How it works

- `cmd/decision-waf-eval`: the CLI (`main.go` dispatch and exit codes, `run.go`, `report.go`).
- `internal/eval/dataset`: read, validate and convert entries to `inspect.Request`.
- `internal/eval/run`: `Run`, `Sample`, `NewBreaker`.
- `internal/eval/results`: header, result lines, reader and writer.
- `internal/eval/metrics`: confusion matrix, sweep, recommendations, per-label recall, latency, warnings.
- `internal/eval/report`: text, Markdown and JSON renderers, and `compare`.

**Runner.** `run` loads the config and policy, loads and validates the dataset against the policy's labels, samples, and probes the backend (30 s, like the server) before writing anything, so a model that is not up fails fast with exit 1. It then writes or resumes the results file and calls `run.Run`. `--concurrency N` (default 1) uses N workers; each result is written as one line under a mutex, so concurrency changes the order of lines but not their content. When the context is cancelled (SIGINT or SIGTERM), dispatch stops and requests still in flight are not recorded, so a resumed run repeats them rather than keeping a result produced by a cancelled call. The run prints the results path to stdout, progress to stderr, and a summary of failures if any.

**Metrics.** Besides binary detection (TP, FP, TN, FN, precision, recall, F1, false-positive rate) the report gives recall per attack label, how many detected attacks had the label as top category (attribution), false positives on benign requests overall and for `lookalike`-tagged ones, p50/p95/p99 latency (nearest rank), errors by reason, and with `--by-tag` the same confusion figures per tag.

**Exit codes.** 0 success; 1 runtime failure (backend not ready, I/O error, interrupted run; an interrupted run prints the `--resume --out` command); 2 usage or invalid input (bad flags, invalid dataset, configuration or threshold, results file that exists without `--resume`, mismatched resume, refused `compare`). A missing results file given to `report` or `compare` is exit 1.

**`make eval`.** `make eval MODEL_URL=… MODEL=…` builds the binary, runs the dataset (`DATASET`, default the sample), and prints the report. Optional: `MODEL_BACKEND` (`jev` or `openai`, default `jev`), `MODEL_API_KEY`, `MODEL_TIMEOUT` (default 10 s, since real models are slower than the 1 s product default), `SAMPLE`, `CONCURRENCY`, and `EVAL_OUT` with `RESUME=1`. Settings reach the tool as exported variables, so make never echoes the API key. Results default to a timestamped file under `bin/eval/` (git-ignored); `eval/` is excluded from the product image build context in `.dockerignore`.

**Example reports.** `eval/results/` has three Markdown reports on the shipped sample: `d1-3b-sample.md` (a d1 model served locally by LM Studio, `jev` backend), `jev-latest-sample.md` (hosted Jev, `jev-latest`) and `h2o-lightning-4b-sample.md` (a general-purpose 4B reasoning model served locally by LM Studio, `openai` backend). Each is labelled illustrative and carries the small-dataset warning. On this sample d1-3b flags 10 of 14 attacks and `jev-latest` all 14, with no false positives in either. h2o-lightning-4b flags 7 of 14 at the default 0.80, blocks one benign lookalike (`/news/etc-and-more` as path traversal) and times out on another at 60 s. Its misses are scored 0.59 to 0.77 with the right category, so its scores sit lower than a dedicated classifier's rather than missing the attacks outright. It is also slower (p50 about 5 s, against 2.3 s for d1-3b), because each call includes the model's reasoning. None of this says anything reliable about the models; it shows what the output looks like.

Reasoning models served by LM Studio work with the `openai` backend: LM Studio keeps the reasoning out of `content`, accepts `json_schema` and returns logprobs. The base URL must end in `/v1`, and the timeout must cover the reasoning time.

## Limitations and trade-offs

- The sample cannot support a threshold choice. Recommending a default threshold needs a larger operator-supplied or public dataset, which decision-waf does not provide.
- Report quality is bounded by label quality; the tool does not check labels.
- Per-route policy thresholds are not applied; every result is judged at one global threshold.
- No confidence intervals or significance tests; `compare` shows point estimates only.
- The evaluator's breaker never opens, so it cannot show how the server behaves under sustained timeouts (see [architecture.md](architecture.md) for that).
- No HAR or log converters; datasets in other formats need a small script.
- Requests in flight at cancellation are lost and re-run on resume, which wastes a few model calls.
- No web UI and no automatic tuning of category descriptions.

## History

- 2026-10-13: A dataset generator and a 1,200-request attack corpus were dropped before implementation; the tool ships with a hand-written 24-request sample.
- 2026-10-13: The server's engine wiring was exported as `app.BuildEngine` so the evaluator and the server cannot drift.
- 2026-10-13: First example reports recorded for d1-3b (local) and `jev-latest` (hosted).
- 2026-10-14: Example report added for h2o-lightning-4b, the first through the `openai` backend.
- 2026-10-14: The backend and engine wiring moved from `internal/app` to `internal/backend`, so `ailuros-eval` no longer depends on the server.
- 2026-10-14: Dataset and results files reject field names in another case and repeated keys, which `encoding/json` accepted silently.
- 2026-10-14: Results headers record the base URL and classifier timeout, and a resume with different ones is refused.
- 2026-10-14: Every human-readable rate with a zero denominator prints `n/a` (compare, attribution, the recommended points), best recall needs a measurable FPR, and chosen thresholds print exactly (0.825, not 0.82).
- 2026-10-14: Dataset requests are built with `inspect.NewRequest`, the frontends' constructor (moved from `internal/frontend`), so the query is split and gRPC detected as through a proxy; a `?` in `path` and a non-gRPC content type on a `grpc` entry are rejected.
