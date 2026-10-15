# Evaluating models
`ailuros-eval` measures how well a decision model separates benign from
malicious requests on a labelled dataset, and where `AILUROS_BLOCK_THRESHOLD`
should sit for it. It sends each request through Ailuros's own decision
pipeline (policy, redaction, rendering, backend client, attack-score rule)
in-process; no proxy or server is involved.

```bash
make eval MODEL_URL=http://localhost:1234 MODEL=d1-3b
```

runs the shipped sample against a model and prints the report. For an
OpenAI-compatible server add `MODEL_BACKEND=openai` and include `/v1` in
`MODEL_URL` (for example `http://localhost:1234/v1`). Underneath it
is:

```bash
ailuros-eval run --dataset eval/datasets/sample.jsonl --out bin/eval/run.jsonl
ailuros-eval report bin/eval/run.jsonl            # --markdown, --json, --by-tag, --threshold 0.6
ailuros-eval compare bin/eval/a.jsonl bin/eval/b.jsonl
```

`run` reads the same `AILUROS_*` variables as `ailuros` (backend, base URL,
model, API key, timeout, policy file, threshold, body limit). Real models are
usually slower than the 1 s default `AILUROS_CLASSIFIER_TIMEOUT`; `make eval`
sets 10 s (`MODEL_TIMEOUT`). Timeouts and other classifier failures are
reported as errors and left out of the detection numbers, so a run full of
timeouts says so rather than looking clean. `--sample N` evaluates a
stratified random sample; `--concurrency N` runs N requests at once; an
interrupted run continues with `--resume` and the same `--out`, as long as
it is the same run: everything the results file's header records must
match except the start time and the dataset's path. That is the
results-file format version, the dataset's contents, backend, model server,
model, classifier timeout, threshold, policy (path and contents), body
limit, prompt version, sample size, seed, and the Ailuros version
`ailuros-eval` was built from, so a binary built with `make` from another
commit cannot resume the run (`go build` and `go run` stamp `dev`).

**Reading the report.** Detection counts a request as flagged when its attack
score (1 − P(benign)) is at least the threshold, as Ailuros does; per-route
policy thresholds are not applied. The sweep shows precision, recall,
false-positive rate, and F1 from 0.05 to 0.95 and recommends two points:
best F1, and the highest recall whose false-positive rate is at most
`--max-fpr` (default 0.01). Choose `AILUROS_BLOCK_THRESHOLD` from those with
your own tolerance for blocking real users in mind. The report warns when
fewer than 100 benign or 100 attack requests were scored: below that, the
recommendations are noise.

**Prompt version.** The results header records `prompt_version` (currently
2: version 2 added the `signals:` block). `compare` warns when the two runs
differ in it, since their scores are not directly comparable; results from
before the field count as version 1. A request blocked by a policy limit
carries `limit` (the limit name) in its result, with an attack score of 1 and
no model call. It counts toward detection and recall, but not toward
category attribution (it names no category) or latency (the model was not
called). When every detected attack was a limit block, attribution prints
`n/a`; the JSON report gives its denominator as `attribution_detected`.

**The shipped sample** (`eval/datasets/sample.jsonl`) is 24 hand-written
requests: 10 benign, five of them tagged `lookalike`, and 14 classic attacks.
It makes the tool runnable and is used by the tests; it is far too small to
choose a threshold with. `eval/results/` holds example reports.

**Bringing your own data.** A dataset is JSON Lines: a header line, then one
labelled request per line.

```json
{"ailuros_eval_dataset": 1, "name": "shop-2026-10", "description": "Sampled production traffic, hand-labelled"}
{"id": "r-1", "label": "benign", "method": "GET", "scheme": "https", "host": "shop.example.com", "path": "/search", "query": "q=red+shoes", "headers": {"user-agent": ["Mozilla/5.0"]}, "tags": ["query"]}
{"id": "r-2", "label": "sqli", "method": "POST", "path": "/login", "body_b64": "dXNlcj1hZG1pbictLSZwYXNzPXg=", "tags": ["body"]}
```

`label` is `benign` or a category from your policy; `method` and `path` are
required, and the query string goes in `query`, not in `path`; `headers` maps names to lists of values; bodies are base64 in
`body_b64` and cut to `AILUROS_BODY_MAX_BYTES` as in `standard` mode; gRPC
requests set `grpc` to `package.Service/Method` (the path must match, and a
`content-type` header, if any, must be gRPC; `application/grpc` is added when
there is none) and
carry one unframed protobuf message as the body; `protocol` (`HTTP/1.1`, `HTTP/2`, …) and `ja4` set the connection metadata that the proxy would supply, so recorded traffic replays with its signals; `note` and `tags` are free
text (`tags` slice the report with `--by-tag`; `lookalike` gets its own
false-positive count). Unknown fields, field names in another case (`LABEL`)
and keys repeated within one object are rejected, so a typo cannot silently
drop a field. Headers that the default policy redacts (`authorization`,
`cookie`, …) never reach the model, exactly as in production.

The best data is your own traffic: export a sample of requests from your
proxy logs, label it, and write it in this format. Public labelled HTTP
datasets work too, under their own licences; Ailuros does not redistribute
them. For example, the CSIC 2010 HTTP dataset ships normal and anomalous
requests as raw HTTP text: parse each request's method, path, query, headers,
and body, label the normal ones `benign` and the anomalous ones with the
closest category from your policy, and write one line per request. Whatever
the source, check the labels: the report can only be as right as they are.
