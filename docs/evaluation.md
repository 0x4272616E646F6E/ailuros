# Evaluating models
`decision-waf-eval` measures how well a decision model separates benign from
malicious requests on a labelled dataset, and where `DECISION_WAF_BLOCK_THRESHOLD`
should sit for it. It sends each request through decision-waf's own decision
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
decision-waf-eval run --dataset eval/datasets/sample.jsonl --out bin/eval/run.jsonl
decision-waf-eval report bin/eval/run.jsonl            # --markdown, --json, --by-tag, --threshold 0.6
decision-waf-eval compare bin/eval/a.jsonl bin/eval/b.jsonl
```

`run` reads the same `DECISION_WAF_*` variables as `decision-waf` (backend, base URL,
model, API key, timeout, policy file, threshold, body limit). Real models are
usually slower than the 1 s default `DECISION_WAF_CLASSIFIER_TIMEOUT`; `make eval`
sets 10 s (`MODEL_TIMEOUT`). Timeouts and other classifier failures are
reported as errors and left out of the detection numbers, so a run full of
timeouts says so rather than looking clean. `--sample N` evaluates a
stratified random sample; `--concurrency N` runs N requests at once; an
interrupted run continues with `--resume` and the same `--out`, as long as
it is the same run: everything the results file's header records must
match except the start time and the dataset's path. That is the
results-file format version, the dataset's contents, backend, model server,
model, classifier timeout, threshold, policy (path and contents), body
limit, prompt version, sample size, seed, and the decision-waf version
`decision-waf-eval` was built from, so a binary built with `make` from another
commit cannot resume the run (`go build` and `go run` stamp `dev`).

**Reading the report.** Detection counts a request as flagged when its attack
score (1 − P(benign)) is at least the threshold, as decision-waf does; per-route
policy thresholds are not applied. The sweep shows precision, recall,
false-positive rate, and F1 from 0.05 to 0.95 and recommends two points:
best F1, and the highest recall whose false-positive rate is at most
`--max-fpr` (default 0.01). Choose `DECISION_WAF_BLOCK_THRESHOLD` from those with
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
{"decision_waf_eval_dataset": 1, "name": "shop-2026-10", "description": "Sampled production traffic, hand-labelled"}
{"id": "r-1", "label": "benign", "method": "GET", "scheme": "https", "host": "shop.example.com", "path": "/search", "query": "q=red+shoes", "headers": {"user-agent": ["Mozilla/5.0"]}, "tags": ["query"]}
{"id": "r-2", "label": "injection", "method": "POST", "path": "/login", "body_b64": "dXNlcj1hZG1pbictLSZwYXNzPXg=", "tags": ["body"]}
```

`label` is `benign` or a category from your policy; `method` and `path` are
required, and the query string goes in `query`, not in `path`; `headers` maps names to lists of values; bodies are base64 in
`body_b64` and cut to `DECISION_WAF_BODY_MAX_BYTES` as in `standard` mode; gRPC
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
datasets work too, under their own licences; decision-waf does not redistribute
them. For example, the CSIC 2010 HTTP dataset ships normal and anomalous
requests as raw HTTP text: parse each request's method, path, query, headers,
and body, label the normal ones `benign` and the anomalous ones with the
closest category from your policy, and write one line per request. Whatever
the source, check the labels: the report can only be as right as they are.

## The self-hosted dataset

`eval/datasets/selfhosted.jsonl` is 299 semi-synthetic requests in the shape a
self-hosted stack sees through forward-auth (headers only): 145 benign
requests to apps such as Sonarr, Radarr, Jellyfin, Home Assistant, Vaultwarden
and Forgejo from browsers and their own clients, 24 of them `lookalike`
searches (`O'Brien`, `cat /etc`, `<3 love`), and 154 attacks: SQL injection,
XSS, command and template injection including Log4Shell, path traversal,
scanner probes and scanner user agents, payloads in custom headers, and
scripted logins. 28 of the requests (tagged `extra`) were added by hand: 10
SSRF and open-redirect attempts, 6 CRLF and NoSQL injections, and 12 benign
requests that carry a URL or redirect target in a parameter. By label: 63
`injection`, 30 `recon`, 23 `xss`, 20 `file_access`, 10 `ssrf_redirect` and 8
`auth_abuse`. `eval/gen/selfhosted.py` regenerates it byte for byte. It is
large enough to compare models, but it is not recorded attack traffic, so
check a threshold against your own traffic before relying on it.

Two decision models served by llama.cpp server through the `jev` backend,
`DECISION_WAF_INSPECTION_MODE=lite`, default categories (reports in
`eval/results/*-selfhosted.md`):

| Threshold | Model | Precision | Recall | False-positive rate | F1 |
|---|---|---|---|---|---|
| 0.8 | `d1-3B` (Q8_0) | 0.989 | 0.565 | 0.007 | 0.719 |
| 0.8 | `h2o-lightning-4b` (Q8_0) | 0.880 | 0.903 | 0.131 | 0.891 |
| 0.9 | `d1-3B` | 1.000 | 0.461 | 0.000 | 0.631 |
| 0.9 | `h2o-lightning-4b` | 0.945 | 0.896 | 0.055 | 0.920 |

`h2o-lightning-4b` catches about twice as many attacks, including all 16
`extra` SSRF, redirect, CRLF and NoSQL attacks at 0.9, and names the right
category for 96% of the attacks it flags (`d1-3B`: 87%). At 0.9, 7 of its 8
false positives are `lookalike` searches; at 0.8, benign URL parameters such
as a `redirect_uri` back to the site start to score as `ssrf_redirect`.
Served through the `openai` backend instead, `d1-3B` reasons before
answering: in an earlier run on the first 271 requests it timed out on 269 of
them at a 10 s timeout.
