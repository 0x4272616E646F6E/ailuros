# Ailuros architecture

Ailuros is an ingress decision service. A proxy you already run (Envoy, NGINX, Traefik) asks it about every request; Ailuros renders the request as text, asks a decision model (TypeSafe Jev or any OpenAI-compatible LLM) how likely it is to be an attack, and answers allow or block. It is one Go binary with several thin frontends over one shared decision core. This note explains why it is shaped that way. For setup see the [README](../../README.md); the full variable table is in [Configuration](../configuration.md).

## Context

The goal is middleware that other people deploy in front of their own services, with a few environment variables and an optional policy file. Constraints that shaped the design:

- Operators already have a proxy and do not want a second data plane to run, secure and upgrade.
- Detection quality comes from a model, so every request pays model latency and cost. This is accepted, not hidden.
- Swapping Jev for a local model must be configuration, not code.
- New traffic types should arrive as new frontends without touching the decision logic.
- The decision must be explainable (which attack category, what score) without telling attackers anything.

## Decisions

### A decision service behind existing proxies, not a proxy

Proxies already terminate TLS, route, retry and load-balance, and each has a hook for asking an external service about a request: Envoy `ext_proc` and `ext_authz`, NGINX `auth_request`, Traefik `ForwardAuth`. Ailuros implements those protocols and nothing else. Rejected: shipping an Ailuros data plane (a large surface with no detection benefit).

### Always inline, no bypass tier

Every request is classified by the model before the proxy forwards it. There is no cache, rule-based pre-filter or allow-list that skips the classifier. The consequences are deliberate: each request carries the classifier's latency (Jev advertises 70-500 ms) and cost, and the model's rate limits become the service's throughput limit. A bypass tier would be a second detection system that has to be kept correct and would be the first thing an attacker targets. Operators who want less cost route less traffic through the proxy filter.

### One binary, several frontends, a shared core

`cmd/ailuros` loads configuration and starts the enabled listeners (`internal/app`). Each frontend only translates its protocol into an `inspect.Request`, calls `decision.Engine`, and translates the outcome back. Per-protocol code lives in `internal/frontend/{extproc,extauthz,forwardauth}`; what they share lives in `internal/frontend` and `internal/frontend/envoyreq`. Separate binaries per proxy were rejected: they would duplicate configuration, policy reload and telemetry.

### Decision rule: attack score against a threshold

The score is `1 - P(benign)`, the probability that the request is an attack of any kind. A request is blocked when the score is at or above the threshold (`internal/decision/engine.go`, `verdictOutcome`).

The first design blocked only when the single most likely category was an attack with confidence at or above the threshold. A spot check with a local decision model showed why that fails: a model can be sure a request is an attack while splitting its probability across categories (a `UNION SELECT` had `P(benign) = 0.045` but its mass was divided between `credential_stuffing` and `sqli`). With a top-category rule, 8 of 14 attacks were blocked at 0.8; with the attack score, 11 of 14, and all 14 at 0.45 with no benign request blocked. The set was too small to tune a default on, so 0.8 stands until the evaluation harness produces data (see [evaluation.md](evaluation.md)).

For the same reason categories carry no thresholds. The category is a label for operators (logs, metrics, an optional debug header) and a vocabulary for the model, not an input to the decision. A `threshold` key on a category is an unknown key and rejected at load.

### Failure mode is a separate, explicit axis

When classification fails (timeout, upstream error, bad output, open breaker, panic), the outcome is `fail_open` or `fail_closed`, never a guessed verdict. The mode comes from `AILUROS_FAILURE_MODE` (default `open`), overridable per route. Failures are never retried inline: a retry would double latency on a request that is already waiting. A reply that is not a model answer at all (invalid JSON, no choices, missing or out-of-range probabilities) is a backend failure, `bad_response`. An answer that is not one of the labels (an unknown category, text that is not the JSON answer) is `bad_output`, and `AILUROS_BAD_OUTPUT` decides it instead of the failure mode: `block` by default, or `fail_closed`, or `failure_mode`. Request content cannot shape the reply envelope, but it can push a model off its answer format far more easily than it can make it answer benign, so under the failure mode `open` a prompt injection only had to break the format to be allowed. For the same reason `bad_output` never counts against the breaker: the model is up and answering.

### The proxy owns the "Ailuros is down" case

`AILUROS_FAILURE_MODE` covers a failing model, not a missing Ailuros. If Ailuros cannot be reached, only the proxy knows what to do (Envoy `failure_mode_allow`, NGINX `error_page`, Traefik's built-in fail-closed). The two settings are independent, and the shipped examples set them apart on purpose (model failures open, an unreachable Ailuros closed); [Operations](../operations.md#when-ailuros-itself-is-unreachable) gives the per-proxy detail. To keep the two from racing, proxies should wait longer than the classifier timeout: `config.ProxyTimeoutMargin` (500 ms) is the margin the shipped configs use, so Ailuros always answers, applying its own failure mode, before the proxy gives up. Tests for the configs derive their timeouts from the exported defaults in `internal/config`.

### Readiness ignores the breaker

`/readyz` turns ready once the startup probe call to the classifier succeeds and never flips back. An open circuit breaker does not fail readiness, because pulling pods out of service during an upstream outage would turn a model outage into a total outage; it is visible in metrics and the failure mode handles the traffic.

## How it works

Request flow, per request:

1. A frontend receives the request and builds an `inspect.Request` (`frontend.NewRequest` for the shared part): method, scheme, host, path, query, lower-cased headers, client IP, TLS/SNI, gRPC service and method, and optionally a body.
2. `decision.Engine.Decide` resolves the route (`policy.Resolve`), redacts a copy of the request (`internal/redact`), and calls the classifier.
3. The engine maps the verdict or error to an `Outcome` (`allow`, `block`, `fail_open`, `fail_closed`), notifies the observer (logs and metrics), and returns a `Decision`.
4. The frontend renders the decision in its protocol.

`Engine` also has `DecideNote` (partly inspected content), `Fail` (a request that could not be classified at all) and `Bypass` (an outcome fixed by configuration, such as `AILUROS_DEEP_OVERSIZE=block`). The policy lives behind an atomic pointer, so a reload never disturbs in-flight decisions.

### Request model and rendering

`internal/inspect.Request` is the only type classifiers see. `Render` turns it into a deterministic text block (fixed field order, one field per line, headers sorted by name, every line of a text body prefixed with `| ` so request content cannot pose as a field) so both backends receive identical input and verdicts are comparable. Line breaks in values are escaped so request content cannot forge extra fields, and `classifier.Prompt` wraps the block in `<request>` tags and escapes any such tag inside it. Bodies go in as text when they are valid UTF-8; gRPC and other binary bodies are sent as their readable text runs (printable runs of four or more characters, like `strings(1)`), which exposes protobuf string fields without a schema. gRPC-Web text bodies are base64-decoded first. Decoding protobuf properly is out of scope. Rendering is covered by golden files in `internal/inspect/testdata`.

Inspection mode (`lite`, `standard`, `deep`) controls how much body is captured. Only Envoy `ext_proc` can see bodies; the other frontends always inspect in `lite`, log a warning at startup, and count `ailuros_mode_downgrades_total` per request when the configured mode is higher. How the modes map to Envoy is in [envoy.md](envoy.md).

### Policy

`internal/policy` holds three things, loaded from the YAML file named by `AILUROS_POLICY_FILE` (see `examples/policy.yaml`):

- **Categories.** Names plus descriptions, which are passed to the model so operators tune detection without code changes. `benign` is implicit. A `categories` key replaces the built-in defaults (`sqli`, `xss`, `path_traversal`, `rce`, `scanner`, `credential_stuffing`); it does not extend them.
- **Routes.** First match wins. A route matches on `host`, `path_prefix`, `grpc_service`, all of which must match, and may set `threshold` and `failure_mode`. Precedence is route over environment variable. Hosts are matched case-insensitively without port (IPv6 literals with or without brackets), and paths are decoded and cleaned the way backends will see them, so `//admin` or `/%61dmin` cannot slip past an `/admin` route. Where backends read one path differently, every reading is resolved and the stricter settings apply (the lower threshold, and `closed` if either reading is closed). When the two come from different routes, the decision's `route` names both, threshold route first (`1+0`). `path_prefix` is matched both on whole segments and as a plain prefix: segments keep a lenient `/public/` route off `/public-admin`, and the plain prefix keeps a strict `/admin` route on `/admin;jsessionid=x` and `/admin.json`, which routers that strip path parameters or extensions serve as `/admin`. An encoded slash (`%2F`, `%5C`) is a separator to some backends and not others, so a path containing one is resolved both decoded (with `%5C` as `/`) and kept literal. Paths are also read case-folded, with each literal `\` as `/`, and with `;parameters` stripped from each segment before dot segments are resolved, for backends that ignore case, treat backslashes as slashes, or strip parameters as Tomcat and Spring do (so `/public/..;/admin` is `/admin`). Otherwise `/admin%2F..%2Fpublic/x` would get a `/public` route's settings while a gateway routing on the `/admin` prefix serves it as admin.
- **Redaction.** Header names and JSON field names whose values are replaced with `[REDACTED]` before anything leaves the process, including in query strings and form bodies (also as part of a nested name such as `user[password]` or `user.password`; pairs are split on `;` as well as `&`, keys are decoded leniently so one bad `%` escape does not hide a name, and a masked value runs to the next `&`, `;` included) and in bodies that are not valid JSON (for example truncated ones). The query in a `Referer` header is masked the same way, and gRPC messages using the JSON codec (`application/grpc+json`, and gRPC-Web text, decoded first) by pattern. The pattern also matches a key spelled with `\u` escapes. `multipart/form-data` parts are masked by field name, and other parts redacted by their own content type, scanning for the boundary so a truncated body is still covered. Protobuf bodies cannot be redacted by field name: the wire format carries field numbers, not names. A `redact` key replaces the defaults (`authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key`).

Validation is strict (unknown keys, a second YAML document, duplicate or `benign` categories, empty routes, thresholds outside (0, 1], a host with a scheme, path or wildcard, a `grpc_service` with a method, a redacted header that is not a header name) and reports every problem at once; a bad policy at startup is fatal. Reload happens on `SIGHUP` or a change in the policy file's directory (`internal/app/reload.go`; it watches the directory because editors and Kubernetes ConfigMaps replace the file, and debounces 200 ms). A reload that fails validation keeps the last good policy, logs an error, and counts `ailuros_policy_reloads_total{result="failure"}`. Environment variables need a restart.

### Classifier backends

Both backends implement `classifier.Classifier` and return a `Verdict` (`Benign`, most likely attack `Category`, `Confidence`, optional full `Probs`). `Verdict.Validate` rejects non-finite or out-of-range probabilities and a category of `benign`.

- **`jev`** (`internal/classifier/jev`): one Choice question on `/v1/systemone` with `benign` plus the configured categories as answers. Jev's per-answer probabilities give the full distribution, so `Benign` is exact. Jev's own `confidence` field measures spread and is ignored. The same endpoint shape is served by local decision-model runtimes such as LM Studio, so this backend also covers those.
- **`openai`** (`internal/classifier/openai`): any `/chat/completions` server (Ollama, vLLM, llama.cpp, LM Studio, OpenAI). Fixed system prompt listing the categories, `temperature: 0`, and a constrained JSON answer (`json_schema`, falling back to `json_object` with client-side validation). Confidence comes from token logprobs: the probability of the chosen label is the product of the probabilities of the tokens spelling it. The backend only sees that one label, so an attack label with probability `c` is treated as `Benign = 1 - c`. A startup probe detects `json_schema` and `logprobs` support and caches it. Without logprobs every label has probability 1.0, so the threshold degrades to plain allow/block and a warning is logged.

### The guard

`classifier.Guard` wraps the chosen backend and is the only way the engine reaches it (`backend.Engine` in `internal/backend`, used by both the server and `ailuros-eval`):

- **Timeout** from `AILUROS_CLASSIFIER_TIMEOUT` (default 1 s) on every call.
- **Circuit breaker** (`breaker.go`): opens when at least half of at least 20 calls finished in the last 10 s failed, goes half-open after a 10 s cooldown and admits exactly one probe; success closes it, failure reopens it. While open, calls fail immediately with `circuit_open`. Every admitted call carries a generation ticket; each state change starts a new generation, and an outcome reported on an older ticket is ignored. Without that, a slow call admitted while closed that finishes after the breaker opened would close it early or disturb the half-open probe. Caller cancellation (`canceled`) releases a probe without counting against backend health. A failure rate over a minimum volume, not a run of consecutive failures, because a client controls some failures: requests with large bodies time out. With a run of five as the trigger, a handful of them opened the breaker and failed every client's requests, open under the default failure mode, for 10 s at a time. Now an attacker must supply most of all classified traffic, which proxy rate limits are for. Timeouts still count, since a hung model is what the breaker is for, and `bad_output` does not count, since the model is answering.
- **Panic recovery**: a panic in a backend becomes a `panic` error and counts as a failure. The engine has a second recover, and `frontend.Decide` a third for the whole handler.

Error reasons used in logs and metrics: `timeout`, `upstream_5xx`, `upstream_4xx`, `rate_limited` (429), `upstream_other` (a non-200 status that is not an error, such as a redirect), `connection`, `circuit_open`, `bad_response`, `bad_output`, `internal` (the request to the model could not be built), `panic`, `canceled`, `protocol_error`. All but `bad_output` follow the failure mode.

### Failure modes in practice

For a decision, the effective mode is the matching route's `failure_mode`, else `AILUROS_FAILURE_MODE`. `fail_open` passes the request through; `fail_closed` denies with 503 (gRPC `UNAVAILABLE`). Typical use: global `open` so a model outage does not take the site down, with `closed` on `/admin` or a payments gRPC service. Content that was not fully inspected (over `AILUROS_DEEP_MAX_BYTES`, compressed gRPC) is a separate case with its own setting, `AILUROS_DEEP_OVERSIZE`; see [envoy.md](envoy.md).

### Frontends

All four listeners are optional and started by `internal/app`. Defaults: `ext_proc` on `:9001`, forward-auth on `:9002`, `ext_authz` off (conventionally `:9003`), admin (`/metrics`, `/healthz`, `/readyz`) on `:9090`. Setting an address to empty disables that listener, except the admin address, which must be set.

- **ext_proc** (`extproc`): a bidirectional stream per request; the only frontend with body modes. Detail in [envoy.md](envoy.md).
- **ext_authz** (`extauthz`): one `Check` per request, metadata only.
- **forward-auth** (`forwardauth`): HTTP; the proxy sends the original method and URI in headers (`X-Forwarded-*` for Traefik, `X-Original-*` for NGINX). A request carrying both header sets, or neither, is rejected with a 500 rather than classified, because a client could otherwise choose what Ailuros sees.

`frontend.Decide` is the shared safety net. It builds the request and decides it inside a recover. If a handler panics (including in an observer after a block), a denial already taken stands; otherwise the route's failure mode is applied through the engine, and if that panics too, without it. A panic can therefore never turn into an unchecked allow for a route that is fail-closed.

Denials come from one place (`frontend.DenialFor`): block is 403 / `PERMISSION_DENIED`, fail-closed is 503 / `UNAVAILABLE`, uninspectable-or-oversize is 413 / `RESOURCE_EXHAUSTED`, malformed is 400 / `INVALID_ARGUMENT`. Forward-auth answers every block with 403, since NGINX `auth_request` passes no other denial status through, and a misconfigured proxy (missing or conflicting original-request headers) with 500, which is not a decision. A request with several `content-type` values, or a method that is not an HTTP token, is malformed. With several content types, gRPC servers accept a request when any value is gRPC, so reading only one would let Ailuros inspect it as HTTP while the upstream serves it as gRPC. Every content-type check goes through `inspect.Request.MediaType`, so the frontends, deep-mode framing and redaction cannot disagree. Bodies are generic JSON with the request ID and never name the category. Allowed requests gain `X-Ailuros-Request-Id`. `AILUROS_EXPOSE_VERDICT=true` adds `X-Ailuros-Decision` (outcome, score, category, confidence) for testing only; it logs a startup warning.

### Telemetry

`internal/telemetry`; one `Recorder` is the engine's observer.

- **Logs.** JSON via `slog` on stdout, one `decision` line per request: `request_id`, `frontend`, `mode`, `route`, `method`, `host`, `path`, `outcome`, `attack_score`, `category`, `confidence`, `backend`, `classifier_latency_ms`, `reason`, `client_ip`, `grpc_method`, and `stream_id` (in deep mode, the request ID the upstream sees). Every field is present on every line, empty or `null` when it does not apply. Failures log at warn. Query strings and redacted values are not logged. Only at `debug` level is a redacted body prefix (1 KiB) logged, with a startup warning.
- **Metrics.** Prometheus on the admin listener: `ailuros_decisions_total{outcome,category,route,frontend}`, `ailuros_classifier_latency_seconds{backend}`, `ailuros_classifier_errors_total{backend,reason}`, `ailuros_circuit_breaker_state{backend}` (0 closed, 1 half-open, 2 open), `ailuros_mode_downgrades_total{frontend}`, `ailuros_policy_reloads_total{result}`. The `route` label is the route's index in the policy file or `default`, which bounds cardinality. The `category` label is the attack category for a block, `benign` for an allow, and `none` otherwise.
- **Tracing.** OpenTelemetry, enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` (or the traces-specific variant) is set; standard `OTEL_*` variables configure it. The OTLP/HTTP and OTLP/gRPC trace exporters are used directly rather than `autoexport`, which also pulled in log and metric exporters, a Prometheus bridge and stdout exporters that Ailuros never uses. One `ailuros.decide` span per decision, failures and bypasses included (a failure sets the span's status to error and records the classifier error), with an `ailuros.classify` child when the classifier is called; trace context is extracted from incoming headers.

### Configuration

Runtime settings are `AILUROS_*` environment variables, parsed once in `internal/config.Load`, which reports every problem at once and refuses to start on any. Structured policy lives in the optional YAML file above. Values that the shipped proxy configs depend on (classifier timeout, listener ports, proxy timeout margin) are exported constants in `internal/config`, and the config tests derive from them, so changing a default fails a test until the configs follow. Secrets can come from `AILUROS_CLASSIFIER_API_KEY` or `AILUROS_CLASSIFIER_API_KEY_FILE` (not both; an empty file is rejected). The variable table is in [Configuration](../configuration.md), not here.

## Limitations and trade-offs

- Every request pays model latency and cost, and Jev's rate limits cap throughput. There is no caching.
- The `openai` backend sees only the chosen label's probability, so attack probability split across several attack labels is under-counted and that backend is more likely to under-block than `jev`. Recovering the distribution (per-label scoring or `top_logprobs`) is future work.
- The default threshold of 0.8 is not tuned; it should be chosen from an evaluation sweep on your own traffic.
- gRPC bodies are classified as readable text runs, not decoded protobuf.
- Prompt injection against the model is mitigated (untrusted-data instructions, fenced and escaped request block, constrained output) but not eliminated.
- No verdict caching, rule pre-filter, per-route custom block responses, multi-tenancy, admin UI, or protocols beyond HTTP/1.1, HTTP/2 and gRPC.
- In `deep` mode a stream message is classified before it is forwarded, so earlier messages of a later-blocked stream have already been delivered.

## History

- 2026-10-10: Decision rule changed from top-category confidence to attack score `1 - P(benign)`; category thresholds removed.
- 2026-10-13: Default `AILUROS_BODY_MAX_BYTES` lowered from 65536 to 16384; model input cost is linear in tokens, so large prompts risk timeouts.
- 2026-10-13: gRPC and other binary bodies switched from base64 to readable text runs, because the model could not read base64.
- 2026-10-13: ingress-nginx support dropped (retired upstream); Kubernetes is Envoy Gateway via the Gateway API, see [kubernetes.md](kubernetes.md).
- 2026-10-14: Backend and engine construction moved to `internal/backend`, shared by the server and `ailuros-eval`.
- 2026-10-14: Requests with several `content-type` values are refused as malformed (400), and every content-type check shares one parser.
- 2026-10-14: An answer outside the label set (`bad_output`) is blocked by default (`AILUROS_BAD_OUTPUT`) and no longer trips the breaker; a broken reply is now `bad_response` and still follows the failure mode.
- 2026-10-14: `path_prefix` matches whole segments, and a path with an encoded slash is resolved both ways with the stricter result; both closed ways for a request to fall onto a more lenient route.
- 2026-10-14: The breaker opens on a failure rate (half of at least 20 calls in 10 s) instead of 5 consecutive failures, so a few slow requests from one client cannot open it for everyone.
- 2026-10-14: Redaction matches nested form and query names (`user[password]`, `password[]`, `user.password`).
- 2026-10-14: `path_prefix` is matched both on segments and as a plain prefix, stricter wins; segment matching alone had let strict routes miss `/admin;x` and `/admin.json`.
- 2026-10-14: Tracing uses the OTLP trace exporters directly (HTTP by default, gRPC on request) instead of `contrib/exporters/autoexport`, dropping about 70 packages from the build.
- 2026-10-14: Route resolution adds case-folded and backslash-as-slash readings; the block test tolerates floating-point error at the threshold; the API key is a `config.Secret` that never prints; unmatched OpenAI logprobs are logged once.
- 2026-10-14: Redaction covers `\u`-escaped keys in bodies that are not valid JSON, `multipart/form-data` parts, and gRPC-Web text with the JSON codec.
- 2026-10-14: Text body lines are prefixed with `| ` in the prompt, so a body cannot pose as a request field or header; the instructions say so. On a 12-request body sample, d1-3b scored the same except the field-imitation attack (0.81 → 0.91); h2o-lightning-4b scored that one lower (0.94 → 0.67), in line with its other attacks.
- 2026-10-14: Policy validation rejects a second YAML document, hosts with a scheme, path or wildcard, `grpc_service` values with a method, and redacted header names that are not tokens.
- 2026-10-14: The `openai` backend was checked against Ollama 0.40.4, llama.cpp server build 11610 and LM Studio 0.4.26: all accept `json_schema` with `strict`, enforce the label set and return logprobs. vLLM is unchecked.
- 2026-10-14: Redaction masks an object or array value only to its closing bracket (to the end only when the body is cut off), and masks valid JSON in place instead of re-encoding it, which collapsed duplicate keys; both had let a request hide or change what the model saw.
- 2026-10-14: Route resolution adds a reading with `;parameters` stripped from each segment, so `/public/..;/admin` and `/;/admin` get `/admin`'s settings.
- 2026-10-14: A method that is not an HTTP token is malformed (blocked) in every frontend; forward-auth had answered it with a 500, which the NGINX fail-open variant let through uninspected, and capped method length, which NGINX does not.
