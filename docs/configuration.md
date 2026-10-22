# Configuration

decision-waf is configured with `DECISION_WAF_*` environment variables, read once at startup, and an optional YAML policy file.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DECISION_WAF_CLASSIFIER_BACKEND` | required | `jev` or `openai` |
| `DECISION_WAF_CLASSIFIER_MODEL` | required | e.g. `jev-latest`, `llama3.2`, `gpt-5-mini` |
| `DECISION_WAF_CLASSIFIER_BASE_URL` | per backend | `https://api.typesafe.ai` / `https://api.openai.com/v1`; an `http` or `https` URL with a host and no query |
| `DECISION_WAF_CLASSIFIER_API_KEY` / `_FILE` | empty | Bearer token, or a file containing it (an empty file is rejected at startup; a variable set to an empty value counts as unset) |
| `DECISION_WAF_CLASSIFIER_TIMEOUT` | `1s` | Per-request classifier timeout |
| `DECISION_WAF_FAILURE_MODE` | `open` | `open` or `closed` when classification fails |
| `DECISION_WAF_BAD_OUTPUT` | `block` | When the model answers outside the label set: `block` (403, as an attack), `fail_closed` (503), or `failure_mode` (follow `DECISION_WAF_FAILURE_MODE`) |
| `DECISION_WAF_BLOCK_THRESHOLD` | `0.8` | Block when the attack probability `1 − P(benign)` reaches this; routes may override it |
| `DECISION_WAF_INSPECTION_MODE` | `standard` | `lite`, `standard`, `deep` (only ext_proc sees bodies; ext_authz and forward-auth always use `lite`) |
| `DECISION_WAF_BODY_MAX_BYTES` | `16384` | Body cap for `standard` mode: the most body bytes sent to the classifier |
| `DECISION_WAF_DEEP_MAX_BYTES` | `16384` | `deep` mode cap: per request (HTTP) or per message (gRPC), and the most decompressed bytes inspected; at most `67108864` (64 MiB) |
| `DECISION_WAF_DEEP_OVERSIZE` | `classify_prefix` | `deep` mode over the cap: `classify_prefix`, `block` (413 / gRPC 8), or `allow` |
| `DECISION_WAF_DEEP_MAX_MESSAGES` | `100` | `deep` gRPC: classifier decisions per stream (headers included), 1–10000; past it the stream is blocked unless `DECISION_WAF_DEEP_OVERSIZE=allow` |
| `DECISION_WAF_POLICY_FILE` | empty | YAML policy; see `examples/policy.yaml` |
| `DECISION_WAF_EXTPROC_ADDR` | `:9001` | Envoy ext_proc gRPC listener; empty disables it |
| `DECISION_WAF_EXTAUTHZ_ADDR` | empty | Envoy ext_authz gRPC listener; empty disables it |
| `DECISION_WAF_FORWARDAUTH_ADDR` | `:9002` | Forward-auth listener; empty disables it |
| `DECISION_WAF_METRICS_ADDR` | `:9090` | `/metrics`, `/healthz`, `/readyz` |
| `DECISION_WAF_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `DECISION_WAF_EXPOSE_VERDICT` | `false` | Debug only: send `X-Decision-Waf-Decision` (outcome, attack score, category, probability) to clients |
| `DECISION_WAF_JA4_HEADER` | empty | Request header the proxy fills with the client's JA4 TLS fingerprint, which decision-waf then reads and removes; leave empty unless the proxy overwrites it on every request (see Envoy). Pseudo-headers and headers decision-waf reads by name (`content-type`, `transfer-encoding`, `content-length`, `host`, `connection`, `upgrade`, `origin`, `sec-websocket-key`, `sec-websocket-version`, `sec-websocket-protocol`, `content-encoding`, `grpc-encoding`, `referer`, `authorization`, `cookie`, `x-forwarded-for`, `traceparent`, `tracestate`, `baggage`) are rejected |

**Body limits and classifier speed.** A decision model reads input at a few
hundred tokens per second, so the body limits are also prompt-size limits:
the 16 KiB defaults finish in a few seconds on a local 3B model. Raising them
much further (decision-waf warns above 32 KiB) risks classifier timeouts, and a
timeout follows `DECISION_WAF_FAILURE_MODE`, so under `open` an oversized request
would pass unclassified. Bodies over the limit are handled as oversize:
`standard` classifies the prefix; `deep` applies `DECISION_WAF_DEEP_OVERSIZE`
(`block` refuses what it cannot fully inspect).

Binary bodies (gRPC messages, non-UTF-8 HTTP bodies) reach the classifier as
their readable text runs (like `strings`): protobuf keeps string fields as
plain UTF-8, so field values such as usernames and queries are visible
without a schema. Forwarded bytes are never altered.

The policy file's `limits:` block turns request signals (GraphQL shape,
smuggling flags, WebSocket handshakes, JA4) into blocks that skip the model;
every limit is off by default. See [Request signals and limits](signals.md).

The policy file hot-reloads on change or `SIGHUP`. decision-waf watches the policy
file's directory and reacts only to the policy file itself (or a Kubernetes
ConfigMap `..data` swap). An invalid file is rejected and the previous policy
stays active.

## Using local models

The `openai` backend works with OpenAI-compatible servers such as Ollama,
llama.cpp server, LM Studio, and vLLM. Its base URL includes `/v1` (for
example `http://localhost:11434/v1` for Ollama, `http://localhost:8080/v1` for
llama.cpp server, `http://localhost:1234/v1` for LM Studio). At startup decision-waf probes the server for JSON-schema output and
token logprobs. This backend sees only the probability `c` of the label the
model chose (the product of the probabilities of the tokens spelling it): a
`benign` answer gives an attack score of `1 − c`, an attack label gives `c`.
Without logprobs `c` is always 1.0, so the threshold behaves as plain
allow/block.

Checked on 2026-10-14 with decision-waf's own probe and the shipped sample:

| Server | Version | `json_schema` (`strict`) | Label set enforced | Logprobs |
|---|---|---|---|---|
| Ollama | 0.40.4 | yes | yes | yes |
| llama.cpp server | build 11610 | yes | yes | yes |
| LM Studio | 0.4.26 | yes | yes | yes (rejects `json_object`; decision-waf uses `json_schema`) |
| vLLM | not checked (needs an NVIDIA GPU) | | | |

"Label set enforced" means a request telling the model to answer a label
outside the list still got one from the list. A server that accepts
`json_schema` but does not enforce it is reported at startup, and its
answers outside the label set follow `DECISION_WAF_BAD_OUTPUT`.

**Decision models.** Models built for llama.cpp server's decision API
(`POST /v1/systemone`), such as LiquidAI's `d1-3B` and H2O.ai's
`h2o-lightning-4b`, use the `jev` backend with the server's base URL without
`/v1` (for example `http://localhost:8080`); the API key is optional. They
score every category in one pass and generate no tokens: on an RTX 4000 SFF
Ada a check takes about 0.1–0.2 s. Served through the `openai` backend they
reason before answering, run into the timeout, and misclassify ordinary
requests. `h2o-lightning-4b` needs llama.cpp server build 11773 or later.
[Evaluating models](evaluation.md#the-self-hosted-dataset) compares the two.
