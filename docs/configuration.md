# Configuration

Ailuros is configured with `AILUROS_*` environment variables, read once at startup, and an optional YAML policy file.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AILUROS_CLASSIFIER_BACKEND` | required | `jev` or `openai` |
| `AILUROS_CLASSIFIER_MODEL` | required | e.g. `jev-latest`, `llama3.2`, `gpt-5-mini` |
| `AILUROS_CLASSIFIER_BASE_URL` | per backend | `https://api.typesafe.ai` / `https://api.openai.com/v1`; an `http` or `https` URL with a host and no query |
| `AILUROS_CLASSIFIER_API_KEY` / `_FILE` | empty | Bearer token, or a file containing it (an empty file is rejected at startup; a variable set to an empty value counts as unset) |
| `AILUROS_CLASSIFIER_TIMEOUT` | `1s` | Per-request classifier timeout |
| `AILUROS_FAILURE_MODE` | `open` | `open` or `closed` when classification fails |
| `AILUROS_BAD_OUTPUT` | `block` | When the model answers outside the label set: `block` (403, as an attack), `fail_closed` (503), or `failure_mode` (follow `AILUROS_FAILURE_MODE`) |
| `AILUROS_BLOCK_THRESHOLD` | `0.8` | Block when the attack probability `1 − P(benign)` reaches this; routes may override it |
| `AILUROS_INSPECTION_MODE` | `standard` | `lite`, `standard`, `deep` (only ext_proc sees bodies; ext_authz and forward-auth always use `lite`) |
| `AILUROS_BODY_MAX_BYTES` | `16384` | Body cap for `standard` mode: the most body bytes sent to the classifier |
| `AILUROS_DEEP_MAX_BYTES` | `16384` | `deep` mode cap: per request (HTTP) or per message (gRPC), and the most decompressed bytes inspected; at most `67108864` (64 MiB) |
| `AILUROS_DEEP_OVERSIZE` | `classify_prefix` | `deep` mode over the cap: `classify_prefix`, `block` (413 / gRPC 8), or `allow` |
| `AILUROS_DEEP_MAX_MESSAGES` | `100` | `deep` gRPC: classifier decisions per stream (headers included), 1–10000; past it the stream is blocked unless `AILUROS_DEEP_OVERSIZE=allow` |
| `AILUROS_POLICY_FILE` | empty | YAML policy; see `examples/policy.yaml` |
| `AILUROS_EXTPROC_ADDR` | `:9001` | Envoy ext_proc gRPC listener; empty disables it |
| `AILUROS_EXTAUTHZ_ADDR` | empty | Envoy ext_authz gRPC listener; empty disables it |
| `AILUROS_FORWARDAUTH_ADDR` | `:9002` | Forward-auth listener; empty disables it |
| `AILUROS_METRICS_ADDR` | `:9090` | `/metrics`, `/healthz`, `/readyz` |
| `AILUROS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `AILUROS_EXPOSE_VERDICT` | `false` | Debug only: send `X-Ailuros-Decision` (outcome, attack score, category, probability) to clients |
| `AILUROS_JA4_HEADER` | empty | Request header the proxy fills with the client's JA4 TLS fingerprint, which Ailuros then reads and removes; leave empty unless the proxy overwrites it on every request (see Envoy). Pseudo-headers and headers Ailuros reads by name (`content-type`, `transfer-encoding`, `content-length`, `host`, `connection`, `upgrade`, `origin`, `sec-websocket-key`, `sec-websocket-version`, `sec-websocket-protocol`, `content-encoding`, `grpc-encoding`, `referer`, `authorization`, `cookie`, `x-forwarded-for`, `traceparent`, `tracestate`, `baggage`) are rejected |

**Body limits and classifier speed.** A decision model reads input at a few
hundred tokens per second, so the body limits are also prompt-size limits:
the 16 KiB defaults finish in a few seconds on a local 3B model. Raising them
much further (Ailuros warns above 32 KiB) risks classifier timeouts, and a
timeout follows `AILUROS_FAILURE_MODE`, so under `open` an oversized request
would pass unclassified. Bodies over the limit are handled as oversize:
`standard` classifies the prefix; `deep` applies `AILUROS_DEEP_OVERSIZE`
(`block` refuses what it cannot fully inspect).

Binary bodies (gRPC messages, non-UTF-8 HTTP bodies) reach the classifier as
their readable text runs (like `strings`): protobuf keeps string fields as
plain UTF-8, so field values such as usernames and queries are visible
without a schema. Forwarded bytes are never altered.

The policy file's `limits:` block turns request signals (GraphQL shape,
smuggling flags, WebSocket handshakes, JA4) into blocks that skip the model;
every limit is off by default. See [Request signals and limits](signals.md).

The policy file hot-reloads on change or `SIGHUP`. Ailuros watches the policy
file's directory and reacts only to the policy file itself (or a Kubernetes
ConfigMap `..data` swap). An invalid file is rejected and the previous policy
stays active.

## Using local models

The `openai` backend works with OpenAI-compatible servers such as Ollama,
llama.cpp server, LM Studio, and vLLM. Its base URL includes `/v1` (for
example `http://localhost:11434/v1` for Ollama, `http://localhost:8080/v1` for
llama.cpp server, `http://localhost:1234/v1` for LM Studio). At startup Ailuros probes the server for JSON-schema output and
token logprobs. This backend sees only the probability `c` of the label the
model chose (the product of the probabilities of the tokens spelling it): a
`benign` answer gives an attack score of `1 − c`, an attack label gives `c`.
Without logprobs `c` is always 1.0, so the threshold behaves as plain
allow/block.

Checked on 2026-10-14 with Ailuros's own probe and the shipped sample:

| Server | Version | `json_schema` (`strict`) | Label set enforced | Logprobs |
|---|---|---|---|---|
| Ollama | 0.40.4 | yes | yes | yes |
| llama.cpp server | build 11610 | yes | yes | yes |
| LM Studio | 0.4.26 | yes | yes | yes (rejects `json_object`; Ailuros uses `json_schema`) |
| vLLM | not checked (needs an NVIDIA GPU) | | | |

"Label set enforced" means a request telling the model to answer a label
outside the list still got one from the list. A server that accepts
`json_schema` but does not enforce it is reported at startup, and its
answers outside the label set follow `AILUROS_BAD_OUTPUT`.
