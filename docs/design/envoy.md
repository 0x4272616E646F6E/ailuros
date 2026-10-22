# Envoy integration (ext_proc and ext_authz)

decision-waf serves two Envoy APIs: `ext_proc`, which supports all three inspection modes (`lite`, `standard`, `deep`), and `ext_authz`, which supports `lite` only. The Envoy filter config must match the mode the decision-waf process runs in. decision-waf adapts when it does not, and counts the mismatch rather than failing. `deep` holds request bodies inside decision-waf, classifies HTTP bodies whole and gRPC bodies message by message, and releases only what it has decided. This note explains why that is built the way it is. Setup steps are in [Envoy](../envoy.md). The decision engine is in [architecture.md](architecture.md), and the Kubernetes variant is in [kubernetes.md](kubernetes.md).

## Context

- Envoy opens one bidirectional gRPC stream per HTTP request for ext_proc. The filter's `processing_mode` decides what Envoy sends: headers only, one buffered body, or a streamed body.
- decision-waf must answer before Envoy gives up, or the filter's `failure_mode_allow` decides instead of the route's failure mode.
- The classifier is a small model that reads a few hundred tokens a second. Anything sent to it has to be small.
- A blocked request must not reach the upstream. In `deep` mode, request content cannot reach the upstream before decision-waf has looked at it.
- Request side only. The shipped configs skip response headers, body and trailers. Response-side inspection is out of scope.

## Decisions

### One decision-waf process serves one mode, matched to the Envoy config

`DECISION_WAF_INSPECTION_MODE` maps to an Envoy `request_body_mode`: `lite` to `NONE`, `standard` to `BUFFERED_PARTIAL`, `deep` to `FULL_DUPLEX_STREAMED` with `request_trailer_mode: SEND`. `deploy/envoy/{lite,standard,deep,ext_authz}.yaml` ship one config per mode.

On a mismatch decision-waf classifies on headers alone, warns once per process, and increments `decision_waf_mode_downgrades_total{frontend="extproc"}`. It never refuses to serve. Detection uses `ProcessingRequest.protocol_config.request_body_mode` when Envoy sends it. The fallback is a headers message that ends the stream while `content-length` promises a body. A stream that ends with no decision at all is also counted, but only when Envoy sent no `protocol_config` (`checkUndecided` in `internal/frontend/extproc/extproc.go`): with it, a mismatch is caught at the headers, and an undecided end is a client that went away, which Envoy closes the same way. The fallback matters because `end_of_stream` on the headers message reflects the real request, not Envoy's body mode, so the heuristic alone rarely fires.

Rejected: a per-request `mode_override` chosen by decision-waf. Letting the service pick what Envoy sends makes the deployed behavior depend on traffic. A fixed mode per process is easy to reason about, and the mismatch metric shows misconfiguration. ext_authz is always `lite`; a different configured mode is warned about at startup and counted on every request.

### `deep` holds bodies in decision-waf (FULL_DUPLEX_STREAMED)

In `FULL_DUPLEX_STREAMED`, Envoy forwards only the body chunks decision-waf streams back. decision-waf holds incoming chunks and releases them (in chunks of at most 64 KiB) after a decision. This gives true enforcement: a blocked body never reaches the upstream. Envoy 1.33 introduced the mode; decision-waf needs 1.34 or later for every mode, since mismatch detection relies on the `protocol_config` that 1.34 added.

Rejected: Envoy's newer `GRPC` body send mode, which would do gRPC framing in Envoy. decision-waf reassembles the framing itself (`internal/frontend/extproc/grpcframe.go`), so it works on more Envoy releases. It could be adopted later behind the same `deep` setting.

### Headers first

In `deep`, decision-waf classifies the request headers and answers the headers message before any body arrives. Envoy sends no body chunk until it has the headers response, so the answer cannot wait for the body. Once CONTINUE is sent, Envoy forwards the headers upstream, so a header-level attack has to be caught first. A block is an immediate response. The cost is one extra classifier call for any request with a body. The headers decision is logged under a stream-level ID, which is also the `x-decision-waf-request-id` header set on the upstream request.

### gRPC messages are decided one at a time

For `application/grpc` and `application/grpc+<codec>`, the framer reassembles messages (5-byte prefix, handling split messages and several per chunk). Each message is classified with the call's headers and its payload as the body. Message N+1 is not classified until N is decided. An allowed message's original bytes go back to Envoy. A denial is an immediate response with `grpc-status` 7 (block), 14 (fail_closed) or 8 (oversize). Each message decision has its own request ID in the logs. Empty messages are forwarded without a decision, because the headers were already classified. A stream that ends inside a message is classified on what arrived, marked truncated, rather than sent to the failure mode. Without this, a client could declare a length it never sends and slip an unclassified prefix through.

The compressed flag is trusted only when the call has a `grpc-encoding` other than `identity`; otherwise every message is plaintext.

### Message cap: blocks by default

A stream takes at most `DECISION_WAF_DEEP_MAX_MESSAGES` decisions (default 100, range 1 to 10000, headers included). The cap bounds classifier calls, and so model cost, per stream. Past it, nothing more of the stream would be inspected, so the stream is blocked (413, gRPC 8, `reason=message_limit`) under both `classify_prefix` and `block`. Only `DECISION_WAF_DEEP_OVERSIZE=allow` lets the rest through. The first version followed the oversize policy, which under the default meant 99 benign messages followed by anything unclassified. Long-lived streaming RPCs (chat, telemetry) need a higher cap.

### Compressed messages are decompressed, with a bound

`gzip` and `deflate` (zlib; that is gRPC's "deflate") payloads are inflated and the plaintext is classified; the original compressed bytes are forwarded on allow. Output stops at `DECISION_WAF_DEEP_MAX_BYTES` (`internal/frontend/extproc/decompress.go`), so a small message cannot expand into a bomb. A message that inflates past the cap is oversize and handled by the oversize policy. Other encodings (`snappy`, `zstd`) and corrupt data are uninspectable. They are blocked (413, gRPC 8, `reason=uninspectable`) unless the policy is `allow`, even under `classify_prefix`, because there is no readable prefix to classify. The first design classified only the headers for compressed messages, so declaring `grpc-encoding` was a way to skip payload inspection.

The same applies to HTTP bodies (`internal/frontend/extproc/encoding.go`). A `Content-Encoding` of `gzip`, `x-gzip` or `deflate` (zlib, or the raw deflate some clients send) is inflated within the same bound in `standard` and `deep`, and the original bytes are forwarded. `standard` also unframes a buffered gRPC body that declares a `grpc-encoding` and inflates its compressed messages. Any other coding, several codings stacked, corrupt data, and compressed gRPC-Web are uninspectable: blocked with 413 in `standard`, which has no oversize setting, and in `deep` unless `DECISION_WAF_DEEP_OVERSIZE=allow`. Under `allow` an undecodable HTTP body is classified as sent rather than passed unclassified: the first version passed it, so a plaintext attack only needed a false `Content-Encoding`, which many upstreams ignore on requests. gRPC-Web is refused rather than unframed because browser clients do not compress requests. Earlier, these bodies reached the model as compressed bytes, which it cannot read, so any compressed attack was allowed.

### grpc-web is held as HTTP; grpc-web-text is decoded at render time

grpc-web (`application/grpc-web*`) does not use the length-prefixed framing, so `deep` treats it as an ordinary HTTP body: held and classified whole. A deployment that wants per-message decisions can put Envoy's `grpc_web` filter before ext_proc. The text variant is base64. `Request.Render` (`internal/inspect/render.go`, `grpcweb.go`) decodes it in every mode that sends a body, quad by quad because messages may be several padded chunks back to back, and notes "decoded from grpc-web-text" in the prompt. Otherwise an attack would reach the model only as base64. Invalid base64 is rendered as such, with a note.

### Oversize policy: `DECISION_WAF_DEEP_OVERSIZE`

Applies to HTTP bodies over `DECISION_WAF_DEEP_MAX_BYTES`, gRPC messages whose declared length exceeds it, and uninspectable messages.

- `classify_prefix` (default): classify the first `DEEP_MAX` bytes (marked truncated); on allow, release what is held and pass the rest unheld. A gRPC message decision-waf cannot decompress is blocked instead.
- `block`: 413, or gRPC 8 `RESOURCE_EXHAUSTED`, logged `reason=oversize` or `uninspectable`. A 413 from decision-waf means "too large to inspect", not an attack verdict.
- `allow`: pass through unclassified, logged with the same reasons.

### Body limits sized to the model, not to memory

`DECISION_WAF_BODY_MAX_BYTES` (`standard`) and `DECISION_WAF_DEEP_MAX_BYTES` (`deep`; accepted up to 64 MiB) both default to 16 KiB. They were 64 KiB and 1 MiB, and doubled as prompt sizes. A live run showed a large body, or a decompression bomb inflating to the cap, making the classifier time out. Under the default `DECISION_WAF_FAILURE_MODE=open` the request then passed unclassified, so anyone could bypass inspection by sending a large body. At 16 KiB a body classifies inside the timeout. decision-waf warns at startup when the active mode's limit exceeds 32 KiB (`largeBodyLimit` in `internal/app/warnings.go`), because larger bodies rarely finish within `DECISION_WAF_CLASSIFIER_TIMEOUT`. Oversize inputs then fall under the oversize rules rather than silently timing out.

### Binary bodies are rendered as text runs

gRPC payloads are protobuf, and showing them as base64 left even decompressed attacks scoring only 0.55 to 0.61 on a small model. For gRPC bodies, or any body that is not valid UTF-8, the renderer shows the readable runs: printable UTF-8 runs of 4 or more characters, trimmed, joined with ` · `, like `strings(1)`. Protobuf stores string fields as raw UTF-8, so this surfaces field values with no schema. Line breaks and control bytes end a run, so request content cannot forge prompt lines. A body with no such runs renders as `[binary, N bytes, no readable text]`.

### Header mutations set both `value` and `raw_value`

`envoyreq.SetHeader` fills both fields with an overwrite action. ext_proc reads `raw_value` and ext_authz reads `value`, and either alone arrives empty through the other. Incoming header values are read from either field. Allowed requests get `x-decision-waf-request-id`, plus the debug header when `DECISION_WAF_EXPOSE_VERDICT=true`. In `deep` mode the headers of a request with a body go upstream before the body is classified, so such a request carries only the stream's `x-decision-waf-request-id`, never `x-decision-waf-decision`: body decisions stream bytes back with no header mutation.

### Timeouts

- Set `message_timeout` (ext_proc) and `timeout` (ext_authz) to `DECISION_WAF_CLASSIFIER_TIMEOUT` + 500 ms (1.5 s with the 1 s default; Envoy's own default of 200 ms is far too short). The margin lets decision-waf answer, applying its own failure mode, before Envoy gives up. `internal/config` exports the margin and the shipped configs' tests derive their values from it.
- ext_authz's `timeout` is a real gRPC deadline. decision-waf stops waiting for the classifier 50 ms before it (`envoyreq.WithDeadlineMargin`). A context already past that point gets the failure mode without calling the classifier, so an expired deadline never trips the circuit breaker.
- ext_proc's `message_timeout` is a timer inside Envoy that decision-waf cannot see. The classifier timeout is what keeps the answer inside it.
- In `deep`, `message_timeout` does not apply at all. The classifier timeout is the only bound on each decision. Held bodies are bounded by the HTTP connection manager's `request_timeout` (60 s) and `stream_idle_timeout` (30 s) in `deploy/envoy/deep.yaml`, so a slow client cannot hold up to `DEEP_MAX` bytes of memory forever. Raise them for long uploads or long-lived gRPC streams.

### Envoy failure_mode_allow versus the decision-waf failure mode

`failure_mode_allow` governs only an decision-waf that is unreachable or has reset the stream. The shipped configs set it to `false`, so Envoy fails closed (500 for ext_proc, 503 for ext_authz), while `DECISION_WAF_FAILURE_MODE` defaults to open; [Operations](../operations.md#when-decision-waf-itself-is-unreachable) gives the reasoning. Once decision-waf is reachable, the route's failure mode always wins, including after a panic in a handler.

A panic is recovered and answered. A denial the engine had already computed stands. Otherwise the failure mode applies. If applying it panics too, `fail_closed` gets a 503 (gRPC 14), and `fail_open` continues, releasing any held body, rather than resetting. A reset would hand the decision to Envoy's `failure_mode_allow: false` and quietly turn fail_open into fail_closed. Only if rendering that answer also panics does the stream reset. The rule is `frontend.AfterPanic`, shared with ext_authz and forward-auth. Protocol errors (a body before headers) go through the same failure mode. An Envoy reset (context cancelled) stops processing with no response.

### ext_authz is lite only

`envoy.service.auth.v3.Authorization/Check` (`internal/frontend/extauthz`) builds the request from `attributes.request.http`, the source address, and the SNI. Any body is ignored. Allow returns `OkHttpResponse` with the request-ID header. Deny returns `DeniedHttpResponse` with 400, 403, 413 or 503 (`frontend.DenialFor`), the generic JSON body, and `CheckResponse.status` `INVALID_ARGUMENT`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED` or `UNAVAILABLE`, which Envoy maps to gRPC 3, 7, 8 or 14 for gRPC clients. The shipped config uses port 9003, which is off by default (`DECISION_WAF_EXTAUTHZ_ADDR` empty).

### Client IP comes from Envoy's view of the connection

The shipped configs request the `source.address` attribute (and the SNI and TLS version attributes). `envoyreq.ClientIP` uses it when it parses as an IP, with the port stripped. Otherwise it uses the last `X-Forwarded-For` hop, the one the nearest proxy appended. Earlier hops are client-controlled. The edge Envoy must set `use_remote_address: true`, or the downstream address (and `source.address`) comes from a client-supplied `X-Forwarded-For`. Behind trusted L7 proxies, keep it true and set `xff_num_trusted_hops`. Behind an L4 balancer, enable PROXY protocol on the listener.

## How it works

- `internal/app/app.go` runs both gRPC servers. Each registers `grpc.health.v1` and sets `MaxRecvMsgSize` to the larger of a floor and `DEEP_MAX` plus headroom. Shutdown uses `GracefulStop`.
- `internal/frontend/extproc/extproc.go`: stream state machine. `onHeaders` builds the request, detects mismatches, and decides in `lite`. In `standard` it answers CONTINUE and waits for the one buffered body message. In `deep` it classifies headers first. Chunks after `end_of_stream` are ignored (an Envoy bug that re-sends the final chunk).
- `standard.go`: the one buffered body message, truncated to `BODY_MAX_BYTES` and decided.
- `deep.go`, `grpcframe.go`, `decompress.go`: held HTTP bodies, message reassembly and decisions, and bounded inflation. The framer returns bytes only in original order, so passing everything through reproduces the stream exactly.
- `encoding.go`: reading `Content-Encoding` and `grpc-encoding`, and turning a body into the plaintext the model reads.
- `decide.go`: decisions on a stream (classify, bypass, protocol failure) and releasing held body bytes.
- `request.go`: building `inspect.Request` from Envoy's headers and attributes, and adding request trailers.
- `respond.go`: Envoy responses (CONTINUE, streamed body chunks, immediate denials).
- `recover.go`: answering after a panic with `frontend.AfterPanic`'s decision.
- `internal/frontend/envoyreq`: pieces shared by both Envoy frontends: header values and `Headers`/`HeadersFromMap`, client IP, deadline margin, trace context, header mutations (`SetHeader`, `DecisionHeaders`, `DenyHeaders`), and `Decide`, which applies the failure mode without the classifier when the context has already expired.
- `internal/inspect`: `Request.Render` and the grpc-web-text decoder.
- `deploy/envoy/*.yaml` are complete bootstrap examples. `test/deployconfig/deploy_test.go` and the validate-envoy make target check them against the defaults.

## Limitations and trade-offs

- **A block in the middle of a gRPC stream is not delivered cleanly once the upstream has replied.** Earlier messages have already reached the upstream. If the upstream has also sent response headers (a streaming server that has replied), Envoy cannot turn the immediate response into `grpc-status` 7, 8 or 14. It resets the stream and the client sees `INTERNAL` (RST_STREAM). Enforcement holds, since the blocked message never reaches the upstream. Delivering the status would need response-trailer processing. Accepted.
- `deep` adds a classifier call for headers on every request that has a body.
- gRPC-Web is inspected as one held HTTP body, not per message, unless Envoy's `grpc_web` filter runs first.
- Compressed gRPC in `gzip`/`deflate` only; other encodings are blocked (or allowed with `DECISION_WAF_DEEP_OVERSIZE=allow`).
- Protobuf is never decoded to JSON; the model sees readable text runs only.
- Memory: up to `DEEP_MAX` bytes held per open stream. Bounded by Envoy's request and idle timeouts, not by decision-waf.
- Response-side inspection is not implemented.

## History

- 2026-10-12: a per-stream message cap was added, then changed to block by default because it followed the oversize policy and let a client bypass inspection after 99 messages. It is now `AILUROS_DEEP_MAX_MESSAGES`.
- 2026-10-13: compressed gRPC messages are decompressed (gzip, deflate) instead of classified by headers only, closing a bypass via `grpc-encoding`.
- 2026-10-13: `BODY_MAX_BYTES` (64 KiB) and `DEEP_MAX_BYTES` (1 MiB) lowered to 16 KiB after a large body timed out the classifier and passed under fail-open. Binary bodies are rendered as text runs instead of base64.
- 2026-10-13: a live gRPC run showed that a block after the upstream replied arrives as RST_STREAM/INTERNAL. It was documented as an accepted limitation.
- 2026-10-13: header mutations fill both `value` and `raw_value`, after a live Envoy run showed ext_proc reads only `raw_value` (and ext_authz only `value`).
- 2026-10-13: fail_open continues after a recovery panic instead of resetting the stream, which the shipped `failure_mode_allow: false` had turned into fail_closed.
- 2026-10-14: Deep-mode gRPC framing follows the content type alone, so a path that is not `/package.Service/Method` no longer turns per-message inspection off.
- 2026-10-14: HTTP bodies with a `Content-Encoding`, and compressed gRPC messages in `standard` mode, are classified decompressed; compressed gRPC-Web and unknown codings are uninspectable.
- 2026-10-14: Request trailers are classified (with an HTTP body, or as one more decision on a gRPC stream) instead of being forwarded uninspected.
- 2026-10-14: Under `AILUROS_DEEP_OVERSIZE=allow`, an HTTP body Ailuros cannot decompress is classified as sent instead of passed unclassified.
- 2026-10-14: The shipped configs set `internal_address_config` to one documentation address (192.0.2.255/32), so no peer is internal; Envoy's default trusted the `X-Forwarded-For` and `x-envoy-*` headers of RFC 1918 and loopback peers. An empty list does not work: Envoy falls back to the default, which the integration suite caught.
- 2026-10-14: Envoy 1.34 is the documented minimum: it is the first release that sends `protocol_config`, which mismatch detection relies on, and every release still supported upstream is newer. The undecided-stream fallback stays as best effort for older releases.
