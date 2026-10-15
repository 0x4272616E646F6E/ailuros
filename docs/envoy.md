# Envoy
Ailuros serves Envoy's `ext_proc` API on `AILUROS_EXTPROC_ADDR` (`:9001`)
and, when `AILUROS_EXTAUTHZ_ADDR` is set, the `ext_authz` API. Both gRPC
listeners serve `grpc.health.v1`, which reports `SERVING` once the classifier
is ready. Ailuros needs Envoy 1.34 or later (tested with 1.39.4); every
Envoy release still supported upstream qualifies. The Envoy filter config must
match `AILUROS_INSPECTION_MODE`:

| `AILUROS_INSPECTION_MODE` | Example config | Envoy filter setting |
|---|---|---|
| `lite` | `deploy/envoy/lite.yaml` or `deploy/envoy/ext_authz.yaml` | ext_proc `request_body_mode: NONE`, or ext_authz |
| `standard` | `deploy/envoy/standard.yaml` | ext_proc `request_body_mode: BUFFERED_PARTIAL` |
| `deep` | `deploy/envoy/deep.yaml` | ext_proc `request_body_mode: FULL_DUPLEX_STREAMED`, `request_trailer_mode: SEND` |

If Envoy does not send the body the mode needs, Ailuros classifies on headers,
logs a warning once, and counts `ailuros_mode_downgrades_total{frontend="extproc"}`.
Envoy 1.34 and later state their body mode in each stream's
`protocol_config`, so the mismatch is detected at the headers. On older,
unsupported releases Ailuros falls back to counting streams that end without
a decision, which also counts clients that go away before sending their
body.
ext_authz never sees bodies, so any mode other than `lite` is counted as a
downgrade on every request.

**Timeouts.** Set the ext_proc `message_timeout` (Envoy's default is 200 ms)
or the ext_authz `timeout` to `AILUROS_CLASSIFIER_TIMEOUT` + 500 ms; the
examples use 1.5 s. If Envoy's own timeout fires first, Envoy answers 504
for ext_proc, and `status_on_error` for ext_authz (503 in the shipped config;
Envoy's default is 403, which looks the same as a block).

- ext_authz: the `timeout` is a real gRPC deadline. Ailuros stops waiting for
  the classifier 50 ms before it, so it answers with its own failure mode
  first.
- ext_proc: `message_timeout` is a timer inside Envoy, not a deadline on the
  stream, so Ailuros cannot see it; `AILUROS_CLASSIFIER_TIMEOUT` is what keeps
  its answer inside it. In `deep` mode (FULL_DUPLEX_STREAMED) `message_timeout`
  does not apply at all, and `AILUROS_CLASSIFIER_TIMEOUT` is the only bound
  on each classification.

**When Ailuros is unreachable**, Envoy's `failure_mode_allow` decides, not
`AILUROS_FAILURE_MODE` (see
[Operations](operations.md#when-ailuros-itself-is-unreachable)). The shipped configs set `failure_mode_allow: false`: if the ext_proc
stream cannot be established or is reset, Envoy fails closed (500 for
ext_proc, 503 for ext_authz), even though `AILUROS_FAILURE_MODE` defaults
to open; Operations explains why. Set it to `true` for fail-open behavior. Once
Ailuros is reachable, the route's failure mode always wins: even when an
internal error strikes while applying it, an `AILUROS_FAILURE_MODE=open` route
lets the request through (releasing any held body) instead of resetting the
stream. Only if that last step fails too does Ailuros reset the stream and
leave the request to `failure_mode_allow`.

**Responses.** Blocks are 403 for HTTP clients and `grpc-status: 7`
(PERMISSION_DENIED) for gRPC clients; `fail_closed` is 503 /
`grpc-status: 14` (UNAVAILABLE). A request with more than one
`content-type` value (Envoy joins repeated headers with a comma), or a method
that is not an HTTP token, is refused as malformed (400, `grpc-status: 3` INVALID_ARGUMENT) without being
classified, because the upstream may read a different value than Ailuros
does. Allowed requests reach the upstream with
`X-Ailuros-Request-Id`.

**`deep` mode.** Ailuros classifies the request headers first, before Envoy
forwards them (a block is answered right away), then the body or messages: a
request with a body costs one extra classifier call. HTTP bodies are held and
classified whole, then streamed to the upstream unchanged; the headers and
body decisions are logged under the stream's request ID. Each gRPC message is
classified before it is forwarded; a blocked message ends the call, but
earlier messages have already reached the upstream. Once the upstream has
started its response (for example, a streaming server that has replied),
Envoy can no longer send any deny status (`grpc-status: 7`, `8`, or `14`);
it resets the stream, and gRPC clients see `INTERNAL` ("stream terminated by
RST_STREAM"). The blocked message still never reaches the upstream. Each
message decision is logged with its own request ID; the upstream sees the
stream's ID. Past
`AILUROS_DEEP_MAX_BYTES`, or for a body or gRPC message Ailuros cannot
decompress, `AILUROS_DEEP_OVERSIZE` decides (see the gRPC notes below):

- `classify_prefix` (default): classify the first `AILUROS_DEEP_MAX_BYTES`
  and let the rest through unheld if allowed. A body or gRPC message Ailuros
  cannot decompress has no readable prefix, so it is blocked (413).
- `block`: reject with **413** (`grpc-status: 8`, RESOURCE_EXHAUSTED). A 413
  from Ailuros means "too large to inspect", not an attack verdict; the log
  line says `reason=oversize` (or `uninspectable`, or `message_limit`).
- `allow`: let an oversize body or message through unclassified (logged
  `reason=oversize`), and the rest of a stream past its message cap (logged
  `reason=message_limit`). An HTTP body Ailuros cannot decompress is
  classified as it was sent (logged `reason=uninspectable`), so a false
  `Content-Encoding` cannot carry a plaintext attack through; a gRPC message
  it cannot decompress is let through unclassified.

**Request trailers.** `deep.yaml` sends request trailers to Ailuros
(`request_trailer_mode: SEND`), and they are classified with the body: an
HTTP body's decision includes them, and a gRPC stream that sends non-empty
trailers (gRPC clients normally send none) gets one more decision on its
headers and trailers. After an oversize decision lets the rest of a body
through, its trailers pass with it. `standard.yaml` does not send trailers to
Ailuros, so in `standard` mode they reach the upstream unclassified.

**Compressed bodies.** A body with `Content-Encoding: gzip` (or `x-gzip`,
or `deflate`) is decompressed and the plaintext classified, in `standard`
and `deep` mode; the upstream still receives the original bytes.
Decompression stops at the mode's byte limit, and a body that inflates past
it is handled as oversize. Other codings (`br`, `zstd`, …), several codings
applied in turn, and corrupt data cannot be inspected: they are refused with
413 in `standard` mode (which has no setting to allow them), and in `deep`
mode unless `AILUROS_DEEP_OVERSIZE=allow`, which classifies them as sent. An
empty body is never decoded.

While a body or gRPC message is incomplete, Ailuros holds up to
`AILUROS_DEEP_MAX_BYTES` of it per stream, so a slow client ties up that much
memory in Ailuros for as long as its stream stays open. `deploy/envoy/deep.yaml`
bounds this with the HTTP connection manager's `request_timeout` (60 s) and
`stream_idle_timeout` (30 s); tune them to your longest legitimate uploads
and gRPC streams.

gRPC notes for `deep` mode:

- gRPC framing applies only to `application/grpc` and
  `application/grpc+<subtype>`. gRPC-Web (`application/grpc-web*`) is treated
  as an ordinary HTTP body: held and classified whole. A gRPC-Web text body
  (`application/grpc-web-text`) is base64, so Ailuros decodes it before
  classifying (in every mode that sends a body), and the prompt says so. If you
  serve gRPC-Web, putting Envoy's `grpc_web` filter before `ext_proc` in the
  filter chain still gives Ailuros per-message gRPC in `deep` mode.
- A gRPC message counts as compressed only when the request carries a
  `grpc-encoding` header other than `identity`; otherwise its payload is
  classified as plaintext whatever its compressed flag says.
- Compressed messages in `gzip` or `deflate` are decompressed and the
  plaintext is classified; the original compressed bytes are what is
  forwarded. Decompression stops at `AILUROS_DEEP_MAX_BYTES` (a small
  message can inflate enormously), and a message that inflates past it is
  handled as oversize: its decompressed prefix is classified under
  `classify_prefix`.
- In `standard` mode a buffered gRPC body with a `grpc-encoding` is unframed
  and its compressed messages are decompressed the same way; without one, the
  framed bytes are classified as they are.
- A gRPC-Web request with a `grpc-encoding` other than `identity` cannot be
  inspected (browser gRPC-Web clients do not compress requests): it is
  refused with 413 / `grpc-status: 8`, as below.
- Other encodings (`snappy`, `zstd`, …) and corrupt compressed data cannot
  be inspected: the call is blocked with 413 / `grpc-status: 8` (logged
  `reason=uninspectable`) unless `AILUROS_DEEP_OVERSIZE=allow`.
- Zero-length gRPC messages are forwarded without a classifier call (the
  headers were already classified).
- A stream takes at most `AILUROS_DEEP_MAX_MESSAGES` (default 100)
  classifier decisions, the headers decision included. A message after that
  ends the call with 413 / `grpc-status: 8` (logged `reason=message_limit`)
  under both `classify_prefix` and `block`, because nothing more of the stream
  would be inspected. Only `AILUROS_DEEP_OVERSIZE=allow` lets the rest of the
  stream through unclassified. Raise the cap for legitimate long-lived streams
  (chat, telemetry, streaming RPCs); it also bounds classifier calls, and so
  model cost, per stream.
- A stream that ends in the middle of a gRPC message is classified on the
  bytes received (marked truncated), not failed open.

## Request signals

Ailuros adds a `signals:` block to the prompt and a `signals` field to the
log (see [Request signals and limits](signals.md)). Behind Envoy it uses:

- **`request.protocol`.** Every shipped ext_proc config lists it in
  `request_attributes` next to `source.address`; ext_authz always receives
  it. It gives the `protocol` signal and lets `te_on_h2` fire. A config
  without it still works, with no protocol.
- **WebSocket upgrades.** The shipped configs set `upgrade_configs` with
  `upgrade_type: websocket` on the HTTP connection manager. Without it Envoy
  answers a handshake with 403 and Ailuros never sees it. In `standard` and
  `deep` ext_proc decides a real handshake (GET, no body, a
  `Sec-WebSocket-Key`) on its headers, because no body follows an upgrade;
  other requests carrying Upgrade headers take the normal body path.
  Messages after the upgrade are never inspected.

### JA4 TLS fingerprints

Optional, off by default, and only for TLS terminated at Envoy (TLS
passthrough runs no HTTP filter). Envoy computes the fingerprint but cannot
pass it to ext_proc as an attribute, so each shipped config has a commented
block: the `tls_inspector` listener filter with `enable_ja4_fingerprinting`,
and a `header_mutation` HTTP filter, ahead of the Ailuros filter, that
overwrites `x-ailuros-ja4` with `%TLS_JA4_FINGERPRINT%`. Uncomment both and
set `AILUROS_JA4_HEADER=x-ailuros-ja4` on Ailuros. Ailuros reads that header
only when `AILUROS_JA4_HEADER` names it, because a client could send it
itself; the overwrite is what makes the value trustworthy, so do not set the
variable without it. Ailuros removes the header only from its own copy of the
request: Envoy still forwards `x-ailuros-ja4` to the upstream unless you
remove it, for example with `request_headers_to_remove` on the route.
Verified with Envoy 1.39.4. For Envoy Gateway see
`deploy/kubernetes/examples/ja4-client-traffic-policy.yaml` and
[Kubernetes](kubernetes.md).

## Client IP

Behind Envoy, the client address is Envoy's `source.address` attribute
(requested by the example configs), else the last `X-Forwarded-For` hop.
The edge Envoy must set `use_remote_address: true`, as the example configs
do: without it, Envoy takes the downstream address, and so `source.address`,
from the client's own `X-Forwarded-For`, and any client can choose the IP
Ailuros logs and classifies. With it, `source.address` is the TCP peer of the
Envoy listener: behind another L4 load balancer, enable PROXY protocol on the
Envoy listener, or the address Ailuros sees is the balancer's; behind
trusted L7 proxies, keep `use_remote_address: true` and also set
`xff_num_trusted_hops` to their number. On Kubernetes, see
[Client IP](kubernetes.md) in the Envoy Gateway guide.
