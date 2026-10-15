# Operations

## When Ailuros itself is unreachable

`AILUROS_FAILURE_MODE` only governs model failures (see
[How it decides](../README.md#how-it-decides)). If Ailuros
is down or unreachable, the proxy decides what happens:

- Envoy: `failure_mode_allow` on the `ext_proc` / `ext_authz` filter. The
  examples set it to `false` (fail closed); `true` lets requests through
  unclassified while Ailuros is unreachable. See [Envoy](envoy.md).
- NGINX and Traefik: the NGINX example fails closed (503) and has a
  commented fail-open variant; Traefik always fails closed. See
  [NGINX and Traefik](nginx-traefik.md#when-ailuros-itself-is-unreachable).
- Kubernetes: the Envoy Gateway policies ship with `failOpen: false`. See
  [Kubernetes](kubernetes.md).

The shipped examples pair `AILUROS_FAILURE_MODE=open` with a proxy that fails
closed, on purpose. A failing model is usually transient, and Ailuros is still
there to log each request it let through and count it in
`ailuros_classifier_errors_total`. An unreachable Ailuros is usually a deployment fault
(a wrong address, a crash loop, a broken rollout); failing open there would
turn inspection off for every route with nothing recording it. Set the proxy
to fail open only if availability matters more to you than inspection, and
alert on the proxy's own error counters if you do. Setting
`AILUROS_FAILURE_MODE=closed` and leaving the proxy closed is the strict
choice.

## Request IDs

Every allow or deny decision carries `X-Ailuros-Request-Id`, matching the
`decision` log line. The NGINX and Traefik examples forward it upstream on
allowed requests and return it to the client on denials (the NGINX example
re-attaches it to its 403 and 503 responses, which are JSON with a
`request_id` field). Behind Envoy, Ailuros adds it to allowed requests itself
and puts it on its JSON denials. A forward-auth 500 for a
misconfigured proxy (missing or conflicting original-request headers) is not
a decision and has no request ID.

## Observability

- JSON logs on stdout: one `decision` line per request with request ID,
  outcome, `attack_score`, the most likely attack `category` and its
  `confidence`, `reason`, and latency. Every line has the same fields (empty
  or `null` when they do not apply). In `deep` mode each gRPC message
  decision has its own request ID and a `stream_id`, the ID the upstream
  sees. Bodies are never logged above `debug`.
- `ailuros_classifier_errors_total` counts failed classifier calls only, not
  a frontend's protocol errors or a client that went away.
- Prometheus metrics at `:9090/metrics` (`ailuros_*`).
- OpenTelemetry traces when `OTEL_EXPORTER_OTLP_ENDPOINT` or
  `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set, over OTLP/HTTP
  (`http/protobuf`) or, with `OTEL_EXPORTER_OTLP_PROTOCOL=grpc`, OTLP/gRPC.
  The other standard `OTEL_EXPORTER_OTLP_*` variables (headers, TLS,
  timeout) apply; `OTEL_PROPAGATORS` chooses `tracecontext` and/or
  `baggage` (both by default; `none` turns propagation off), and
  `OTEL_TRACES_EXPORTER=none` or `OTEL_SDK_DISABLED=true` turns tracing off. Set `OTEL_SERVICE_NAME` to name the service.
