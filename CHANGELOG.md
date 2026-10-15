# Changelog

All notable changes to Ailuros are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a
minor version may change behavior or configuration; the entry says how.

## [Unreleased]

The first release.

### Added

- Inline classification of every request with TypeSafe Jev (`jev` backend)
  or any OpenAI-compatible model (`openai` backend), local models included.
  A request is blocked when its attack score, `1 − P(benign)`, reaches the
  threshold.
- Envoy `ext_proc` with three inspection modes (`lite` headers only,
  `standard` with a buffered body prefix, `deep` with whole HTTP bodies and
  per-message gRPC), and Envoy `ext_authz`. Requires Envoy 1.34 or later.
- Compressed request bodies and gRPC messages (gzip and deflate) are
  classified decompressed; encodings Ailuros cannot read are refused.
- HTTP forward-auth for NGINX `auth_request` and Traefik `ForwardAuth`.
- Failure modes `open` and `closed` for classifier failures, with a circuit
  breaker and per-route overrides. An answer outside the label set is
  blocked by default (`AILUROS_BAD_OUTPUT`).
- A YAML policy file with categories, routes, per-route thresholds and
  failure modes, and redaction of secret headers, query parameters and body
  fields. It reloads on change or `SIGHUP`.
- Kubernetes manifests for Envoy Gateway: a hardened Kustomize base and one
  overlay per mode. The base policy ConfigMap is empty, so the built-in
  defaults (redacted headers included) apply and follow new releases.
- JSON decision logs, Prometheus metrics and OpenTelemetry traces.
- `ailuros-eval`, which measures a model on a labelled dataset and suggests
  a threshold, with a 24-request sample and example reports.
- Example configs for Envoy, NGINX and Traefik, checked by integration tests
  that run each proxy in front of Ailuros.
- Request signals: the shape of GraphQL documents (depth, fields, aliases,
  operations, batches, introspection), request-smuggling header flags,
  WebSocket handshake properties, the HTTP protocol and, behind Envoy, the
  client's JA4 fingerprint. They appear in the prompt (a `signals:` block)
  and in a `signals` log field. GraphQL is read from the body and from the
  URL's `query=` on every method; depth, fields and aliases follow fragment
  spreads, once per spread (a cycle reports `fragment_cycle`); `operations`
  counts operation definitions per document, with batches limited by
  `max_batch`. Policy `max_*` limits must be below 1048576 (the ceiling at
  which expanded counts saturate). A
  leading UTF-8 byte order mark on a JSON body is ignored, so it cannot
  hide a batch from `max_batch`. A JSON `query` string Go cannot decode (a raw
  control character, an invalid or short escape) is decoded leniently and
  still measured; an invalid escape `\X` is read as `X` and as nothing,
  in keys too, and the larger reading counts. URL pairs are split on `;` as well as `&` and decoded
  leniently, for both GraphQL and redaction. A `query=` value is also read
  whole up to the next `&` (the larger reading counts), and a redacted
  value is masked up to the next `&`, so a `;` inside a value hides
  nothing.
- Opt-in policy `limits:` that block on those signals before the model is
  called (403, `reason=limit`, `limit=<name>` in the log), per route.
- `AILUROS_JA4_HEADER`, off by default, for the JA4 fingerprint an Envoy
  `header_mutation` filter puts in a request header. It may not name a
  pseudo-header or any header Ailuros reads by name (the WebSocket
  handshake, `origin`, `content-encoding`, `grpc-encoding` and `referer`
  included; see docs/configuration.md).
- `deploy/kubernetes/examples/ja4-client-traffic-policy.yaml`: the same for
  Envoy Gateway, with a `ClientTrafficPolicy` on an HTTPS listener.
- The Envoy configs and Envoy Gateway overlays request `request.protocol`,
  and the Envoy configs set `upgrade_configs` for WebSocket handshakes.
- The prompt gains the `signals:` block (prompt version 2), which shifts model
  scores. `ailuros-eval` results record `prompt_version` and `limit`,
  `compare` warns when prompt versions differ, and dataset entries take
  `protocol` and `ja4`. The JSON summary gives attribution's denominator as
  `attribution_detected`, and attribution prints `n/a` when only limit
  blocks were detected.
- Release images for linux/amd64 and linux/arm64, signed with cosign, with
  SBOMs and SLSA build provenance.

[Unreleased]: https://github.com/0x4272616E646F6E/ailuros/commits/main
