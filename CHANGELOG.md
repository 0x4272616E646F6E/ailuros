# Changelog

All notable changes to decision-waf are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a
minor version may change behavior or configuration; the entry says how.

## [0.3.0] - 2026-10-23

### Changed

- The default attack categories are replaced by a coarser set, in this
  order: `injection`, `xss`, `file_access`, `ssrf_redirect`, `recon`,
  `auth_abuse` and `other_attack` (`benign` is unchanged). The new
  `injection` description also covers NoSQL operators and CRLF header
  injection; `ssrf_redirect` and `other_attack` are new.

  | Before | From this release |
  |---|---|
  | `sqli` | `injection` |
  | `rce` | `injection` |
  | `xss` | `xss` |
  | `path_traversal` | `file_access` |
  | `scanner` | `recon` |
  | `credential_stuffing` | `auth_abuse` |

  Policy files with their own `categories` key are unaffected. Deployments
  on the defaults log and count the new names, so dashboards and alerts
  keyed on the old `category` values (for example on
  `decision_waf_decisions_total`) need updating, as do datasets labelled
  with the old names.
- `eval/datasets/sample.jsonl` and `eval/datasets/selfhosted.jsonl` use the
  new labels. The self-hosted dataset (now `selfhosted-2026-10b`) gains 28
  hand-written requests: SSRF and open-redirect attempts, CRLF and NoSQL
  injections, and benign requests with URLs in parameters (299 in all).

## [0.2.0] - 2026-10-22

### Changed (breaking)

- The project is renamed from Ailuros to decision-waf. There are no
  compatibility aliases: rename every setting below when upgrading.
  decision-waf and `decision-waf-eval run` refuse to start while any
  `AILUROS_*` variable is set, and name the `DECISION_WAF_*` replacement for
  each. Datasets and results files written with the old keys must have
  their header keys renamed before 0.2.0 reads them.

  | What | Before (0.1.x) | From 0.2.0 |
  |---|---|---|
  | Repository | `github.com/0x4272616E646F6E/ailuros` | `github.com/0x4272616E646F6E/decision-waf` |
  | Go module | `github.com/0x4272616E646F6E/ailuros` | `github.com/0x4272616E646F6E/decision-waf` |
  | Image | `ghcr.io/0x4272616e646f6e/ailuros` | `ghcr.io/0x4272616e646f6e/decision-waf` |
  | Binaries | `ailuros`, `ailuros-eval` | `decision-waf`, `decision-waf-eval` |
  | Environment variables | `AILUROS_*` | `DECISION_WAF_*` (same suffixes) |
  | HTTP headers | `X-Ailuros-*` (`x-ailuros-request-id`, `x-ailuros-decision`, `x-ailuros-ja4`) | `X-Decision-Waf-*` (`x-decision-waf-request-id`, `x-decision-waf-decision`, `x-decision-waf-ja4`) |
  | Metrics | `ailuros_*` (e.g. `ailuros_decisions_total`) | `decision_waf_*` (e.g. `decision_waf_decisions_total`) |
  | Trace spans and attributes | `ailuros.decide`, `ailuros.classify`, `ailuros.*` | `decision_waf.decide`, `decision_waf.classify`, `decision_waf.*` |
  | Eval file keys | `ailuros_eval_dataset`, `ailuros_eval_results`, `ailuros_version` | `decision_waf_eval_dataset`, `decision_waf_eval_results`, `decision_waf_version` |
  | Paths | `/etc/ailuros/policy.yaml`, `/etc/ailuros-secret` | `/etc/decision-waf/policy.yaml`, `/etc/decision-waf-secret` |
  | Kubernetes resources and labels | `ailuros`, `ailuros-*` (e.g. `ailuros-policy`, `app.kubernetes.io/name: ailuros`) | `decision-waf`, `decision-waf-*` (e.g. `decision-waf-policy`, `app.kubernetes.io/name: decision-waf`) |

### Added

- `eval/datasets/selfhosted.jsonl`: 271 semi-synthetic self-hosted requests
  (headers only), with `eval/gen/selfhosted.py` to regenerate it, and reports
  for `d1-3B` and `h2o-lightning-4b` on it.

### Documentation

- Decision models served by llama.cpp server (`d1-3B`, `h2o-lightning-4b`)
  use the `jev` backend (`/v1/systemone`); through `openai` they reason and
  time out.

- NGINX Gateway Fabric: the decision-waf NGINX module inspects every request on a
  route alongside tinyauth or another `auth_request` check, and how it applies
  forward-auth's answers.

## [0.1.0] - 2026-10-15

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

[Unreleased]: https://github.com/0x4272616E646F6E/decision-waf/compare/v0.2.0...HEAD
[0.3.0]: https://github.com/0x4272616E646F6E/decision-waf/releases/tag/v0.3.0
[0.2.0]: https://github.com/0x4272616E646F6E/decision-waf/releases/tag/v0.2.0
[0.1.0]: https://github.com/0x4272616E646F6E/decision-waf/releases/tag/v0.1.0
