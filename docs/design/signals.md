# Request signals and limits

Ailuros extracts a few structural signals from each request before classifying it: the shape of a GraphQL document, header patterns associated with request smuggling, WebSocket handshake properties, and two pieces of connection metadata (the HTTP protocol and, behind Envoy, the client's JA4 TLS fingerprint). The signals are added to the prompt so the model sees them, and a new `limits:` block in the policy can turn specific signals into hard blocks that skip the model. Every limit is off by default.

Status: implemented on `feat/signals`. Operators' view: [docs/signals.md](../signals.md).

## Context

Ailuros is a decision service beside the proxy, not in the data path. It sees what the proxy sends it: headers always, and a body prefix in Envoy's `standard` and `deep` modes. Some attacks are clearer from the request's structure than from its text, and some structure is cheap to check deterministically:

- A GraphQL query 40 levels deep, or with 500 aliases, is a denial-of-service attempt whatever its field names say. Introspection in production is usually reconnaissance.
- `Transfer-Encoding` on an HTTP/2 request, or alongside `Content-Length`, has no legitimate use and is the raw material of request smuggling.
- A cross-origin WebSocket handshake is how cross-site WebSocket hijacking starts.
- The client's TLS fingerprint separates scripted clients from browsers when the headers claim otherwise.

The goal is to catch more in the traffic Ailuros already inspects, cheaply and without changing behavior for operators who do not opt in. Closing blind spots that need Ailuros in the data path (WebSocket messages after the upgrade, TLS passthrough) is out of scope.

Constraints:

- One implementation for every frontend and for `ailuros-eval`, so an evaluation still decides exactly as the server does.
- No new behavior without opt-in: with no `limits`, decisions are the same as before (the prompt gains a `signals:` block).
- Signals that a client could forge must not be trusted by default.

## Decisions

### Signals are extracted once, in the engine

A new package, `internal/signals`, has one pure function, `Extract(*inspect.Request) Signals`. The engine calls it on every decision after resolving the policy and before redaction. Frontends only fill two new metadata fields on `inspect.Request`: `Protocol` and `JA4`.

Rejected:

- **Each frontend computing its own signals.** Each knows its own context, but the GraphQL and smuggling logic would exist three times and `ailuros-eval` would drift from the server.
- **A rule language (CEL over the request and signals).** Most flexible, but it is a heavy dependency, it makes policy harder to validate, and none of the limits below need it.

### Signal catalogue

Each part of `Signals` is empty when it does not apply.

**GraphQL.** A request is a GraphQL candidate when its content type is `application/graphql` (the body is the document), when a JSON body (an object, or an array for a batch) has a string `query` field, or when the URL has a `query` parameter, on any method (the body and the URL are both read, and their documents merged). URL pairs are read with the iterator redaction uses (`inspect.QueryPairs`): split on `;` as well as `&`, keys and values decoded leniently. A `query` value has two readings, measured as the larger field by field: whole up to the next `&`, as a server splitting on `&` alone reads it, so a `;` inside a GraphQL string or comment cannot cut it short, and up to its first `;`, as a server splitting on `;` reads it. One leading UTF-8 byte order mark on a JSON body is dropped before either walk, so it cannot hide a batch from `max_batch` (UTF-16 is out of scope). JSON keys match in any case, as `encoding/json` matches struct tags; a JSON body the strict walk rejects before its end (`NaN`, `Infinity`) falls back to a lenient scan that measures every string `query` key at any depth, over-counting rather than missing one. A string `encoding/json` cannot decode (raw control characters, an invalid or short escape) is decoded leniently rather than dropped: raw bytes are kept and valid escapes decoded; an invalid escape `\X` has two readings, `X` (Jackson with `ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER`) and nothing, and a short or cut-off `\u` escape is dropped with its digits. Keys are decoded the same way and match if any reading does. A document with several readings is measured as the largest of them, field by field (`measure`/`widen`), never their sum. A backend that tolerates such strings (Python `json.loads(strict=False)`, Jackson with `ALLOW_UNQUOTED_CONTROL_CHARS`) runs the query, so a limit must still see it. It counts as GraphQL only if that text lexes as a GraphQL document: after whitespace and comments it starts with `{`, `query`, `mutation`, `subscription` or `fragment`. A search API's `?query=shoes` is not GraphQL.

Measured: operation types (query, mutation, subscription), operation count (per document: the largest document's in a batch, since `max_batch` limits the documents), batch size (entries in the JSON array), maximum selection depth, field count, alias count, fragment count, introspection (a `__schema` or `__type` field; `__typename` does not count), `operationName` (only when it is a GraphQL Name of at most 64 characters), and whether the document was truncated. Depth counts open braces, so a cut-off deep query still reports its depth. Depth follows named fragment spreads: each fragment's own depth and the depth of each spread inside it are recorded, and after the walk a memoised depth-first expansion gives the depth a spread reaches (a spread at depth d of a fragment reaching e levels reaches d-1+e). A spread of an undefined fragment adds nothing; a cycle of spreads reports depth 1048576 (2^20) and the marker `fragment_cycle`, so any `max_depth` trips. Fields and aliases follow spreads the same way: each shape (the operations' text, or one fragment) records the fields and aliases counted while it was current (an alias takes one off fields and adds one to aliases), and the expansion adds, for every spread, the expanded totals of the fragment spread, once per spread, memoised and cycle-guarded like depth. Sums saturate at 2^20 so a fan-out of any size neither overflows nor takes long, and a cycle saturates fields and aliases too. Reported fields and aliases are the larger of what arrived and the expanded totals of the operations, so an unused fragment still counts. Inline fragments are counted in the text and not expanded. The fragment count is of definitions as written.

Only what Ailuros already holds is read: the body prefix in `standard` and `deep`, the URL query in every mode. In `lite` mode and behind forward-auth only URL queries are visible.

The document is read by a small, lenient lexer written for this purpose (`graphql_lexer.go`; about 300 lines with the measurement in `graphql_document.go`), not a GraphQL library: it only counts, it must accept truncated documents that a strict parser rejects, and it adds no module. It understands strings (including block strings), comments, and escapes, so braces inside them do not count.

**Smuggling flags**, from the headers as Ailuros receives them:

| Flag | Condition |
|---|---|
| `te_with_cl` | both `Transfer-Encoding` and `Content-Length` |
| `te_on_h2` | `Transfer-Encoding` on HTTP/2 or HTTP/3, where it is forbidden (needs `Protocol`) |
| `te_not_chunked` | a `Transfer-Encoding` value other than exactly `chunked` |
| `multiple_content_length` | more than one `Content-Length` value (equal or not), or a single value containing a comma (even `5, 5`) |
| `multiple_host` | more than one `Host` value |
| `bad_header_name` | a header name with bytes outside the HTTP token characters |

These are best effort. Ailuros sees headers after the proxy has parsed them, and Envoy rejects most of these requests before they reach Ailuros. The shipped NGINX config clears `Content-Length` on the auth subrequest. The flags mostly catch what a lenient proxy, or one in front of it, lets through.

**WebSocket handshake.** A request is a handshake when `Upgrade` contains `websocket` and `Connection` contains `upgrade`. Only the Envoy frontends can see this: NGINX and Traefik drop both headers from the auth request. Signals: `cross_origin` (Origin missing, or its host differs from the request's Host), the offered subprotocols (only HTTP tokens of at most 64 characters, at most 8, then `+N` for the rest), and `bad_version` (`Sec-WebSocket-Version` other than 13). Messages after the upgrade are not inspected by any frontend.

**Metadata.** `protocol` (`HTTP/1.0`, `HTTP/1.1`, `HTTP/2`, `HTTP/3`) and `ja4` (for example `t13d1516h2_8daaf6152771_b186095e22b6`). Where each comes from is under "Frontends" below.

### Signals in the prompt and the log

`Render` adds a `signals:` block after the TLS lines, one line per non-empty part, in a fixed order:

```
signals:
  protocol: HTTP/2
  ja4: t13d1516h2_8daaf6152771_b186095e22b6
  graphql: op=query operations=1 depth=14 fields=230 aliases=200 introspection=no
  smuggling: te_on_h2
  websocket: cross_origin subprotocols=graphql-ws
```

Values come from the request, so they go through the same cleaning as every other rendered line and cannot forge prompt lines.

Every decision log line carries the signals in compact form (`signals="graphql depth=14 aliases=3; smuggling te_on_h2"`), with or without limits, so operators can measure their traffic before setting any.

Changing the prompt shifts model scores, so `ailuros-eval` results record a prompt version in their header and `compare` warns when two runs differ in it.

### Limits are opt-in policy

A top-level `limits:` block sets defaults; a route's own `limits:` overrides them field by field:

```yaml
limits:
  graphql:
    max_depth: 12          # omitted: no limit; at least 1
    max_aliases: 50
    max_fields: 500
    max_operations: 1      # operation definitions per document
    max_batch: 10          # entries in a JSON batch array
    introspection: block   # allow (default) | block
  smuggling: block         # allow (default) | block: any smuggling flag blocks
  websocket:
    cross_origin: block    # allow (default) | block
    bad_version: block
  ja4:
    block: ["t13d190900_9dc949149365_97f8aa674fd9", "t12i*"]  # exact, or a prefix ending in *
routes:
  - match: { path_prefix: /internal/graphql }
    limits:
      graphql: { introspection: allow, max_depth: 30 }
```

Routes are already resolved under several readings of the path with the stricter result winning; limits merge the same way (the lowest `max_*`, `block` over `allow`, the union of JA4 lists), and the route label still joins contributing routes as `a+b`.

`Parse` rejects unknown keys, a `max_*` below 1, an action other than `allow` or `block`, and empty or malformed JA4 entries (anything but the JA4 alphabet, `_`, and one trailing `*`). Hot reload behaves as for the rest of the policy.

Rejected: **a log-only mode per limit.** The `signals=` log field already shows what a limit would block, so a third action would add configuration without adding information.

### A limit blocks before the model

`signals.Check(Signals, policy.Limits) (limit string, hit bool)` is a pure function that checks limits in a fixed order (smuggling, WebSocket, JA4, then GraphQL batch, operations, introspection, depth, aliases, fields) and reports the first one exceeded. On a hit the engine blocks without calling the model, in `Engine.limited`, which every entry point (`DecideNote`, `Fail` and `Bypass`) runs unless the decision already denies:

- The client gets the normal block response (403, or gRPC 7 `PERMISSION_DENIED`), not the malformed 400: the request is well-formed and policy refused it.
- The decision has note `limit` (logged as `reason=limit`, as other bypass notes are) and a new field `limit=<name>` (for example `graphql_depth`), logged and recorded on the span. Metrics count it as `outcome=block` with category `none`; `ailuros_decisions_total` has no reason or limit label.

On a truncated body the limits apply to what arrived. Depth, alias and field counts only grow with more input, so a prefix over a limit is safe to block; a prefix under the limits goes to the model as before.

### Frontends: protocol and JA4

| Frontend | GraphQL | Smuggling, WebSocket | Protocol | JA4 |
|---|---|---|---|---|
| Envoy ext_proc (`lite`) | URL queries | yes | `request.protocol` attribute | opt-in header |
| Envoy ext_proc (`standard`, `deep`) | URL queries and bodies | yes | `request.protocol` attribute | opt-in header |
| Envoy ext_authz | URL queries | yes | `attributes.request.http.protocol` | opt-in header |
| NGINX, Traefik (forward-auth) | URL queries | smuggling yes; WebSocket no (they drop `Upgrade` and `Connection`) | no | no |
| Envoy Gateway | as the matching Envoy frontend | as the matching Envoy frontend | `EnvoyExtensionPolicy` `processingMode.request.attributes` | `ClientTrafficPolicy` `tls.fingerprints: [JA4]` plus `headers.earlyRequestHeaders` (example; checked by hand, not in kind) |

**ext_proc.** The shipped configs add `request.protocol` to `request_attributes`, and `buildRequest` reads it alongside `source.address`. Without the attribute (an older config) `Protocol` stays empty and `te_on_h2` cannot fire.

**ext_authz.** Envoy always sends the protocol in the CheckRequest; no config change.

**Forward-auth.** No protocol and no JA4. Traefik passes custom client headers through, so a header carrying either could be forged, and Ailuros cannot tell which proxy is in front of it.

**JA4.** Envoy's TLS inspector computes the fingerprint when `enable_ja4_fingerprinting` is set and exposes it as the `%TLS_JA4_FINGERPRINT%` formatter, not as an attribute ext_proc or ext_authz can request. The shipped Envoy configs gain a commented opt-in block: the `tls_inspector` listener filter with fingerprinting on, and a `header_mutation` HTTP filter ahead of Ailuros's filter that overwrites `x-ailuros-ja4` with the fingerprint. Ailuros reads that header only when `AILUROS_JA4_HEADER` names it (default empty: off), because a client can send the header itself when the proxy does not overwrite it. A shared helper, `frontend.TakeJA4(headers, name)`, reads the value, removes the header so it is not rendered twice, and treats `-` (no TLS) as empty. JA4 needs TLS terminated at Envoy; TLS passthrough runs no HTTP filter, so Ailuros never sees those connections.

That `header_mutation` expands `%TLS_JA4_FINGERPRINT%` ahead of the ext_proc and ext_authz filters, and overwrites a client-sent `x-ailuros-ja4`, was verified against Envoy 1.39.4 with a TLS listener (see Verification).

### Configuration and ailuros-eval

One new variable, `AILUROS_JA4_HEADER`, validated as a header name and lower-cased. Limits live in the policy file.

Dataset entries gain optional `protocol` and `ja4` fields so recorded traffic replays with its metadata. Signals come from the engine, so evaluation results match the server without further work; the server-versus-eval test covers it.

## Verification

Checked on 2026-10-14 against Envoy v1.39.4 and Envoy Gateway v1.9.2.

- JA4 through `header_mutation`: works. With `enable_ja4_fingerprinting` on the `tls_inspector` and a `header_mutation` HTTP filter using `OVERWRITE_IF_EXISTS_OR_ADD`, a request carrying a forged `x-ailuros-ja4` reached the route with the real fingerprint (`t13d4907h2_...` over HTTP/2, `...h1_...` over HTTP/1.1). The same worked with `early_header_mutation_extensions` on the connection manager. Ruling: the JA4 work (plan Task 8) proceeds.
- WebSocket handshakes: ext_proc (lite) sees `connection`, `upgrade`, `origin`, `sec-websocket-key`, `sec-websocket-protocol`, `sec-websocket-version`; ext_authz sees the same; NGINX forwards `origin` and the `sec-websocket-*` headers but not `Upgrade` or `Connection`; Traefik likewise. `upgrade_configs: [{ upgrade_type: websocket }]` is needed in the shipped Envoy configs: without it Envoy answers the handshake with 403 and Ailuros never sees it. Detection rule: unchanged (`Upgrade` contains `websocket` and `Connection` contains `upgrade`); it applies behind Envoy only, and handshakes are not detectable behind NGINX or Traefik. Adding `upgrade_configs` is in scope for plan Task 9.
- Envoy Gateway: request attributes supported via `EnvoyExtensionPolicy.spec.extProc[].processingMode.request.attributes` (prefixes including `request.`, so `request.protocol` is accepted); JA4 supported via `ClientTrafficPolicy` `spec.tls.fingerprints: [JA4]` plus `spec.headers.earlyRequestHeaders` (only the CRD schema was read; whether the formatter expands there was not run in Envoy Gateway). Ruling: the Envoy Gateway work (plan Task 9) adds the protocol attribute overlay and, if the kind run confirms the formatter expands, a JA4 overlay; otherwise JA4 is documented as unverified there. Later checked by hand in a throwaway kind cluster with an HTTPS listener: `tls.fingerprints: [JA4]` plus `headers.earlyRequestHeaders.set` of `x-ailuros-ja4: %TLS_JA4_FINGERPRINT%` replaced a forged header (one or two copies) with the real fingerprint over HTTP/1.1 and HTTP/2, and Ailuros, behind the lite overlay with `AILUROS_JA4_HEADER=x-ailuros-ja4`, logged it. It ships as `deploy/kubernetes/examples/ja4-client-traffic-policy.yaml`, not in an overlay, since it needs a TLS listener and Envoy Gateway applies one `ClientTrafficPolicy` per Gateway.

## Testing

- `internal/signals`: table tests per detector, including near-misses that must not fire (`?query=shoes`, `chunked` on HTTP/1.1, a single `Content-Length`, same-origin handshakes, `Upgrade` without `Connection: upgrade`, braces inside GraphQL strings and comments, `__typename`), truncated documents and batches, and a fuzz test of the lexer (no panics, depth never negative).
- `internal/policy`: parsing and validation errors, route overrides, stricter-wins merging across path readings.
- `internal/decision`: a limit hit blocks without calling the classifier and records note `limit` and `limit=…` (logged as `reason=limit limit=…`); signals reach the prompt and the log; with no limits, outcomes are unchanged.
- Frontends: ext_proc and ext_authz carry the protocol; `TakeJA4` honours the opt-in and removes the header; a client's `x-ailuros-ja4` is ignored when `AILUROS_JA4_HEADER` is unset.
- Each key test is checked by removing the logic it guards and seeing it fail.
- Integration (compose): an introspection query blocked by a limit through Envoy and, as a GET, through NGINX; a GraphQL query under the limits (depth 2) reaching the stub model with the `signals:` block; a cross-origin handshake blocked; `HTTP/2` recorded for an h2 request through Envoy. No compose stack has a TLS listener, so JA4 through Envoy was verified by hand only (see Verification).
- Kubernetes (kind): protocol on every overlay. JA4 needs an HTTPS listener, which the kind Gateway lacks; it was checked by hand (see Verification).
- `make validate-envoy` runs `envoy --mode validate` on each shipped config as shipped and with its JA4 block uncommented (a temporary copy), and `test/deployconfig/ja4_test.go` checks offline that the uncommented block puts the overwriting `header_mutation` ahead of Ailuros's filter and is the same in all four configs. Neither sends TLS traffic.

## Rollout

One branch, `feat/signals`, one commit or more per task, each leaving the tree green:

1. Verify JA4 through `header_mutation` on Envoy 1.39.4, and check what Envoy Gateway v1.9.2 offers for request attributes and JA4. It passed for Envoy, so the JA4 work went ahead.
2. `internal/signals` (GraphQL, smuggling, WebSocket), the `signals:` prompt block, the log field and the eval prompt version. Behavior changes only in the prompt.
3. Policy `limits:`: schema, parsing, validation, merging.
4. Enforcement in the engine: `Check`, `Bypass`, the `limit` field, metrics.
5. Protocol in ext_proc and ext_authz, and the Envoy config changes.
6. JA4: config block, `AILUROS_JA4_HEADER`, `TakeJA4`.
7. Envoy Gateway overlays, where supported.
8. Docs (policy limits, a signals page with the frontend table and its limits, configuration, Envoy, CHANGELOG), the eval dataset fields, and the full verification run.

## Limitations and trade-offs

- Fields and aliases follow named spreads, so they can exceed what a server executes (a type condition that never matches, `@skip`ped fields): over-reporting is the safe direction for a limit. Totals stop at 2^20.
- Smuggling flags see the request after the proxy parsed it; they are not a substitute for a proxy that rejects ambiguous framing.
- WebSocket messages after the upgrade, and TLS passthrough, remain uninspected.
- GraphQL bodies are visible only in Envoy's `standard` and `deep` modes; elsewhere only URL queries are.
- WebSocket handshakes are detected only behind Envoy, and Envoy rejects them (403) unless the listener sets `upgrade_configs`, which the shipped configs do. In `standard` and `deep` modes the ext_proc frontend decides a handshake on its headers alone, since Envoy never ends the stream of an upgrade request and no body follows; this applies only to a GET with no body (no Transfer-Encoding, Content-Length absent or 0) and a Sec-WebSocket-Key, and any other request carrying Upgrade headers takes the normal body path.
- JA4 is Envoy-only and opt-in, and it fingerprints the client's TLS library, not the user: shared libraries and middleboxes make it a weak signal on its own.
- The `signals:` block changes the prompt, so model scores shift and earlier evaluation runs are not directly comparable.

## History

- 2026-10-14: Design approved: signals extracted once in the engine, opt-in limits in the policy, JA4 behind an explicit opt-in.
- 2026-10-14: Implemented. Review findings folded in: limits also apply to allowing bypasses and fail-open decisions (a bypass that already blocks keeps its reason), and body-derived GraphQL limits are not checked on the `AILUROS_DEEP_OVERSIZE=allow` bypass, which carries no body; ext_proc decides a real WebSocket handshake on its headers; route limits loosen only for paths every reading places under the route; `ja4: {}` inherits and `ja4: {block: []}` clears; `max_*` must be integers of at least 1. JA4 on Envoy Gateway stayed unverified and was not shipped.
- 2026-10-14: Fields and aliases now follow named fragment spreads (once per spread, saturating at 2^20), closing a fan-out gap where a fragment spread many times counted once and evaded `max_fields` and `max_aliases`.
- 2026-10-14: JA4 on Envoy Gateway checked by hand (see Verification) and shipped as `deploy/kubernetes/examples/ja4-client-traffic-policy.yaml`.
