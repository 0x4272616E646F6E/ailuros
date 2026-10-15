# Request signals and limits

Ailuros measures a few structural signals of each request before it asks the
model: the shape of a GraphQL document, header patterns that go with request
smuggling, WebSocket handshake properties, the HTTP protocol and, behind
Envoy, the client's JA4 TLS fingerprint. The signals are added to the prompt
and to the decision log. An optional `limits:` block in the policy can turn
any of them into a block that skips the model. Every limit is off by
default: with no `limits:`, decisions are the same as before, except that the
model sees the `signals:` block.

## What Ailuros extracts

Each kind is absent from the prompt and the log when it does not apply. The
signals are computed on the request as the engine received it, before
redaction, and rendered in a fixed order:

```
signals:
  protocol: HTTP/2
  ja4: t13d1516h2_8daaf6152771_b186095e22b6
  graphql: op=query operations=1 batch=3 depth=14 fields=230 aliases=200 fragments=2 introspection=no name=Search
  smuggling: te_on_h2
  websocket: cross_origin subprotocols=graphql-ws
```

The decision log carries the same text in a `signals` field, for example
`signals="graphql op=query operations=1 depth=14 fields=230 aliases=200 introspection=no; smuggling te_on_h2"`,
whether or not any limit is set.

**GraphQL.** A request is a candidate when its content type is
`application/graphql` (the body is the document), when a JSON body has a
top-level `query` string (an object, or an array of objects for a batch), or
when the URL has a `query=` parameter, on any method. URL pairs are split
on `;` as well as `&`, as some servers do, and decoded leniently (a bad `%`
escape is kept as it is); a `query=` value is read both whole up to the
next `&`, so a `;` inside it cannot cut the document short, and up to its
first `;`, and each measure is the larger of the two. The body and the URL
are both read and their documents merged; `name` is the body's
`operationName`, else the URL's. JSON keys `query` and `operationName` match
in any case, as Go backends match them. A JSON body that Go's decoder
rejects before it ends (`NaN` or `Infinity`, which Python backends accept)
is scanned leniently instead: every `query` key with a string value, at any
depth, is measured, which can over-count. A string Go cannot decode (a raw
newline or tab, an invalid or short escape such as `\x` or `\u12`) is still
measured: raw bytes are kept and valid escapes decoded. An invalid escape
`\X` is read both as `X` (as Jackson reads it with
`ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER`) and as nothing, the larger
reading counting; a short `\u` escape is dropped with its digits. This
applies to keys too, so `"quer\y"` is a `query` key. It counts as GraphQL only if the
text starts, after whitespace and comments, with `{`, `query`, `mutation`,
`subscription` or `fragment`, so `?query=shoes` is not GraphQL. Measured:
operation types (`op=`), `operations` (operation definitions per document;
in a batch, the largest document's count, since `max_batch` limits the
documents), `batch` (entries in a JSON array, shown when there is one),
`depth`, `fields`, `aliases`, `fragments` (shown when above 0),
`introspection` (a `__schema` or `__type` field; `__typename` does not
count), `name` (the `operationName`, shown only when it is a GraphQL name of
at most 64 characters, so it cannot forge other fields), and `truncated`
when the body was cut. `depth` follows named fragment spreads into the
fragments they name, so a query cannot hide its nesting in a chain of
fragments; a spread of a fragment that is not defined (say, cut off) adds
nothing. Fragment spreads that form a cycle (`F1` spreads `F2`, which
spreads `F1`) report `depth=1048576` and the marker `fragment_cycle`, so any
`max_depth` blocks them. `fields` and `aliases` follow spreads too, once per
spread: a fragment spread ten times counts ten times, so fan-out cannot hide
under `max_fields` or `max_aliases`. Each is the larger of what arrived and
what the operations expand to, so a fragment nothing spreads still counts,
and the expanded totals saturate at 1048576 (a cycle reports that too; the
count can still be larger when the arrived text or a batch is). `fragments`
counts the definitions as written. A JSON body's one leading UTF-8 byte
order mark is ignored (UTF-16 bodies are not read). Braces inside strings,
block strings and comments are not counted. Limit names: `graphql_batch`,
`graphql_operations`, `graphql_introspection`, `graphql_depth`,
`graphql_aliases`, `graphql_fields`.

**Smuggling flags**, from the headers as Ailuros receives them:

| Flag | Condition |
|---|---|
| `te_with_cl` | both `Transfer-Encoding` and `Content-Length` |
| `te_on_h2` | `Transfer-Encoding` on HTTP/2 or HTTP/3 (needs the protocol, see below) |
| `te_not_chunked` | a `Transfer-Encoding` other than exactly `chunked` |
| `multiple_content_length` | more than one `Content-Length` value (equal or not), or a single value containing a comma (even `5, 5`) |
| `multiple_host` | more than one `Host` value |
| `bad_header_name` | a header name with bytes outside the HTTP token characters |

Limit name: `smuggling`.

**WebSocket handshake.** A request is a handshake when `Upgrade` contains
`websocket` and `Connection` contains `upgrade`. Rendered: `cross_origin`
(Origin missing, or its host differs from the request's Host), `bad_version`
(`Sec-WebSocket-Version` other than 13), and `subprotocols=` the offered
subprotocols that are HTTP tokens of at most 64 characters, the first 8 of
them, then `+N` for the rest and for any that are not tokens (for example
`subprotocols=graphql-ws,+2`); `handshake` when none of those applies. Limit names:
`websocket_cross_origin`, `websocket_bad_version`.

**Protocol and JA4.** `protocol` is `HTTP/1.0`, `HTTP/1.1`, `HTTP/2` or
`HTTP/3`. `ja4` is the client's TLS fingerprint, for example
`t13d1516h2_8daaf6152771_b186095e22b6`. Limit name: `ja4`.

Values come from the request and are cleaned like every other rendered line,
so they cannot forge prompt lines.

## Which frontend sees what

| Frontend | GraphQL | Smuggling | WebSocket handshake | Protocol | JA4 |
|---|---|---|---|---|---|
| Envoy ext_proc `lite` | URL queries | yes | yes | `request.protocol` (in the shipped configs) | opt-in |
| Envoy ext_proc `standard`, `deep` | URL queries and bodies | yes | yes | `request.protocol` | opt-in |
| Envoy ext_authz | URL queries | yes | yes | always | opt-in |
| NGINX, Traefik (forward-auth) | URL queries | yes | no | no | no |
| Envoy Gateway | as the matching Envoy frontend | as Envoy | as Envoy (the cross-origin limit case runs in kind) | the shipped overlays request `request.protocol` | opt-in, example |

- **Bodies** are visible only in `standard` and `deep` ext_proc, so a POSTed
  GraphQL body is measured only there. Elsewhere only the URL's `query=`
  parameters are.
- **WebSocket handshakes** are visible behind Envoy only: NGINX and Traefik
  drop `Upgrade` and `Connection` from the auth request. Envoy rejects
  handshakes with 403 unless the listener has `upgrade_configs`, which the
  shipped configs set. In `standard` and `deep`, ext_proc decides a real
  handshake (a GET with no body and a `Sec-WebSocket-Key`) on its headers,
  since no body follows an upgrade; any other request carrying Upgrade
  headers takes the normal body path. Messages after the upgrade are never
  inspected.
- **Protocol** needs `request.protocol` in the ext_proc `request_attributes`;
  without it (an older config) `te_on_h2` cannot fire. Forward-auth gets no
  protocol, because a header carrying it could be forged.
- **JA4** is Envoy only and opt-in, and needs TLS terminated at Envoy; see
  [Envoy](envoy.md#ja4-tls-fingerprints). On Envoy Gateway,
  `deploy/kubernetes/examples/ja4-client-traffic-policy.yaml` does the same
  with a `ClientTrafficPolicy`; see [Kubernetes](kubernetes.md).

## Limits

Limits are set in the policy file (see [Configuration](configuration.md)). A
top-level `limits:` block gives defaults, and a route's `limits:` overrides
them field by field:

```yaml
limits:
  graphql:
    max_depth: 12          # omitted: no limit; an integer, at least 1
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

`Parse` rejects unknown keys, a `max_*` that is not an integer from 1 to
1048575 (GraphQL counts saturate at 1048576, so a limit there could never
trip), an action other than `allow` or `block`, and JA4 entries that are not the
JA4 alphabet (lower-case letters, digits, `_`) with at most one trailing `*`.
On a route, an omitted field inherits the default. `ja4: {}` inherits the
default list; `ja4: {block: []}` clears it. The policy hot-reloads like the
rest of the file.

**Several readings of a path.** A path can fall under more than one route
(see `examples/policy.yaml`), and the stricter result wins, as it does for
thresholds: the lowest `max_*`, `block` over `allow`, the union of JA4
lists. A route therefore loosens limits only for paths that every reading
places under that route; an ambiguous path gets the stricter limits.

**What a block looks like.** The client gets the normal block response, 403
(gRPC status 7, `PERMISSION_DENIED`), not the malformed-request 400. The
decision log has `reason=limit` (the decision's note, logged as the
reason as for other bypasses) and `limit=<name>` (for example
`graphql_depth`); the span has `ailuros.limit`; the decisions metric counts it as
`outcome=block` with category `none`. The model is not called. Limits are checked
in a fixed order, and the first hit is reported: smuggling, WebSocket, JA4,
then GraphQL batch, operations, introspection, depth, aliases, fields.

**Where limits apply.** Limits apply to every decision that would otherwise
let the request through, so a limit hit turns an allowing bypass
(`AILUROS_DEEP_OVERSIZE=allow`, the message limit, an uninspectable body
allowed) or a fail-open classifier failure into a limit block. A bypass that
already blocks keeps its own reason. On a truncated body, limits apply to
what arrived; depth, aliases and fields only grow with more input, so a
prefix over a limit is safe to block. One gap: in `deep` mode with
`AILUROS_DEEP_OVERSIZE=allow`, the oversize bypass carries no body, so
body-derived GraphQL limits are not checked on that path (limits derived
from headers and the URL are, at the headers decision).

## Tuning

Every decision log line has a `signals` field whether or not limits are set,
so measure your traffic first, then set limits above what normal traffic
does:

```bash
jq -r 'select(.signals | contains("graphql")) | .signals' < ailuros.log | sort | uniq -c | sort -rn | head
```

Scope GraphQL limits to your GraphQL routes with a route `limits:` block
(or leave them unset at the top level), because other endpoints can look
like GraphQL (see below). Start with `smuggling: block` and
`websocket.cross_origin: block` only after checking the log for legitimate
hits.

## Limits of this approach

- GraphQL candidates are only `application/graphql` bodies, JSON bodies with
  a top-level `query` string (an object or a batch array), and `query=` URL
  parameters on any method. Form bodies and `text/plain` JSON bodies are not
  measured. A search API that takes JSON in `query=` may be measured as
  GraphQL depth, so scope GraphQL limits to GraphQL routes.
- Fields and aliases follow named fragment spreads once per spread; the
  expanded totals saturate at 1048576 (reported counts can exceed that when
  the arrived text or a batch is larger). Inline fragments are counted as
  written. Counts can exceed what a server executes (a fragment on a type the object is not, or `@skip`ped
  fields), which errs toward blocking.
- GraphQL limits are only as strong as the body cap. Only the body prefix
  Ailuros receives is read, and a JSON body can put large `variables` or
  `extensions` (or very deep nesting) before `query` to push the query past
  that prefix, where it is not measured. If you rely on GraphQL limits, keep
  legitimate `query` fields within `AILUROS_BODY_MAX_BYTES` (`standard`) or
  `AILUROS_DEEP_MAX_BYTES` (`deep`), and consider `deep` with
  `AILUROS_DEEP_OVERSIZE=block` so oversize bodies are refused rather than
  judged on their prefix.
- The GraphQL `name=` in the prompt and the log comes from the unredacted
  request: a `json_fields` redaction of `operationName` does not hide it
  there.
- The GraphQL reader is a small, lenient lexer that counts, not a validator.
  A document the server's parser reads differently can differ from the
  count.
- Smuggling flags see the request after the proxy parsed it, so they are best
  effort and no substitute for a proxy that rejects ambiguous framing. Envoy
  rejects most of these requests before Ailuros sees them.
- WebSocket handshakes are detected only behind Envoy. Messages after the
  upgrade, and TLS passthrough, are never inspected.
- GraphQL bodies are visible only in Envoy's `standard` and `deep` modes.
- JA4 is Envoy only and opt-in. It fingerprints the client's TLS library, not
  the user; shared libraries and middleboxes make it a weak signal alone.
  Ailuros removes the header only from its own copy of the request: Envoy
  still forwards `x-ailuros-ja4` upstream unless you remove it (for example
  with `request_headers_to_remove` on the route, or a `RequestHeaderModifier`
  on the HTTPRoute with Envoy Gateway).
- The `signals:` block changes the prompt, so model scores shift and
  evaluation runs from before it are not directly comparable (see
  [Evaluating models](evaluation.md)).
