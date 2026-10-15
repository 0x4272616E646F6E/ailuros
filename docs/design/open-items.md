# Known open items

These are known, accepted, low-severity gaps found in code review and left unfixed on purpose. None of them affects the allow or block decision unless the line says so. Each one is small enough to become a GitHub issue; the lines give the file and the impact so they can be copied into one. Items that were fixed since are not listed. For the design behind the code, see [architecture.md](architecture.md) and [envoy.md](envoy.md); for how the tests are built, see [testing.md](testing.md).

## Robustness

- The OpenAI backend has not been checked against vLLM, which needs an NVIDIA GPU (`internal/classifier/openai/openai.go`). Ollama, llama.cpp server and LM Studio support `json_schema` with `strict`, enforce the label set, and return logprobs (docs/configuration.md). A server that rejects `json_schema` falls back to `json_object`; one that accepts but ignores it is reported at startup.

## Inspection coverage

These are documented limits of what Ailuros sees or reports (docs/signals.md, "Limits of this approach"; [signals.md](signals.md)), listed here so they are tracked with the rest.

- WebSocket messages after the upgrade, and TLS passthrough connections, are never inspected: Envoy runs no HTTP filter on them (docs/signals.md).
- WebSocket handshakes are detected only behind Envoy. NGINX and Traefik do not pass `Upgrade` and `Connection` to forward-auth, so `websocket` limits never fire there (`internal/frontend/forwardauth`, docs/design/signals.md, Verification).
- GraphQL bodies are measured only in Envoy `standard` and `deep` modes; Envoy `lite`, ext_authz, NGINX and Traefik see URL queries only (`internal/signals/graphql.go`).
- Form bodies, `text/plain` GraphQL bodies, and JSON with comments, single quotes or UTF-16 are not measured as GraphQL, though some servers accept them (`internal/signals/graphql_source.go`).
- In `deep` mode the `AILUROS_DEEP_OVERSIZE=allow` bypass carries no body, so body-derived GraphQL limits are not checked on it; URL and header limits still are (`internal/decision`, docs/design/signals.md, History).
- GraphQL limits are only as strong as the body cap: a JSON body can put large `variables` or `extensions` before `query` and push the query past the prefix Ailuros reads (`AILUROS_BODY_MAX_BYTES`, `AILUROS_DEEP_MAX_BYTES`; docs/signals.md).
- The GraphQL `operationName` shown in the prompt and the decision log is taken from the unredacted request, so a `json_fields` redaction of `operationName` does not hide it there (`internal/signals/graphql.go`).
- A route label that joins several path readings (`a+b`) can include `default`, the label of a reading that matched no route, carried in from an intermediate combination, so the label can name more than the routes that supplied the settings (`stricter` in `internal/policy/resolve.go`). Logs and the metrics route label are affected; the decision is not.
- A limit block is reported only in the decision log (`limit=<name>`) and the span: `X-Ailuros-Decision` and `ailuros_decisions_total` (category `none`, no reason label) do not name the limit that fired (`internal/telemetry/metrics.go`, `internal/frontend`).
- A JSON string that mixes escape styles (one invalid escape the lenient decoder keeps, another it drops) is read only in the two uniform readings (all kept, all dropped), not in every mix of them (`internal/signals/graphql_source.go`).
- Redaction splits URL pairs on `&` and `;` together and on `&` alone; a server that splits on `;` only reads pairs neither reading produces, and those are not covered (`internal/inspect/query.go`, `internal/redact/redact.go`).

## Tests

- Nothing in CI classifies with a real model. `make test-integration-model` is manual and asserts nothing about detection (`test/integration/model_test.go`).
- `test/integration` has a few harness gaps. An exported `AILUROS_IT_MODEL_URL` makes plain `make test-integration` run the model profile. With `-keep`, the kept Envoy mounts a temporary `lite.yaml` that is deleted afterwards. A stack's project name is released before `compose down` finishes (`test/integration/compose_test.go`). The echo upstream silently truncates bodies over 8 MiB (`test/integration/echo/main.go`).
- Several integration cases are weaker than they look. The message-cap test accepts any gRPC `INTERNAL`, with no check for the reset or the `message_limit` log. The gzip case does not check that echo got nothing, and the snappy case does not check the logged reason. No test asserts the redaction replacement value. The forged `X-Real-Ip` case never checks that the header reached Ailuros (`test/integration/envoy_deep_test.go`, `test/integration/traefik_test.go`).
- The deep gRPC state machine lacks tests for trailers before headers, a second headers message, an empty oneof, and standard mode under `FULL_DUPLEX_STREAMED` (`internal/frontend/extproc/extproc_test.go`). The framer has no boundary tests for length equal to the cap, a 4 GiB declared length, or a cap of 0 (`internal/frontend/extproc/grpcframe_test.go`).
- `internal/app` has no tests for a SIGHUP after start (only before Run and during the shutdown drain), the hard stop after the shutdown window, the health flip on shutdown, or listener rollback (`internal/app/app_test.go`), and `internal/backend` has none for the OpenAI no-logprobs warning.
- OpenAI and Jev backends: no test that Validate rejects a logprob product above 1, that the probe stops on a 5xx, that the `Authorization` header is sent, or for a token that spans the key and the value (`internal/classifier/openai/openai_test.go`, `internal/classifier/jev/jev_test.go`).
- Policy tests: rejection cases check only that an error occurred, with no NaN or multi-error case (`internal/policy/parse_test.go`). Resolve has no test for an empty path (`internal/policy/resolve_test.go`).
- Redact tests lack a truncated SSN object, a check that a non-secret prefix survives, and a URL-escaped form key (`internal/redact/redact_test.go`). Render and gRPC path tests lack a truncated rune cut by more than one byte, and `ParseGRPCPath` cases for `/` and `/svc/` (`internal/inspect`).
- The fence test does not try variants such as `< /request>` or `</request foo>` (`internal/classifier/classifier_test.go`). The guard panic test does not check that the breaker records a failure (`internal/classifier/guard_test.go`).
- Engine tests: `TestSetPolicyConcurrent` asserts nothing beyond the race detector, and body-field redaction is not checked at engine level (`internal/decision/engine_test.go`).
- Telemetry tests: the tracing test leaves the global tracer provider set, and `grpc_method` and the breaker gauge values are not checked (`internal/telemetry`).
- Forward-auth has no test that a `traceparent` header continues the trace (`internal/frontend/forwardauth/forwardauth_test.go`).
