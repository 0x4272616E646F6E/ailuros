# Testing strategy

decision-waf is tested in layers. Unit tests are fast and network-free. Offline checks keep the shipped proxy configs consistent with the Go defaults. Two opt-in suites run the real proxies in front of decision-waf: a docker compose matrix (Envoy in four modes, NGINX, Traefik) and a kind cluster with Envoy Gateway. The same shared test cases run in both. A real-model profile reports detection quality but asserts nothing about it. The integration suites exist because real proxies exposed bugs that unit tests could not.

## Context

decision-waf sits between a proxy and a decision model. Most of the risk is in the seams: what each proxy actually sends, how it reacts to slow or absent answers, and what reaches the upstream. A unit test builds the messages the author expects, so it cannot find a wrong expectation about a proxy. Constraints:

- `go test ./...` must stay network-free and need no Docker, kind or kubectl, so contributors and CI can always run it.
- Integration runs must be repeatable: pinned images, a deterministic model, one command per suite that CI can call unchanged.
- The shipped configs in `deploy/` are the thing under test, so tests should mount them unmodified.

## Decisions

### Layers, from cheapest to dearest

| Layer | Command | Needs |
|---|---|---|
| Unit tests | `make test` (`go test -race ./...`) | Go |
| Offline config checks | part of `go test ./...`; `make validate-k8s` | Go (and `kubectl` for the k8s render test, which skips without it) |
| Envoy config validation | `make validate-envoy` | Docker |
| Compose integration matrix | `make test-integration` | Docker, Compose v2 |
| Kind and Envoy Gateway | `make test-k8s` | Docker, kind, kubectl |
| Real-model profile | `make test-integration-model MODEL_URL=... MODEL=...` | Docker, a reachable model |

Run commands and prerequisites are in [CONTRIBUTING.md](../../CONTRIBUTING.md#integration-tests); this note covers why the layers look like this.

### Offline checks derive expectations from the config defaults

`test/deployconfig/deploy_test.go` checks the shipped Envoy, NGINX and Traefik files and the Dockerfile. `test/k8sconfig/render_test.go` renders every Kubernetes overlay and example with `kubectl kustomize` and checks policies, Service ports and selectors. Neither hard-codes a timeout or port. Both compute them from exported `internal/config` values (`DefaultClassifierTimeout + ProxyTimeoutMargin`, `DefaultExtProcAddr`, `ConventionalExtAuthzAddr`, ...). Changing a default then fails the tests until every shipped file follows, which is the rule that proxy timeouts must exceed the classifier timeout (see [envoy.md](envoy.md)). Rejected: duplicating the numbers in the tests, which drifts silently.

`make validate-envoy` runs `envoy --mode validate` on every `deploy/envoy/*.yaml`, as shipped and with its commented JA4 opt-in uncommented in a temporary copy (`test/deployconfig/ja4_test.go`, which skips without `DECISION_WAF_ENVOY_IMAGE`), using the `ENVOY_IMAGE` that the compose stacks use; CI fails if the two differ.

### Real proxies, driven from Go through docker compose

Integration tests are Go tests behind the `integration` build tag that run `docker compose` and send real HTTP/1.1, h2c and gRPC traffic. Rejected: shell scripts with curl, which cannot match decisions to request IDs or check what the upstream saw, the checks that caught the bugs below. The compose files double as runnable demos.

### A deterministic stub model

`test/integration/stubmodel` implements the Jev endpoint and decides on markers in the request text, so no model or API key is needed:

- `attack` returns `injection` at 0.99 and `xss-marker` returns `xss`; anything else is benign.
- `stub-fail` returns HTTP 503, `stub-garbage` returns malformed JSON, `stub-offformat` returns a well-formed answer whose choice is not a label, and `stub-slow` waits 3 s (the stub tests set a 1 s classifier timeout). A prompt over 32 KiB is also slow, to model a model that chokes on large input.
- It records every prompt. `GET /prompts?contains=<marker>` returns those containing a test-unique marker, so tests find "what the model saw" without decision-waf forwarding its request ID.

`test/integration/echo` is the upstream. Its HTTP side answers 200 with the method, path, query, headers and body it received. It also serves `echo.v1.Echo` (unary and bidirectional stream) over h2c on the same port, replying with each message and the metadata it saw. A test therefore asserts both what the client got and what the upstream actually received, including that a blocked request never arrived. Both programs are `package main` in the main module, built by `test/integration/Dockerfile`; they compile only with the `integration` tag.

### One set of cases, two environments

`sharedCases` in `test/integration/cases_test.go` holds the cases every stack runs (the file is the list; it covers allow and block paths, model failures and timeouts, malformed requests, forged headers, GraphQL and WebSocket limits and the recorded protocol) and takes a `Stack`. A `Stack` reaches the proxy, stub and echo by address and delegates the three things that differ to an `environment` interface: `decisionWafLogs`, `stopDecisionWaf`, `diagnostics`. Compose implements it with `docker compose logs`, `stop` (its project state lives in `composeEnvironment`, not on `Stack`); kind with `kubectl logs`, scaling to 0. Body, gRPC and deep-stream cases are likewise shared helpers, and so is the last case every stack runs, `failClosedWhenDecisionWafDown`: it stops decision-waf (compose `stop`, kind scale to 0) and asserts the status the shipped config documents (500 for ext_proc and Traefik, 503 for ext_authz and NGINX; on kind 500 for every overlay, because Envoy Gateway marks a policy whose Service has no ready endpoints invalid and answers 500 itself) and that nothing reached echo. Where proxies differ (forward-auth, a proxy that writes its own 403 body), a case reads a capability field on the stack's `proxy`, never the stack's name, and a field's zero value is the strict expectation, so a new stack cannot silently skip an assertion. The check that the upstream never sees `x-envoy-internal` runs on every stack.

Build tags separate the files: compose-only files are `//go:build integration`, Kubernetes-only files `//go:build k8s`, and the harness and shared cases `integration || k8s`. Each tag has its own `TestMain` (so `make lint` and `make vet` run once per tag combination).

### Test the same policy in both environments

Both environments use one test policy file, `test/integration/k8s/common/policy.yaml`: `/admin` fails closed and the JSON field `password` is redacted. The compose stacks mount it, and the kind overlays generate the `decision-waf-policy` ConfigMap from it (a Kustomize `configMapGenerator` with `behavior: replace`). There is one copy, so a case cannot pass on one environment for a policy the other never used.

### The kind suite never touches the developer's kubeconfig

`TestMain` creates a temporary kubeconfig and passes `--kubeconfig` to every `kind` call. Every `kubectl` call goes through `kubectlArgs`, which adds `--kubeconfig` and `--context kind-decision-waf-it`; `TestKubectlArgsPinContext` pins this. The developer's kubeconfig and current context are therefore never read or changed. `-keep` (`KEEP=1`) leaves the cluster and prints the kubeconfig path. An earlier version used the default kubeconfig and switched the user's context; CONTRIBUTING.md tells those users how to restore it.

Each overlay runs in its own namespace from a test Kustomization that references the shipped overlay unmodified. If an overlay cannot be composed unmodified, the test fails with an explanation rather than testing a private copy. Before applying, the stack goes through `--dry-run=server` so CRD rejections surface with the API server's message, and afterwards the test waits for the policy's `status.conditions` to report accepted: an unaccepted policy would leave routes unprotected and every "blocked" case would fail confusingly. decision-waf runs with one replica. The Envoy Gateway release and the kind node image are pinned in `test/integration/k8s_test.go`.

### The real-model profile reports, it does not assert

`make test-integration-model` swaps the stub for a Jev-compatible model, sends the 24 requests in `eval/datasets/sample.jsonl` through Envoy `lite`, and prints each decision and a summary. Assertions about detection would make CI depend on a model; quality measurement belongs to [evaluation.md](evaluation.md). Settings reach `go test` as environment variables so `make` never echoes the API key. Since a real model exceeds the 1 s stub timeout, the profile raises decision-waf's classifier timeout (`MODEL_TIMEOUT`, default 10s) and mounts a temporary `lite.yaml` whose `message_timeout` is that plus 500 ms.

## How it works

- Lifecycle (`up` in `test/integration/compose_test.go`): `docker compose -p decision-waf-it-<stack> ... up -d --no-build --wait` (the three images are built once, before any stack starts), gated by healthchecks (stub and echo `/healthz`, proxy ready endpoints); decision-waf's distroless image has no healthcheck, so the harness polls its `/readyz` on the published admin port instead. Cleanup runs `down -v`; `-keep` skips it. Dynamic host ports and per-stack project names (with a hash suffix when a test overrides decision-waf settings) let runs coexist with other work.
- Observing: decisions come from decision-waf's JSON logs matched by request ID, never by order; prompts from the stub; the upstream view from echo. Every request carries a unique marker. On failure the harness prints the last 50 log lines per service and recent prompts (kind adds the decision-waf, Envoy and Envoy Gateway logs and the policy and Gateway conditions).
- Stack-specific cases live in `envoy_*_test.go`, `nginx_test.go`, `traefik_test.go` and `k8s_cases_test.go`; the shared ones in `harness_test.go` and `cases_test.go`.
- Kind: `TestMain` checks tools, recreates cluster `decision-waf-it`, installs Envoy Gateway, builds the three images once and loads them. The proxy is reached by `kubectl port-forward` to the Service Envoy Gateway generates. A full run takes about 1.5 minutes.

### CI mapping

| Workflow | What it runs |
|---|---|
| `.github/workflows/ci.yml` `lint` | `make lint` and `make vet` (once per build-tag combination), `go mod tidy -diff` |
| `ci.yml` `test` | `go test -race` with coverage, which includes the version-pin consistency test in `test/pins` |
| `ci.yml` `build` | binaries, hadolint on both Dockerfiles, image build (not pushed) |
| `ci.yml` `validate` | `make validate-envoy`, `make validate-k8s`, kubeconform on the overlays and examples |
| `ci.yml` `integration` | `make test-integration`, after `test` passes |
| `.github/workflows/security.yml` | CodeQL, `govulncheck` (default, `integration` and `k8s` tags), Gitleaks, zizmor, dependency review; weekly schedule |
| `.github/workflows/k8s.yml` | `make test-k8s`, weekly and on demand only |

The kind suite is off the push path because it downloads Envoy Gateway and takes minutes. `make test-integration-model` is not in CI.

## Limitations and trade-offs

- The stub decides on keywords, so integration tests prove plumbing, not detection. The stub tests also use a 1 s classifier timeout, shorter than a real model needs.
- Scenarios that need a dead or replaced decision-waf (stopping it, changing its IP) use their own compose project so they cannot disturb the others; this costs extra stack startups.
- kubeconform skips the Envoy Gateway CRDs, which have no schema there; only `make test-k8s` checks them, against a real API server.
- Only Envoy Gateway is tested on Kubernetes. No load or performance testing, and no parallel CI orchestration.
- The Kubernetes proxy versions are pinned; bumping them is a deliberate change that may need config fixes (see History).

## History

- 2026-10-13: Envoy's ext_proc delivers header values in `raw_value`, ext_authz in `value`; Ailuros read only one and header mutations arrived empty. Both are read, with a unit test (`internal/frontend/extproc/extproc_test.go`) using `raw_value`.
- 2026-10-13: large bodies exceeded the classifier timeout and the request failed open; the stub's slow-on-large-prompt rule and the timeout cases came from this.
- 2026-10-13: Envoy trusted a client-supplied `X-Forwarded-For` for the client IP; the shipped configs now use the real peer address (`use_remote_address`) and the forged-header case guards it.
- 2026-10-13: NGINX held requests for its 60 s default when Ailuros hung; the shipped config bounds the auth timeouts (`TestNginx`, `TestShippedNginxConfigBoundsAuthTimeouts`).
- 2026-10-13: NGINX pinned Ailuros's IP at startup and kept using it after Ailuros moved; the config uses a resolver and a variable in `proxy_pass` (`TestNginxReResolvesAilurosWithoutReload`).
- 2026-10-13: gRPC-Web text bodies (base64) evaded inspection; they are decoded before classification (`internal/inspect/grpcweb_test.go`, plus an Envoy `standard` integration case).
- 2026-10-13: Envoy Gateway v1.9.2 rejects decimal durations; policies use `1500ms`, not `1.5s`. Separately, review caught that the API-key Secret was mounted inside the read-only policy ConfigMap volume, which container runtimes commonly refuse; no test used that component, so it was moved to `/etc/ailuros-secret` before it could ship.
- 2026-10-13: review (not an integration test) found that a panic in a decision observer after a block could turn the block into an allow on a fail-open route. `frontend.Decide` now keeps the block, and `internal/frontend/frontend_test.go` covers it.
- 2026-10-13: the kind suite first used the default kubeconfig and changed the user's current context; it now uses a temporary kubeconfig and a pinned context.
- 2026-10-14: The integration test policy is one file that both environments use, replacing three copies kept equal by a check in the kind setup.
