# Kubernetes with Envoy Gateway

Ailuros runs on Kubernetes as an ordinary Deployment that Envoy Gateway calls through the Gateway API. `deploy/kubernetes/` holds a Kustomize base and one overlay per inspection mode (`lite`, `standard`, `deep`, `ext_authz`). Each overlay ships the Envoy Gateway policy that attaches Ailuros to a Gateway. No new Ailuros code was needed. This note explains the choices behind those manifests. For install steps see [Kubernetes (Envoy Gateway)](../kubernetes.md).

## Context

The standalone Envoy, NGINX and Traefik deployments are covered in [envoy.md](envoy.md) and [architecture.md](architecture.md). Kubernetes users needed a supported way to put Ailuros in front of their applications. The obvious route was an ingress-nginx integration, but ingress-nginx is retired upstream.

Constraints:

- Ailuros's inspection mode is a property of the process, so one Deployment serves one mode.
- With `failOpen: false` the data path depends on Ailuros being up, so availability and rollouts matter more than for a pure sidecar.
- The manifests must be checkable without a cluster, and the default `go test ./...` must not need Kubernetes tools.

## Decisions

### Envoy Gateway and the Gateway API

Envoy Gateway already exposes the two hooks Ailuros serves: `EnvoyExtensionPolicy.extProc` (per-route body mode, message timeout, fail-open) and `SecurityPolicy.extAuth.grpc`. Ailuros already speaks both protocols, so Kubernetes support is manifests, policies, tests and documentation.

Rejected or out of scope:

- **Other Gateway API implementations** (Istio, Cilium, kGateway). Each has its own CRDs for external processing, and core Gateway API has no standard ext_authz or ext_proc hook. Supporting them would mean separate manifests and test matrices.
- **A Helm chart.** Kustomize overlays are enough for a handful of fixed variants, and they render offline with `kubectl kustomize`.
- **Overlays tied to a published image.** The base uses the placeholder image `ailuros`; operators set the release image (`ghcr.io/0x4272616e646f6e/ailuros`) or their own build with Kustomize `images:`, so the manifests never pin a version.

### One overlay per mode, one Deployment per mode

`AILUROS_INSPECTION_MODE` is read once at startup and decides what the process expects the proxy to send, so a Deployment cannot serve two modes. Each overlay patches the mode into the base and adds its policy:

| Overlay | Policy | Notes |
|---|---|---|
| `lite` | `EnvoyExtensionPolicy` | headers only |
| `standard` | `EnvoyExtensionPolicy` | body `BufferedPartial` |
| `deep` | `EnvoyExtensionPolicy` + `BackendTrafficPolicy` + `ClientTrafficPolicy` | body `FullDuplexStreamed`, trailers sent |
| `ext_authz` | `SecurityPolicy` | Ailuros in `lite` mode and `AILUROS_EXTAUTHZ_ADDR=:9003`, because ext_authz sends no body |

Policies target a Gateway named `eg` in the same namespace. Operators patch `targetRefs` to their own Gateway or route. A policy that names a missing target is not applied, so the install guide tells operators to check the `Accepted` condition.

### Hardened, replicated base

`deploy/kubernetes/base/` is the same for every mode:

- **Pod hardening.** Non-root, read-only root filesystem, no privilege escalation, all capabilities dropped, `RuntimeDefault` seccomp, no service account token. The image is distroless static, so nothing needs a writable filesystem or a shell.
- **Availability.** Two replicas, a PodDisruptionBudget (`minAvailable: 1`) and a soft topology spread by hostname. With `failOpen: false`, no ready pod means refused traffic, so one voluntary disruption must not remove every replica. The spread is soft (`ScheduleAnyway`) so a small cluster can still schedule. The budget blocks drains if someone runs a single replica.
- **Rollouts.** Ailuros closes its gRPC listeners at once on SIGTERM, but Envoy Gateway removes the endpoint asynchronously. Requests in that window would be refused. A native `preStop` sleep of 5 s (no shell in the image) keeps the pod serving until the endpoint is gone. `terminationGracePeriodSeconds: 20` covers that sleep plus Ailuros's 10 s shutdown window with 5 s spare.
- **Probes.** Readiness is `/readyz` (ready once the model probe passes), liveness is `/healthz`, both on the metrics port.

### An empty model fails closed

The base sets `AILUROS_CLASSIFIER_MODEL` to an empty string on purpose. `config.Load` rejects an empty model, so a Deployment applied without a model never becomes ready, and `failOpen: false` then refuses traffic. The alternative, a default model name, could start and pass requests while pointing at a backend nobody chose.

### Policy ConfigMap with hot reload

The policy file is the `ailuros-policy` ConfigMap mounted at `/etc/ailuros/policy.yaml` (`AILUROS_POLICY_FILE`). Ailuros's existing file reload handles the symlink swap Kubernetes performs when a ConfigMap changes, so policy edits need no restart. Other settings are `AILUROS_*` variables in the Deployment.

### Service ports and h2c

The Service exposes `extproc` 9001, `extauthz` 9003 and `metrics` 9090. The two gRPC ports carry `appProtocol: kubernetes.io/h2c`, which tells Envoy Gateway to use cleartext HTTP/2 to the backend. Without it the gRPC call would fail. Port 9003 only listens in the `ext_authz` overlay.

### Timeouts

Each policy waits `AILUROS_CLASSIFIER_TIMEOUT` (1 s) plus 500 ms, so Ailuros answers, applying `AILUROS_FAILURE_MODE`, before Envoy gives up. Envoy Gateway's default message timeout of 200 ms would undercut Ailuros. The value is written `1500ms`, not `1.5s`, because the pinned CRD's duration pattern rejects decimals.

- **deep.** Full-duplex streaming ignores `messageTimeout`, so the overlay bounds the stream with the limits of `deploy/envoy/deep.yaml`: a `BackendTrafficPolicy` ends idle streams after 30 s, and a `ClientTrafficPolicy` requires the whole request within 60 s (`requestReceivedTimeout`, the counterpart of Envoy's `request_timeout`). The overlay first used `BackendTrafficPolicy.requestTimeout`, which in Envoy Gateway times only the upstream response and starts once the request has fully arrived, so a client dripping its body just inside the idle timeout held Ailuros memory indefinitely, and long streaming responses were cut at 60 s. Both policies target the Gateway. A route-level `BackendTrafficPolicy` would replace it, and Envoy Gateway applies one `ClientTrafficPolicy` per Gateway, so operators merge their own client settings into the overlay's.
- **ext_authz.** `SecurityPolicy.extAuth` has its own `timeout`, also `1500ms`.

### API key as a Component, mounted outside the policy volume

A key in an optional Secret volume plus `AILUROS_CLASSIFIER_API_KEY_FILE` would crash Ailuros when the Secret is absent, because `config.Load` fails on an unreadable key file. So the base has no key (a local model needs none) and `deploy/kubernetes/components/api-key` adds the volume and the variable together. `examples/with-api-key` shows its use.

The Secret mounts at `/etc/ailuros-secret`, not under `/etc/ailuros`. A mountpoint nested inside the read-only ConfigMap volume cannot be created by the runtime, and the pod fails to start. The component appends the volume with a JSON patch so the policy volume stays first.

### Mixed modes

Two modes need two instances. Kustomize renames Services with `nameSuffix` but does not follow the rename into Envoy Gateway `backendRefs`, so `examples/mixed-modes` ships a `nameReference` configuration for `EnvoyExtensionPolicy` and `SecurityPolicy`. Each instance also gets an `app.kubernetes.io/instance` label (with `includeSelectors`), so each Service, Deployment and spread constraint selects only its own pods. Without it, both Services would select all Ailuros pods. Each policy is retargeted at its own HTTPRoute, since two Gateway-level policies would both apply. Shipped overlays keep the plain name `ailuros`. The example is the supported way to run more than one.

### Client IP

Envoy Gateway trusts no forwarded hops and uses the connection peer. Behind a load balancer that sets `X-Forwarded-For`, Ailuros would log and classify the balancer's address. `examples/client-traffic-policy.yaml` is a `ClientTrafficPolicy` with `clientIPDetection.xForwardedFor.numTrustedHops`. It is an example, not part of an overlay, because the right number depends on the operator's network and too high a number lets clients forge their address. See [Envoy](../envoy.md#client-ip) for the Envoy side.

### Fail-closed with `failOpen: false`

Every policy sets `failOpen: false`. If no Ailuros pod is ready, for example while the model is unreachable at startup, attached routes are refused rather than passing uninspected: Envoy Gateway marks the policy invalid ("no ready endpoints") and answers 500 itself, in every overlay (`make test-k8s` checks this by scaling Ailuros to 0). The `ext_authz` overlay also sets `statusOnError: 503`, because Envoy Gateway's default, 403, is what a block looks like too; it is expected to apply when endpoints exist but cannot answer (a hung or crashing pod that is still ready), which is not tested. Once Ailuros is up, `AILUROS_FAILURE_MODE` and per-route policy decide model-failure behavior as on every other proxy. The replicas, budget, spread and `preStop` sleep exist to keep this stance from turning rollouts into outages. Deep mode requires `failOpen: false` anyway.

## How it works

- `deploy/kubernetes/base/`: ServiceAccount, policy ConfigMap, Deployment, Service, PodDisruptionBudget.
- `deploy/kubernetes/overlays/<mode>/`: patches `AILUROS_INSPECTION_MODE` (and `AILUROS_EXTAUTHZ_ADDR` for `ext_authz`) and adds `envoy-gateway-policy.yaml`.
- `deploy/kubernetes/components/api-key/`: optional Secret mount.
- `deploy/kubernetes/components/network-policy/`: optional NetworkPolicy admitting only Envoy Gateway's proxy pods (`app.kubernetes.io/{name: envoy, component: proxy, managed-by: envoy-gateway}` in the `envoy-gateway-system` namespace) to the gRPC ports. The namespace is part of the match because anyone who can create a pod can copy the labels. Opt-in because it needs an enforcing network plugin and assumes Envoy Gateway's default namespace and pod labels. The kind suite runs every overlay with it, and a probe from an unrelated pod was refused on 9001 while 9090 stayed open.
- `deploy/kubernetes/examples/`: `mixed-modes`, `with-api-key`, `with-network-policy`, `client-traffic-policy.yaml`, `ja4-client-traffic-policy.yaml` (JA4 fingerprints to Ailuros; needs an HTTPS listener).
- `test/k8sconfig/render_test.go` (`make validate-k8s`) renders every overlay and example with `kubectl kustomize` and asserts mode, hardening, `preStop` and grace period, spread, selectors, policy fields, ports with `appProtocol`, the API key mount, and the mixed-mode renames. It skips if kubectl is absent.
- `make test-k8s` runs the shared integration cases through every overlay in a kind cluster with Envoy Gateway installed. The harness uses a temporary kubeconfig so a developer's contexts are untouched. See [testing.md](testing.md).

## Limitations and trade-offs

- Only Envoy Gateway is supported and tested (v1.9.2 on Kubernetes v1.37.0 in kind). Field names track that release's CRDs.
- No Helm chart. Operators compose their own Kustomization over an overlay and set the image there.
- A policy that Envoy Gateway does not accept protects nothing and must be checked by the operator.
- The deep overlay's stream limits (60 s to receive a request, 30 s idle) apply to all routes of the Gateway, and its `ClientTrafficPolicy` is the one per Gateway that Envoy Gateway applies.
- Ailuros does not detect the mode of a stream. Pairing a mode with the matching policy is the overlay's job.
- Only `eg` in the same namespace is targeted by default. Cross-namespace attachment is left to operator patches.

## History

- 2026-10-13: Kubernetes support designed around Envoy Gateway, replacing the planned ingress-nginx integration.
- 2026-10-13: Envoy Gateway v1.9.2 rejects decimal durations; policies use `1500ms`.
- 2026-10-13: A Secret mounted under the read-only policy ConfigMap volume failed; the API key mounts at `/etc/ailuros-secret`.
- 2026-10-13: An optional Secret volume would have crashed Ailuros when absent; the key moved into a Kustomize Component.
- 2026-10-13: Review found rollouts dropping requests while the endpoint was being removed; added the `preStop` sleep, grace period and topology spread.
- 2026-10-13: Test runs were changed to use a temporary kubeconfig, so they never touch the developer's current context.
- 2026-10-14: The deep overlay bounds request reception with a `ClientTrafficPolicy` (`requestReceivedTimeout: 60s`) instead of `BackendTrafficPolicy.requestTimeout`, which timed only the upstream response.
- 2026-10-14: The `ext_authz` overlay answers 503 when Ailuros is unreachable, and an optional `network-policy` component admits only Envoy Gateway's proxy pods to the gRPC ports.
- 2026-10-14: The mixed-modes example shares its `nameReference` configuration through a `rename` component instead of a copy per instance.
- 2026-10-14: The network-policy component also matches Envoy Gateway's namespace; labels alone admitted any pod that copied them.
- 2026-10-15: Correction to the 2026-10-14 `ext_authz` entry: with no Ailuros pod ready, clients get 500, not 503. Envoy Gateway marks the `SecurityPolicy` (like the `EnvoyExtensionPolicy` of the other overlays) invalid when its Service has no ready endpoints and refuses the routes itself; `statusOnError: 503` is expected to apply only while endpoints exist but cannot answer (untested). The kind suite now asserts the 500.
