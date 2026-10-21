# Kubernetes (Envoy Gateway)
On Kubernetes, Ailuros runs as a Deployment that [Envoy Gateway](https://gateway.envoyproxy.io)
calls through the Gateway API. Tested with Envoy Gateway v1.9.2 on Kubernetes
v1.37.0 (the kind node image);
`deploy/kubernetes/` holds a Kustomize base and one overlay per mode:

| Overlay | Envoy Gateway policy | Ailuros sees |
|---|---|---|
| `lite` | `EnvoyExtensionPolicy` (ext_proc) | request headers |
| `standard` | `EnvoyExtensionPolicy`, body `BufferedPartial` | headers and up to `AILUROS_BODY_MAX_BYTES` of the body |
| `deep` | `EnvoyExtensionPolicy`, body `FullDuplexStreamed`, plus a `BackendTrafficPolicy` and a `ClientTrafficPolicy` | headers, then the body as it streams; gRPC message by message |
| `ext_authz` | `SecurityPolicy` (ext_authz) | request headers |

On NGINX Gateway Fabric instead, see
[NGINX Gateway Fabric](nginx-traefik.md#nginx-gateway-fabric-every-request-next-to-tinyauth).

**Install.** Use a release image, `ghcr.io/0x4272616e646f6e/ailuros:<X.Y.Z>`
(check it first as in [Verifying images](verifying-images.md)), or build and
push your own (`docker build -t <registry>/ailuros:<tag> .`). Then make your
own Kustomization on top of an overlay that sets the image and the model:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: my-app
resources:
  - <path to your Ailuros checkout>/deploy/kubernetes/overlays/standard
images:
  - { name: ailuros, newName: ghcr.io/0x4272616e646f6e/ailuros, newTag: <X.Y.Z> }
patches:
  - patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata: { name: ailuros }
      spec:
        template:
          spec:
            containers:
              - name: ailuros
                env:
                  - { name: AILUROS_CLASSIFIER_BACKEND, value: jev }
                  - { name: AILUROS_CLASSIFIER_BASE_URL, value: "https://api.typesafe.ai" }
                  - { name: AILUROS_CLASSIFIER_MODEL, value: <model> }
```

and `kubectl apply -k .`. The base leaves `AILUROS_CLASSIFIER_MODEL` empty on
purpose: Ailuros refuses to start until you set it, so a half-configured
install fails closed rather than passing traffic. For a hosted model, create
the key Secret (`kubectl create secret generic ailuros-classifier
--from-literal=api-key=…`) and add `components:
[<path>/deploy/kubernetes/components/api-key]`; the component mounts the
Secret at `/etc/ailuros-secret`. The policy file is the `ailuros-policy`
ConfigMap; Ailuros reloads it when the ConfigMap changes. The base ships it
empty, so the built-in defaults apply and follow new releases; a section you
add replaces its default (start from `examples/policy.yaml`).

**Attaching.** The shipped policies attach to every route of a Gateway named
`eg` in the same namespace. Patch `targetRefs` to name your Gateway, or an
HTTPRoute/GRPCRoute to protect only that route. **Check that Envoy Gateway
accepted the policy** — a policy that names a missing target, or a field the
installed version rejects, protects nothing:

```bash
kubectl get envoyextensionpolicy ailuros -o jsonpath='{.status.ancestors[0].conditions[?(@.type=="Accepted")]}'
```

(`securitypolicy` for `ext_authz`); `status` must be `True`.

**One mode per Deployment.** Ailuros's inspection mode is per process, so one
Deployment serves one mode. To run two modes, install two instances with
their own name suffix and instance label, each policy attached to its own
routes: `deploy/kubernetes/examples/mixed-modes` does this for lite and deep,
including the Kustomize `nameReference` configuration that keeps the
policies' `backendRefs` pointing at the renamed Services. The deep half's
`BackendTrafficPolicy` moves to its route, but its `ClientTrafficPolicy` can
only target a Gateway, so the 60s limit to receive a request applies to the
lite routes too.

**Timeouts.** Each policy waits `AILUROS_CLASSIFIER_TIMEOUT` + 500ms
(`messageTimeout`/`timeout: 1500ms` for the default 1s) so Ailuros answers —
applying `AILUROS_FAILURE_MODE` — before Envoy gives up; for the
`EnvoyExtensionPolicy` overlays, Envoy Gateway's default `messageTimeout` of
200ms would undercut it (the `SecurityPolicy` default is 10s). Raise both together. Write durations in
whole units such as `1500ms`: the Envoy Gateway v1.9.2 CRDs reject `1.5s`.
Deep mode's full-duplex streaming ignores `messageTimeout`, and Ailuros holds
part of every unfinished body, so its overlay bounds the stream instead: a
`BackendTrafficPolicy` ends idle streams after 30s, and a
`ClientTrafficPolicy` requires the whole request to arrive within 60s
(`requestReceivedTimeout`), the limits of `deploy/envoy/deep.yaml`. Both
target Gateway `eg`, so they apply to every route of it. A
`BackendTrafficPolicy` on a route replaces the Gateway's rather than merging
with it, and Envoy Gateway applies one `ClientTrafficPolicy` per Gateway: put
other client settings, such as the client IP example below, into the
overlay's.

**Failure behavior.** The policies ship with `failOpen: false`: while no
Ailuros pod is ready (for example while the model is unreachable at startup),
attached routes are refused with a 5xx. With no ready Ailuros endpoints at
all, Envoy Gateway marks the policy invalid ("no ready endpoints") and
answers 500 itself, in every overlay (checked by `make test-k8s`, which
scales Ailuros to 0). The `ext_authz` overlay's `statusOnError: 503` is
expected to apply when Envoy still has endpoints but cannot get an answer
from them (not tested); it is set because Envoy Gateway's default, 403,
cannot be told apart from a block. Once Ailuros is up,
`AILUROS_FAILURE_MODE` and per-route policy decide as everywhere else. That is why the base runs 2 replicas, spread
softly across nodes, with a PodDisruptionBudget (`minAvailable: 1`; with a
single replica it blocks node drains). A `preStop` sleep of 5 s and a 20 s
termination grace period keep a terminating pod serving until Envoy Gateway
has removed its endpoint, so rollouts do not drop requests.

**Who can call Ailuros.** The Service is reachable from every pod in the
cluster, and every call on the gRPC ports is a classifier call. A noisy or
compromised workload can exhaust the model's rate limit, and with
`AILUROS_FAILURE_MODE=open` protected routes then pass unclassified. Add
`components: [<path>/deploy/kubernetes/components/network-policy]` to admit
only Envoy Gateway's proxy pods, in `envoy-gateway-system`, to those ports
(edit the namespace if Envoy Gateway runs its proxies elsewhere; it needs a
network plugin that enforces NetworkPolicy).

**Client IP.** Envoy Gateway trusts no forwarded hops by default and uses the
connection's peer. Behind a load balancer that sets `X-Forwarded-For`, apply
`deploy/kubernetes/examples/client-traffic-policy.yaml` with `numTrustedHops`
set to the number of proxies you control in front of the Gateway.

**Request signals.** The `lite`, `standard` and `deep` overlays request
`request.protocol` in `processingMode.request.attributes`, so the protocol
signal works; the `ext_authz` overlay gets it without configuration.
The shared cross-origin WebSocket limit case passes on every overlay in the
kind run. See [Request signals and limits](signals.md).

**JA4.** `deploy/kubernetes/examples/ja4-client-traffic-policy.yaml` has Envoy
Gateway compute the client's JA4 fingerprint and write it into
`x-ailuros-ja4` before any HTTP filter runs, replacing any value the client
sent; set `AILUROS_JA4_HEADER=x-ailuros-ja4` on the Deployment to have
Ailuros read it. It needs an HTTPS listener that terminates TLS at the
Gateway. Envoy Gateway applies one `ClientTrafficPolicy` per Gateway, so with
the deep overlay or the client IP example, merge the `tls` and `headers`
fields into that policy instead. It was checked by hand on Envoy Gateway
v1.9.2 (the kind tests have no TLS listener).

The rest of [Envoy](envoy.md) (modes, timeouts, gRPC) applies here too;
[Configuration](configuration.md) lists every `AILUROS_*` variable.
