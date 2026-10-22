# Design notes

These notes record why decision-waf is built the way it is: the constraints, the
decisions and the alternatives that were turned down. The main
[README](../../README.md) says how to run and configure it; the code says
what it does. Each note ends with a dated history of changes to the design.

- [architecture.md](architecture.md): the decision rule, failure modes,
  policy, the classifier backends and their guard, the frontends, telemetry
  and configuration.
- [envoy.md](envoy.md): the ext_proc and ext_authz integrations, body and
  gRPC message handling, deep mode, and the shipped Envoy configs.
- [kubernetes.md](kubernetes.md): the Kustomize base and overlays for Envoy
  Gateway, hardening, availability and timeouts.
- [signals.md](signals.md): GraphQL, smuggling and WebSocket signals,
  protocol and JA4 metadata, and the opt-in limits that block on them.
- [testing.md](testing.md): the test layers, the stub model, the shared
  integration cases, and how they map to CI.
- [evaluation.md](evaluation.md): `decision-waf-eval`, which measures a model
  against labelled requests.
- [open-items.md](open-items.md): known low-severity gaps left unfixed on
  purpose.
