# Ailuros

Ailuros is an ingress decision service. A proxy sends each request to Ailuros,
which uses TypeSafe Jev or an OpenAI-compatible model, including local models,
to return an allow or block decision.

> Status: early development. Ailuros ships Envoy `ext_proc` (all three
> inspection modes) and `ext_authz` frontends, and an HTTP forward-auth
> frontend for NGINX `auth_request` and Traefik `ForwardAuth`,
> and Kubernetes through Envoy Gateway (see
> [Kubernetes (Envoy Gateway)](docs/kubernetes.md)).

## Quick start

```sh
docker build -t ailuros .
docker run --rm -p 9001:9001 -p 9002:9002 -p 9090:9090 \
  -e AILUROS_CLASSIFIER_BACKEND=openai \
  -e AILUROS_CLASSIFIER_BASE_URL=http://host.docker.internal:11434/v1 \
  -e AILUROS_CLASSIFIER_MODEL=llama3.2 \
  ailuros
```

On Linux, `host.docker.internal` needs `--add-host=host.docker.internal:host-gateway`
added to the `docker run` command.

Then point your proxy at Ailuros: Envoy at the ext_proc listener
`ailuros:9001` (see [Envoy](docs/envoy.md) and `deploy/envoy`), NGINX or
Traefik at `http://ailuros:9002/` (see [NGINX and Traefik](docs/nginx-traefik.md)).
Every setting is listed in [Configuration](docs/configuration.md).

## How it decides

1. The proxy forwards the original request's method, URI, host, and headers.
2. Ailuros redacts configured secrets, then asks the model to classify the
   request as `benign` or one of your configured attack categories.
3. Ailuros calculates the attack score as `1 − P(benign)`. It blocks with 403
   when the score reaches the matching route's `threshold`, or
   `AILUROS_BLOCK_THRESHOLD` when no route threshold is set; otherwise it
   allows with 200. The most likely attack category is logged but does not
   affect the decision.
4. Model failures follow `AILUROS_FAILURE_MODE`: `open` allows and `closed`
   returns 503. Invalid model output follows `AILUROS_BAD_OUTPUT` and defaults
   to blocking. If Ailuros is unreachable, the proxy decides (see
   [Operations](docs/operations.md#when-ailuros-itself-is-unreachable)).

Every request is classified inline, so every request pays the model's latency.
Jev's API also enforces rate limits; size your deployment accordingly.

## Documentation

- [Configuration](docs/configuration.md): every `AILUROS_*` variable, body
  limits, the policy file, local models.
- [Envoy](docs/envoy.md): `ext_proc` and `ext_authz`, the three inspection
  modes, timeouts, gRPC.
- [NGINX and Traefik](docs/nginx-traefik.md): forward-auth, client IP, and
  the headers the proxy must control; inspecting every request on NGINX
  Gateway Fabric with the
  [Ailuros NGINX module](https://github.com/0x4272616E646F6E/ailuros-nginx-module).
- [Kubernetes (Envoy Gateway)](docs/kubernetes.md): Kustomize overlays,
  attaching policies, availability.
- [Request signals and limits](docs/signals.md): GraphQL shape, smuggling,
  WebSocket and JA4 signals, and opt-in limits that block before the model.
- [Operations](docs/operations.md): when Ailuros is unreachable, request IDs,
  logs, metrics and traces.
- [Evaluating models](docs/evaluation.md): `ailuros-eval`, and choosing a
  threshold.
- [Verifying images](docs/verifying-images.md): signatures, SBOMs and
  provenance of release images.
- [Design notes](docs/design/README.md): why Ailuros is built the way it is.

[CONTRIBUTING.md](CONTRIBUTING.md) covers building, testing and CI;
[SECURITY.md](SECURITY.md) says how to report a vulnerability; changes are
listed in [CHANGELOG.md](CHANGELOG.md).

## License

Ailuros is licensed under the [Apache License, Version 2.0](LICENSE). See
[NOTICE](NOTICE) for the copyright notice.
