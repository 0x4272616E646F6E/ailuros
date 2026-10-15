# Contributing to Ailuros

Bug reports, fixes, tests and documentation are welcome. For larger changes,
open an issue first. Report security issues privately as described in
[SECURITY.md](SECURITY.md).

## Development setup

You need Go (the version in `go.mod`) and
[golangci-lint](https://golangci-lint.run) v2. Docker with Compose v2 is
required for integration tests; `make validate-k8s` also needs kubectl, and
`make test-k8s` needs kind.

| Command | What it does |
|---|---|
| `make build` | builds `bin/ailuros` and `bin/ailuros-eval` |
| `make test` | unit and offline config tests with the race detector, no network |
| `make lint vet` | golangci-lint (with gosec) and `go vet`, once per build tag |
| `make validate-envoy` | checks the shipped Envoy configs with `envoy --mode validate`, also with the JA4 block uncommented (Docker) |
| `make validate-k8s` | renders and checks every Kubernetes overlay offline |
| `make test-integration` | every proxy in front of Ailuros, with docker compose |
| `make test-k8s` | the same cases in a kind cluster with Envoy Gateway |
| `make eval` | runs `ailuros-eval` against a model ([Evaluating models](docs/evaluation.md)) |

Run `make lint vet test` before opening a pull request. Run
`make test-integration` when changing a frontend or shipped proxy config.
See [docs/design/](docs/design/README.md) for design context.

## Pull requests

- Keep a pull request to one change, with tests for new behavior and for
  every bug fixed (a test that fails without the fix).
- Write commit messages that say what changed and why, in plain sentences.
  Do not add `Co-Authored-By` trailers for AI tools.
- Add a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for anything
  a user would notice.
- Update the docs in the same pull request when behavior or configuration
  changes. If a design decision changes, add a dated line to the History of
  the relevant note in `docs/design/`.

CI must pass before a pull request is merged.

## Licence of contributions

Ailuros is licensed under the [Apache License, Version 2.0](LICENSE). Under
section 5 of that licence, anything you submit for inclusion is licensed
under the same terms, with no separate agreement or sign-off needed. Only
submit work you have the right to license this way.

## Integration tests

`make test` needs no network. `make test-integration` runs the shared cases
through each supported proxy with Docker Compose:

| Stack | Proxy config |
|---|---|
| `envoy-lite`, `envoy-standard`, `envoy-deep`, `envoy-extauthz` | `deploy/envoy/*.yaml` |
| `nginx` | `deploy/nginx/nginx.conf` |
| `traefik` | `deploy/traefik/dynamic.yml` + `test/integration/compose/traefik-static.yml` |

The tests build Ailuros, a stub decision model and an echo upstream, then use
the stub's request markers to exercise allow, block and failure paths. No model
or API key is needed.

```sh
make test-integration
# One stack, left running afterwards for inspection:
go test -tags integration -count=1 -run '^TestNginx$' ./test/integration -keep
# Clean up kept stacks, including the hashed per-override projects
# (ailuros-it-<stack>-<hash>); `docker compose ls --all --filter name=ailuros-it`
# lists them. Containers a test started on a stack's network carry the
# ailuros-it.project label and go first:
for c in $(docker ps -aq --filter label=ailuros-it.project); do docker rm -f "$c"; done
for p in $(docker compose ls --all -q --filter name=ailuros-it); do docker compose -p "$p" down -v; done
```

`make test-integration-model MODEL_URL=… MODEL=…` runs the sample dataset
against a real model. `make test-k8s` runs the shared cases through every Kubernetes overlay in a
temporary kind cluster and installs Envoy Gateway v1.9.2; `KEEP=1` leaves the
cluster running for inspection. `make validate-k8s` checks overlays offline.

## Continuous integration

GitHub Actions (`.github/workflows/`):

| Workflow | When | What |
|---|---|---|
| `ci` | pull requests, pushes to `main` | `make lint` (golangci-lint v2 with gosec), `go vet` (all build tags), `go mod tidy` check, `go test -race` with coverage, binaries and image build, hadolint, `make validate-envoy`, `make validate-k8s`, kubeconform, `make test-integration` |
| `security` | pull requests, pushes to `main`, weekly | CodeQL (Go and workflows), govulncheck, Gitleaks over the full history, zizmor, dependency review on pull requests |
| `scorecard` | pushes to `main`, weekly | OpenSSF Scorecard |
| `k8s` | weekly, on demand | `make test-k8s` (kind and Envoy Gateway) |
| `release` | `vX.Y.Z` tags on a `main` commit | unit tests, multi-arch image to GHCR, Grype scan and SBOM per platform, cosign signature, provenance, then the version tags |

Run the main checks locally with `make lint vet test`.
