.PHONY: build eval lint test vet validate-envoy validate-k8s test-integration test-integration-model test-k8s

ENVOY_IMAGE ?= envoyproxy/envoy:v1.39.4

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/0x4272616E646F6E/ailuros/internal/version.Version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/ailuros ./cmd/ailuros
	go build -ldflags "$(LDFLAGS)" -o bin/ailuros-eval ./cmd/ailuros-eval

test:
	go test -race ./...

lint:
	golangci-lint run ./...
	golangci-lint run --build-tags=integration ./test/integration/...
	golangci-lint run --build-tags=k8s ./test/integration/...

vet:
	go vet ./...
	go vet -tags integration ./test/integration/...
	go vet -tags k8s ./test/integration/

validate-envoy: export AILUROS_ENVOY_IMAGE = $(ENVOY_IMAGE)
validate-envoy:
	go test -count=1 -run '^TestEnvoyValidates$$' -v ./test/deployconfig/

test-integration:
	go test -tags integration -count=1 -timeout 15m ./test/integration/...

test-integration-model: export AILUROS_IT_MODEL_URL = $(value MODEL_URL)
test-integration-model: export AILUROS_IT_MODEL = $(value MODEL)
test-integration-model: export AILUROS_IT_MODEL_BACKEND = $(value MODEL_BACKEND)
test-integration-model: export AILUROS_IT_MODEL_API_KEY = $(value MODEL_API_KEY)
test-integration-model: export AILUROS_IT_MODEL_TIMEOUT = $(value MODEL_TIMEOUT)
test-integration-model:
	@test -n "$$AILUROS_IT_MODEL_URL" -a -n "$$AILUROS_IT_MODEL" || { echo "usage: make test-integration-model MODEL_URL=<base URL> MODEL=<name> [MODEL_BACKEND=jev|openai] [MODEL_API_KEY=<key>] [MODEL_TIMEOUT=10s]"; exit 2; }
	go test -tags integration -count=1 -timeout 15m -run TestModelProfile -v ./test/integration/

DATASET ?= eval/datasets/sample.jsonl
EVAL_OUT_ORIGIN := $(origin EVAL_OUT)
ifndef EVAL_OUT
EVAL_OUT := bin/eval/$(shell date +%Y%m%d-%H%M%S).jsonl
endif
eval: export AILUROS_CLASSIFIER_BASE_URL = $(value MODEL_URL)
eval: export AILUROS_CLASSIFIER_MODEL = $(value MODEL)
eval: export AILUROS_CLASSIFIER_BACKEND = $(or $(value MODEL_BACKEND),jev)
ifdef MODEL_API_KEY
eval: export AILUROS_CLASSIFIER_API_KEY = $(value MODEL_API_KEY)
endif
eval: export AILUROS_CLASSIFIER_TIMEOUT = $(or $(value MODEL_TIMEOUT),10s)
eval: build
	@test -n "$$AILUROS_CLASSIFIER_BASE_URL" -a -n "$$AILUROS_CLASSIFIER_MODEL" || { echo "usage: make eval MODEL_URL=<base URL> MODEL=<name> [DATASET=<file>] [MODEL_BACKEND=jev|openai] [MODEL_API_KEY=<key>] [MODEL_TIMEOUT=10s] [SAMPLE=N] [CONCURRENCY=N] [EVAL_OUT=<file> RESUME=1]"; exit 2; }
	@test -z "$(RESUME)" -o "$(EVAL_OUT_ORIGIN)" != undefined || { echo "RESUME=1 needs EVAL_OUT=<results file> to continue; without it a new run would start"; exit 2; }
	bin/ailuros-eval run --dataset "$(DATASET)" --out "$(EVAL_OUT)" --concurrency $(or $(CONCURRENCY),1) $(if $(SAMPLE),--sample $(SAMPLE)) $(if $(RESUME),--resume)
	bin/ailuros-eval report "$(EVAL_OUT)"

validate-k8s:
	go test -count=1 -v ./test/k8sconfig/

test-k8s:
	go test -tags k8s -count=1 -timeout 30m -v ./test/integration/ $(if $(KEEP),-args -keep)
