.PHONY: tidy build test nats up up-catch run build-hardened version caught release sbom loc doctor status console demo quickstart catch verify-catch

VERSION ?= $(shell cat VERSION 2>/dev/null || echo 2.0.0)
LDFLAGS := -s -w -X main.version=$(VERSION)

tidy:
	go mod tidy

build:
	go build -ldflags="$(LDFLAGS)" -o bin/atde$(shell go env GOEXE) ./cmd/atde

test:
	go test ./...

bench:
	go test ./internal/ingest/rules ./internal/catch ./internal/disrupt/edge ./internal/ingest/honeypot -bench=. -benchmem

nats:
	docker compose -f deployments/docker-compose.yml up -d nats

up:
	docker compose -f deployments/docker-compose.yml up -d --build

up-catch catch:
	docker compose -f deployments/catch-node.yml up -d --build

run:
	go run -ldflags="$(LDFLAGS)" ./cmd/atde -config configs/config.yaml -mode catch-node

caught:
	go run ./cmd/atde -mode caught

doctor:
	go run ./cmd/atde -config configs/config.yaml -mode doctor

status:
	go run ./cmd/atde -config configs/config.yaml -mode status

console:
	@echo Open http://127.0.0.1:9091/console  (ATDE must be running)

demo:
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts/demo-honeypot.ps1 || bash scripts/demo-honeypot.sh

verify-catch:
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify-catch.ps1 || bash scripts/verify-catch.sh

quickstart:
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts/quickstart.ps1 || bash scripts/quickstart.sh

version:
	@echo $(VERSION)

build-hardened:
	bash scripts/build-hardened.sh

sbom:
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts/sbom.ps1 || bash scripts/sbom.sh

loc:
	@powershell -NoProfile -Command "(Get-ChildItem -Recurse -Filter *.go | Where-Object { \$$_.FullName -notmatch '\\\\vendor\\\\' } | Get-Content | Measure-Object -Line).Lines"

release: test build sbom
	@echo "Built ATDE $(VERSION) -> bin/ + dist/sbom-lite.txt"
