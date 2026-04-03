.PHONY: build run test test-integration lint clean generate migrate image validate-boot deploy smoke-test seed-apikey up down ci

# Binary names
CONTROLPLANE_BIN := bin/controlplane
VMD_BIN := bin/vmd
SEED_APIKEY_BIN := bin/seed-apikey
BOXD_BIN := bin/boxd

# Go build flags
LDFLAGS := -ldflags "-s -w"

## Build

build: build-controlplane build-vmd build-seed-apikey build-boxd

build-controlplane:
	go build $(LDFLAGS) -o $(CONTROLPLANE_BIN) ./cmd/controlplane

build-vmd:
	go build $(LDFLAGS) -o $(VMD_BIN) ./cmd/vmd

build-seed-apikey:
	go build $(LDFLAGS) -o $(SEED_APIKEY_BIN) ./cmd/seed-apikey

build-boxd:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BOXD_BIN) ./cmd/boxd

## Run

run-controlplane:
	go run ./cmd/controlplane

run-vmd:
	go run ./cmd/vmd

## Code generation

generate: generate-sqlc generate-proto

generate-sqlc:
	sqlc generate

generate-proto:
	protoc --go_out=. --go_opt=module=github.com/superserve-ai/sandbox \
		--go-grpc_out=. --go-grpc_opt=module=github.com/superserve-ai/sandbox \
		proto/*.proto

## Database (migrations run automatically on controlplane startup)

migrate-up:
	psql "$(DATABASE_URL)" -f db/migrations/001_initial.sql
	psql "$(DATABASE_URL)" -f db/migrations/002_add_stopped_status.sql

seed-apikey:
	go run ./cmd/seed-apikey

## Docker

up:
	docker compose up -d --build

down:
	docker compose down

## VM Image

image:
	cd images/base && ./build.sh

## Validate

validate-boot:
	cd images/base && sudo ./validate-boot.sh

## Test

test:
	go test ./... -v -count=1

test-short:
	go test ./... -short -count=1

test-integration:
	go test -tags integration ./internal/integration/ -v -count=1 -timeout 10m

## Lint

lint:
	golangci-lint run ./...

## Deploy

deploy:
	bash deploy/deploy.sh

smoke-test:
	bash deploy/smoke-test.sh

## CI (runs all checks locally)

ci: lint test build

## Clean

clean:
	rm -rf bin/
	rm -rf images/base/output/
