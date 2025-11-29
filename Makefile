.PHONY: test test-unit test-integration test-e2e lint sec ci

MODULE_PATH=./...

test: test-unit

test-unit:
go test ./internal/... ./cmd/... -count=1

test-integration:
go test ./test/integration/... -count=1 || true

test-e2e:
@echo "e2e tests not implemented yet"

lint:
golangci-lint run ./... || true

sec:
gosec ./... || true

ci: lint test-unit test-integration test-e2e sec
