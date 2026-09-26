.PHONY: build test vet fmt e2e clean help

help:
	@echo "FlowSight build targets:"
	@echo "  build      Build the daemon and tools"
	@echo "  test       Run Go tests"
	@echo "  vet        Run go vet"
	@echo "  fmt        Run gofmt (check only)"
	@echo "  e2e        Run end-to-end regression tests"
	@echo "  measure    Measure performance at three scales"
	@echo "  clean      Remove build artifacts"

build:
	go build ./...
	go build -o bin/flowsightd ./cmd/flowsightd
	go build -o bin/fsload ./cmd/fsload
	go build -o bin/fsbench ./cmd/fsbench

test:
	go test ./...
	sh web/uitest/run.sh

vet:
	go vet ./...
	gofmt -l ./cmd ./internal

fmt:
	gofmt -w ./cmd ./internal ./web

e2e:
	bash test/e2e/run.sh

measure:
	sh test/e2e/measure.sh

clean:
	rm -rf bin/
	go clean -cache
