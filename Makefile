.PHONY: build test lint doctor

PYTHON := .venv/bin/python
export GOCACHE := $(CURDIR)/.cache/go-build

build:
	@mkdir -p bin
	go build -C engine -o ../bin/daysra-engine ./cmd/daysra-engine

test:
	go test -C engine ./...
	PYTHONPATH=src $(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check src tests
	go vet -C engine ./...
	@unformatted="$$(gofmt -l engine)"; \
	if [ -n "$$unformatted" ]; then \
		printf '%s\n' "$$unformatted"; \
		exit 1; \
	fi

doctor: build
	PYTHONPATH=src $(PYTHON) -m daysra doctor

