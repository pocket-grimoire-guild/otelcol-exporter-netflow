SHELL := /usr/bin/env bash

.PHONY: all check test go-test fmt lint docs shellcheck validate-config fuzz-seeds

all: check test

check: fmt lint docs shellcheck validate-config fuzz-seeds

test: go-test

go-test:
	go test ./...

fmt:
	@files="$$(gofmt -l .)"; \
	if [[ -n "$$files" ]]; then \
		echo "gofmt required:" >&2; echo "$$files" >&2; exit 1; \
	fi

lint:
	go vet ./...

docs:
	python3 scripts/check-docs.py

shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck is required" >&2; exit 1; }
	@find scripts distribution integration \
		-type f -name '*.sh' -print0 | \
		xargs -0 shellcheck -x -P SCRIPTDIR

validate-config:
	python3 scripts/validate-config.py

fuzz-seeds:
	python3 scripts/check-fuzz-manifest.py
