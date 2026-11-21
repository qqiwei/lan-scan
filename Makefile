CARGO ?= cargo

.PHONY: all build release test fmt clippy check install clean

all: test

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test

fmt:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

check: fmt clippy test

install:
	$(CARGO) install --path .

clean:
	$(CARGO) clean
