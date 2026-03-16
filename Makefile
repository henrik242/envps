OS := $(shell uname)

ifeq ($(OS),Darwin)
envps:
	cargo build --release --target aarch64-apple-darwin
	cargo build --release --target x86_64-apple-darwin
	lipo -create \
		target/aarch64-apple-darwin/release/envps \
		target/x86_64-apple-darwin/release/envps \
		-output envps
else ifeq ($(OS),Linux)
envps:
	cargo build --release --target x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/release/envps envps
else ifeq ($(OS),FreeBSD)
envps:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release
	cp target/release/envps envps
else ifeq ($(OS),NetBSD)
envps:
	cargo build --release
	cp target/release/envps envps
else
envps:
	@echo "Unsupported OS: $(OS)"
	@exit 1
endif

clean:
	cargo clean
	rm -f envps

.PHONY: envps clean
