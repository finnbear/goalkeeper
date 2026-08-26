.PHONY: ddos test lint

ddos:
	cargo run --example ddos --features web_socket

test:
	cargo test --all-features

lint:
	cargo fmt --check
	cargo clippy --all-targets --all-features
