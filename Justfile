set dotenv-load := true

default:
    @just --list

# === BUILD === #

[group('build')]
build *args:
    cargo build --release {{ args }}

[group('build')]
build-debug *args:
    cargo build {{ args }}

# === RUN === #

[group('run')]
example name *args:
    cargo run --example {{ name }} {{ args }}

# === CHECK === #

[group('check')]
check: check-rust check-just

[group('check')]
[group('rust')]
check-rust:
    cargo check --all-targets --all-features

[group('check')]
[group('just')]
check-just:
    #!/usr/bin/env sh
    for file in $(find . -name "Justfile"); do
      just --unstable --fmt --check --justfile "$file"
    done

# === FORMAT === #

alias fmt := format

[group('format')]
fix: format lint-fix

[group('format')]
format: format-rust format-just

[group('format')]
[group('rust')]
format-rust *args:
    cargo fmt --all {{ args }}

[group('format')]
[group('just')]
format-just:
    #!/usr/bin/env sh
    for file in $(find . -name "Justfile"); do
      just --unstable --fmt --justfile "$file"
    done

# === LINT === #

[group('lint')]
lint:
    cargo clippy --workspace --all-targets --all-features

[group('lint')]
lint-fix:
    cargo clippy --workspace --all-targets --all-features --fix --allow-dirty --allow-staged

# === TEST === #

[group('test')]
test *args: test-docs
    cargo nextest run --all-targets --all-features {{ args }}

test-docs *args:
    cargo test --doc

# === DOCS === #

[group('docs')]
docs *args:
    cargo doc

[group('docs')]
docs-serve:
    devd -l target/doc
