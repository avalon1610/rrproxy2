# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

rrproxy2 is a Rust HTTP/HTTPS proxy that forwards traffic through encrypted tunnels. It splits request bodies into randomly-sized encrypted chunks (ChaCha20-Poly1305) to bypass network restrictions and DPI. Two components: **local proxy** (client-side, intercepts + chunks + encrypts) and **remote proxy** (server-side, reassembles + forwards).

## Build & Run Commands

```bash
# Build
cargo build                    # debug build
cargo build -r                 # release build

# Test
cargo test                     # run all tests
cargo test <test_name>         # run a single test

# Dev (via justfile)
just debug_local               # run local proxy on 0.0.0.0:8080 (alias: just dl)
just debug_remote              # run remote proxy on 0.0.0.0:8081 (alias: just dr)

# Release builds
just release_windows           # cross-compile for Windows via cargo-xwin (alias: just rw)
just release_musl              # static Linux binary (alias: just rm)
just release                   # build all targets + zip (alias: just r)
```

## Architecture

### Core Trait

`Proxy` trait (`src/proxy.rs`) — defines `new()`, `listen_addr()`, `handler()`, and a default `serve()` that runs a Hyper server with auto HTTP/1 + HTTP/2 support. Both `LocalProxy` and `RemoteProxy` implement this trait.

### Data Flow

1. Client → LocalProxy: intercepts HTTP/HTTPS (TLS MITM with dynamic certs)
2. LocalProxy chunks body into random sizes (50-100% of `--chunk` size), encrypts each chunk, sends as separate POST requests to RemoteProxy
3. RemoteProxy receives chunks, tracks them via transaction ID + chunk index, reassembles when complete
4. RemoteProxy forwards reconstructed request to destination, encrypts response back

### Module Map

- `src/main.rs` — CLI entry point, dispatches to local/remote based on subcommand
- `src/options.rs` — clap CLI definitions (`LocalModeOptions`, `RemoteModeOptions`)
- `src/proxy.rs` — `Proxy` trait + custom header constants (`X-Request-Id`, `X-Fetch-Id`, etc.)
- `src/crypto.rs` — `Cipher` struct: ChaCha20-Poly1305 with BLAKE3 key derivation, random 12-byte nonce prepended to ciphertext
- `src/convert.rs` — reqwest↔hyper response conversion, `CipherHelper` trait for encrypt/decrypt, hop-by-hop header removal
- `src/header.rs` — header name/value obfuscation (bidirectional mapping)
- `src/local.rs` — LocalProxy implementation
  - `local/forward.rs` — chunk splitting, concurrent sending via `FuturesUnordered`
  - `local/tls.rs` — TLS interception (CONNECT handling)
  - `local/cert.rs` — dynamic cert generation with LRU cache (max 2048)
  - `local/bypass.rs` — CIDR/domain bypass rules
  - `local/buf.rs` — TLS buffer management
- `src/remote.rs` — RemoteProxy implementation
  - `remote/transaction.rs` — chunk assembly state machine (`Pending` → `Committed`), BTreeMap for ordered reassembly
  - `remote/info.rs` — decrypt/parse request metadata from headers

### Key Patterns

- Shared state via `Arc<Mutex<T>>` (transaction map, cert cache)
- `anyhow::Result` throughout for error handling
- Encryption overhead accounted for in chunk size calculation: 12 (nonce) + 16 (auth tag) + associated data length, adjusted for base64 encoding
- Custom headers disguised as common HTTP headers (e.g., `X-Referer` carries encrypted original URL)
- Structured logging via `tracing` crate, file output to `*_proxy_logs/` directories
- External `misc` crate (git dep) provides `TracingLogger`

## Rust Edition

Uses Rust edition **2024** — be aware of edition-specific changes (e.g., `gen` is a reserved keyword).
