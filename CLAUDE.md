# CLAUDE.md — petriage development notes

## Project overview

petriage is a cross-platform PE file surface analysis CLI/GUI tool written in Rust.
Binary name: `petriage`. Crate name: `petriage`.

## Build & test commands

```bash
cargo build                      # CLI only
cargo build --features gui       # CLI + GUI
cargo build --features tui       # CLI + TUI hex viewer
cargo test --quiet               # Run all tests (CLI)
cargo test --quiet --all-features # Run all tests including GUI/TUI
```

## Architecture

```
src/
  main.rs           # CLI entry, clap args, batch/fail-on logic
  analysis.rs       # All PE analysis (headers, imports, hashes, imphash, anomalies, etc.)
  output.rs         # format_text / format_json / format_ndjson
  gui/mod.rs        # egui GUI (feature-gated)
  gui/app_state.rs  # GUI state
  gui/panels/       # GUI tab panels
  tui.rs            # ratatui hex viewer (feature-gated)
tests/
  malformed.rs      # Integration tests (39 tests as of 79f22ca)
```

## Key conventions

- `AnalysisOptions` controls what to parse; `show_all` gates rich_header/tls/debug
- Exit codes: 0=success, 1=input error, 2=output error, 3=--fail-on threshold exceeded
- JSON error output goes to stderr: `{"error": "message"}`
- Tests use synthetic PE byte arrays (no external fixtures)
- Helper `build_minimal_pe_with_cert_dd()` is the base PE builder for tests
- Commit messages: imperative mood, Co-Authored-By trailer

## Known issues / TODO

- **Load Config Directory**: Not yet implemented (listed in feature_scope.md v0.2).

- **Authenticode trust verification**: Signature parsing works but chain validation
  against a root store is not performed. `trust_verified` is always `false`.

- **Authenticode dual-signing**: Only the first WIN_CERTIFICATE and first SignerInfo
  are processed.

## Recently completed

### Clippy / metadata cleanup (2026-03-01)

- All 40 clippy warnings resolved (0 warnings on `cargo clippy --all-features`)
- Cargo.toml: added `repository`, `homepage`, `documentation` for crate publish readiness
- `AppState::Loaded::result` boxed (`Box<AnalysisResult>`) to fix large_enum_variant
- `IconGroup`, `IconImage`, `ResourceInfo::icon_data` — `#[allow(dead_code)]` (GUI-only fields)
- `parse_resource_directory` — `#[allow(clippy::too_many_arguments)]`

### 79f22ca (2026-02-24)

- imphash (Mandiant-compatible)
- `--batch <dir>`, `--ndjson`, `--fail-on <severity>`
- `-H` filter regression fix (rich_header/tls/debug gated behind show_all)
- `--batch` + `-o` output file support
- 3 GUI panel files tracked (debug, rich_header, tls)
