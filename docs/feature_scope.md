# petriage Feature Scope

## MVP (v0.1) — Must Have

These features are the minimum for a useful surface analysis tool. Every serious PE analysis tool provides these, and without them petriage would not be competitive.

1. **File Info**: file size, file type detection, file hashes (MD5, SHA1, SHA256, imphash) — **implemented**
   - imphash: Mandiant-compatible import hash (DLL name normalization, `.dll`/`.ocx`/`.sys` extension removal, ordinal fallback) — **implemented**
2. **DOS Header**: e_magic, e_lfanew — **implemented** (minimal fields, not full 64-byte DOS header)
3. **PE Signature**: PE signature validation ("PE\0\0") — **implemented** (via goblin)
4. **COFF/File Header**: machine type, number of sections, timestamp, characteristics — **implemented**
5. **Optional Header**: magic (PE32/PE32+), entry point, image base, subsystem, DLL characteristics, data directory count — **implemented**
6. **Data Directories**: list all 16 data directories with RVA and size — **implemented**
7. **Section Headers**: name, virtual/raw size, virtual/raw address, characteristics, per-section entropy — **implemented**
8. **Import Table**: DLL names and imported function names (by name) — **implemented**
   - Note: import by ordinal display is deferred to goblin's output
9. **Export Table**: exported function names, ordinals, RVAs — **implemented** (ordinal_base correction applied)
   - Note: forwarded exports detection is **not yet implemented**
10. **Strings**: ASCII and UTF-16LE string extraction (configurable min length, default 4, max 100K strings) — **implemented**
11. **Overlay Detection**: detect data appended after the last section (offset and size) — **implemented**
12. **Output Formats**: human-readable table output (default) + JSON output (`--json`) + NDJSON output (`--ndjson`) + file output (`-o`) — **implemented**
    - `--batch <dir>`: Batch-analyze all PE files in a directory — **implemented**
    - `--ndjson`: Newline-delimited JSON (one JSON object per line, ideal for streaming/piping) — **implemented**
    - `--fail-on <severity>`: Exit with code 3 if any anomaly meets or exceeds the given severity (critical/warning/info) — **implemented**

## v0.2 — Important

These features differentiate a good tool from a basic one. PEStudio, PE-bear, and PPEE all provide these.

13. **Resource Directory**: resource tree parsing (types, names, languages, sizes), VS_VERSIONINFO parsing, manifest extraction, embedded icon extraction (RT_GROUP_ICON / RT_ICON → ICO reconstruction) and GUI display — **implemented**
14. **Rich Header**: parsing, XOR key extraction, compiler/linker tool entries (comp.id, product.id, count), Rich Hash (MD5, YARA/VirusTotal compatible), checksum verification (tampering detection), Product ID database (~70 entries, VS 6.0–2022), comp_id hex display — **implemented**
15. **TLS Directory**: TLS callback detection (critical for malware — callbacks run before main), PE32/PE32+ support, callback VA listing — **implemented**
16. **Debug Directory**: PDB path, debug type (CodeView, COFF, etc.), GUID, age. PDB paths are always parsed (not gated by `--all`) and surfaced as OPSEC indicators in CLI (yellow highlight + dedicated section) and GUI (orange badge on Debug/File Info tabs) — **implemented**
17. **Suspicious API Indicators**: ~130 APIs across 12 categories with 3-level severity (high/medium/low), CLI color-coding, GUI filtering — **implemented**
18. **Anomaly Detection**: 31 deterministic rules (22 anomaly + 9 OPSEC) with `rule_id`/`evidence`/`threshold` for JSON traceability. Covers packing (entropy, W^X, expansion ratio), security features (ASLR/DEP/CFG/SEH), timestamp anomalies, structural issues, suspicious API combos, OPSEC indicators (OPSEC-001: PDB path leakage), and Rich Header integrity (RICH-001: checksum tampering, RICH-002: missing Rich Header). All arithmetic uses checked/float operations to prevent overflow panics on crafted PEs. Full rule table: [anomaly_rules.md](anomaly_rules.md) — **implemented**
19. **PE Header Editor (GUI)**: CFF Explorer-style header editing in the Editor tab. Editable fields: COFF header (TimeDateStamp, Characteristics with flag checkboxes), Optional header (AddressOfEntryPoint, ImageBase PE32/PE32+, SectionAlignment, FileAlignment, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics with 7 individual flag checkboxes), Section headers (Name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, Characteristics with flag checkboxes). Modified fields highlighted, pending edits tracked, Save As writes patched PE. Boundary-checked: truncated optional headers show error instead of editable fields; OOB edits skipped on save; no-op edits are not tracked — **implemented**
20. **Load Config Directory**: SEH handler table, CFG function table, guard flags — **not yet implemented**
21. **TUI Hex Viewer**: interactive terminal hex viewer with PE region navigation, alternate screen mode (`--features tui`, `-x`/`--view` flag) — **implemented**
22. **Authenticode**: digital signature presence detection, PKCS#7/CMS parsing, X.509 certificate chain extraction (subject, issuer, serial, validity, SHA-1 thumbprint), signer identification, expiry/self-signed/chain warnings (`-c`/`--authenticode`, GUI "Signing" tab) — **implemented**

## v0.3 — Advanced

These features make petriage a comprehensive professional-grade tool.

23. **.NET Metadata**: CLR header, metadata tables, streams, managed entry point
24. **Bound/Delay Imports**: parsing and display
25. **Relocation Table**: parsing (base relocation entries)
26. **Entropy Histogram**: per-section and overall entropy with visual bar chart in terminal
27. **Packer Detection**: signature-based packer/compiler identification (PEiD-compatible signatures)
28. **Exception Directory**: exception handler table (x64)

## Technical Approach

### Rust Crate Selection

| Crate | Purpose | Justification |
|-------|---------|---------------|
| **goblin** | Primary PE parser | Best-maintained Rust PE library; handles headers, sections, imports, exports; fuzz-tested against 100M+ inputs |
| **clap** | CLI argument parsing | Industry standard for Rust CLIs; derive macro for clean code |
| **md-5, sha1, sha2** | Hash computation | Standard RustCrypto crates |
| **serde + serde_json** | JSON output | De facto Rust serialization |
| **image** | ICO/PNG/BMP decoding for icon display (GUI only) | Standard Rust image library; optional dependency gated behind `gui` feature |
| **ratatui** | TUI hex viewer (optional, `tui` feature) | Terminal UI framework; alternate screen mode for interactive PE browsing |
| **crossterm** | Terminal I/O for TUI (optional, `tui` feature) | Cross-platform terminal manipulation |
| **cms** | PKCS#7/CMS SignedData parsing for Authenticode | Standard RustCrypto crate for CMS/PKCS#7 |
| **x509-cert** | X.509 certificate parsing | Standard RustCrypto crate for X.509 |
| **der** | ASN.1 DER encoding/decoding | Required by cms and x509-cert |
| **const-oid** | OID constants (e.g., CN = 2.5.4.3) | Required for X.509 attribute extraction |
| Manual parsing | Rich header, TLS, debug, resources, overlay | goblin doesn't expose these; straightforward to parse from raw bytes |

**Why goblin over pelite?** goblin is more actively maintained (recent releases, larger community), handles both PE32 and PE32+ uniformly, and is heavily fuzz-tested. pelite has deeper PE coverage but slower release cadence. We supplement goblin's gaps with targeted manual parsing rather than pulling in a second full PE library.

### Architecture

```
petriage <file> [OPTIONS]

Options:
  -a, --all              Show all information (default)
  -H, --headers          Show headers only (DOS + COFF + Optional)
  -i, --imports          Show imports
  -e, --exports          Show exports
  -s, --sections         Show sections
  -S, --strings          Show strings
  -r, --resources        Show resources
  -c, --authenticode     Show Authenticode/code signing info
  --hashes               Show file hashes
  --overlay              Show overlay information
  --json                 Output as JSON
  --min-str-len <N>      Minimum string length (default: 4)
  -o, --output <FILE>    Write output to file
  -x, --view             Launch TUI hex viewer (--features tui)
  (GUI is a separate binary: petriage-gui)
  -h, --help             Print help
  -V, --version          Print version
```

### Module Structure (actual)

```
src/
  main.rs           # CLI entry point, argument parsing, exit code contract
  rich_db.rs        # Rich Header Product ID database (~70 entries, VS 6.0–2022)
  analysis.rs       # All PE analysis logic in one module:
                    #   headers, sections, imports, exports, strings,
                    #   hashes, entropy, overlay, resources (tree/version/manifest/icons),
                    #   suspicious API indicators (~130 APIs, 12 categories),
                    #   anomaly detection (31 rules with rule_id/evidence/threshold),
                    #   authenticode (PKCS#7/CMS + X.509 certificate chain)
  output.rs         # Human-readable and JSON formatting
  gui/mod.rs        # egui GUI entry point (optional, --features gui)
  gui/app_state.rs  # GUI application state
  gui/panels/       # GUI tab panels (file_info, headers, sections, imports, ..., authenticode, editor)
  tui.rs            # ratatui TUI hex viewer (optional, --features tui)
```

> Note: The original plan split logic across multiple files (strings.rs, hashes.rs, etc.) but the actual implementation consolidates everything in `analysis.rs` for simplicity. This may be refactored as the codebase grows.

### Cross-Compilation

Rust's cross-compilation support enables single-binary distribution:
- `cargo build --target x86_64-unknown-linux-gnu`
- `cargo build --target aarch64-unknown-linux-gnu`
- `cargo build --target x86_64-apple-darwin`
- `cargo build --target aarch64-apple-darwin`
- `cargo build --target x86_64-pc-windows-gnu`

All targets produce static binaries with zero runtime dependencies.

### Design Principles

1. **No execution**: petriage never executes or loads the PE — pure static/surface analysis
2. **Robust parsing**: Handle malformed and truncated PEs gracefully (common in malware)
3. **Fast**: Process files in milliseconds, suitable for batch analysis of thousands of samples
4. **Offline**: No network calls by default (no VirusTotal, no update checks)
5. **Composable**: JSON output enables piping to jq, integration with SIEM, etc.