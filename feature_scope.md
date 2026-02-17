# readpe Feature Scope

## MVP (v0.1) - Must Have

These features are the minimum for a useful surface analysis tool. Every serious PE analysis tool provides these, and without them readpe would not be competitive.

1. **File Info**: file size, file type detection, file hashes (MD5, SHA1, SHA256, imphash)
2. **DOS Header**: full DOS header parsing (e_magic, e_lfanew, all fields)
3. **PE Signature**: PE signature validation ("PE\0\0")
4. **COFF/File Header**: machine type, number of sections, timestamp, characteristics
5. **Optional Header**: magic (PE32/PE32+), entry point, image base, subsystem, DLL characteristics, data directory count
6. **Data Directories**: list all 16 data directories with RVA and size
7. **Section Headers**: name, virtual/raw size, virtual/raw address, characteristics, per-section entropy
8. **Import Table**: DLL names and imported function names (by name and by ordinal)
9. **Export Table**: exported function names, ordinals, forwarded exports
10. **Strings**: ASCII and Unicode string extraction (configurable min length, default 4)
11. **Overlay Detection**: detect data appended after the last section (offset and size)
12. **Output Formats**: human-readable table output (default) + JSON output (`--json`)

## v0.2 - Important

These features differentiate a good tool from a basic one. PEStudio, PE-bear, and PPEE all provide these.

13. **Resource Directory**: resource tree parsing (types, names, languages, sizes)
14. **Rich Header**: parsing, XOR key extraction, compiler/linker tool entries (comp.id, product.id, count)
15. **TLS Directory**: TLS callback detection (critical for malware — callbacks run before main)
16. **Debug Directory**: PDB path, debug type (CodeView, COFF, etc.), GUID, age
17. **Suspicious API Indicators**: flag known suspicious imports (VirtualAlloc, CreateRemoteThread, WriteProcessMemory, NtUnmapViewOfSection, etc.) with risk categorization
18. **Anomaly Detection**: flag structural anomalies (mismatched checksums, suspicious section names, entry point outside code section, zero-size sections, abnormal entropy, etc.)
19. **Load Config Directory**: SEH handler table, CFG function table, guard flags

## v0.3 - Advanced

These features make readpe a comprehensive professional-grade tool.

20. **.NET Metadata**: CLR header, metadata tables, streams, managed entry point
21. **Authenticode**: digital signature parsing and certificate chain extraction (not full verification — that requires Windows CryptoAPI)
22. **Bound/Delay Imports**: parsing and display
23. **Relocation Table**: parsing (base relocation entries)
24. **Entropy Histogram**: per-section and overall entropy with visual bar chart in terminal
25. **Packer Detection**: signature-based packer/compiler identification (PEiD-compatible signatures)
26. **Exception Directory**: exception handler table (x64)
27. **Certificate Table**: raw certificate data extraction

## Technical Approach

### Rust Crate Selection

| Crate | Purpose | Justification |
|-------|---------|---------------|
| **goblin** | Primary PE parser | Best-maintained Rust PE library; handles headers, sections, imports, exports; fuzz-tested against 100M+ inputs |
| **clap** | CLI argument parsing | Industry standard for Rust CLIs; derive macro for clean code |
| **md-5, sha1, sha2** | Hash computation | Standard RustCrypto crates |
| **serde + serde_json** | JSON output | De facto Rust serialization |
| Manual parsing | Rich header, TLS, debug, resources, overlay | goblin doesn't expose these; straightforward to parse from raw bytes |

**Why goblin over pelite?** goblin is more actively maintained (recent releases, larger community), handles both PE32 and PE32+ uniformly, and is heavily fuzz-tested. pelite has deeper PE coverage but slower release cadence. We supplement goblin's gaps with targeted manual parsing rather than pulling in a second full PE library.

### Architecture

```
readpe <file> [OPTIONS]

Options:
  -a, --all           Show all information (default)
  -H, --headers       Show headers only (DOS + COFF + Optional)
  -i, --imports       Show imports
  -e, --exports       Show exports
  -s, --sections      Show sections
  -S, --strings       Show strings
  -r, --resources     Show resources
  --hashes            Show file hashes
  --json              Output as JSON
  --min-length <N>    Minimum string length (default: 4)
  -o, --output <FILE> Write output to file
  -h, --help          Print help
  -V, --version       Print version
```

### Module Structure

```
src/
  main.rs           # CLI entry point and argument parsing
  analysis.rs       # PE analysis logic (headers, sections, dirs)
  strings.rs        # String extraction from raw bytes
  hashes.rs         # File and import hash computation
  entropy.rs        # Shannon entropy calculation
  rich_header.rs    # Rich header parsing (manual)
  resources.rs      # Resource directory parsing (manual)
  overlay.rs        # Overlay detection
  indicators.rs     # Suspicious API flagging
  output.rs         # Human-readable and JSON formatting
```

### Cross-Compilation

Rust's cross-compilation support enables single-binary distribution:
- `cargo build --target x86_64-unknown-linux-gnu`
- `cargo build --target aarch64-unknown-linux-gnu`
- `cargo build --target x86_64-apple-darwin`
- `cargo build --target aarch64-apple-darwin`
- `cargo build --target x86_64-pc-windows-gnu`

All targets produce static binaries with zero runtime dependencies.

### Design Principles

1. **No execution**: readpe never executes or loads the PE — pure static/surface analysis
2. **Robust parsing**: Handle malformed and truncated PEs gracefully (common in malware)
3. **Fast**: Process files in milliseconds, suitable for batch analysis of thousands of samples
4. **Offline**: No network calls by default (no VirusTotal, no update checks)
5. **Composable**: JSON output enables piping to jq, integration with SIEM, etc.
