# readpe

A fast, cross-platform CLI tool for PE (Portable Executable) file surface analysis, written in Rust.

## Motivation

Malware analysts frequently examine Windows PE files, but the most capable surface analysis tools -- PEStudio and CFF Explorer -- only run on Windows. This forces analysts to maintain Windows VMs just for static triage, even when execution is unnecessary. Cross-platform alternatives are either GUI-only (PE-bear, XPEViewer), Python-based and slow (pefile, peframe), or unmaintained CLI tools with limited features (pev/readpe in C).

**readpe** fills this gap: a single compiled binary that runs natively on Linux, macOS, and Windows, providing comprehensive PE surface analysis from the command line with zero runtime dependencies.

## Concept

- **No execution** -- Pure static/surface analysis. The PE is never loaded or executed, making it safe for malware triage.
- **All-in-one** -- Consolidates the features analysts typically need multiple tools for (headers, imports, strings, hashes, entropy) into one command.
- **Fast** -- Native Rust binary. Processes files in milliseconds, suitable for batch analysis of large sample sets.
- **Composable** -- JSON output (`--json`) enables piping to `jq`, integration with SIEMs, and scripting in automation pipelines.
- **Offline** -- No network calls. No VirusTotal lookups, no update checks. Fully air-gapped friendly.

## Features

| Feature | Description |
|---------|-------------|
| DOS Header | `e_magic`, `e_lfanew` |
| COFF Header | Machine type, timestamp, characteristics |
| Optional Header | Magic, entry point, image base, subsystem, DLL characteristics, data directories |
| Sections | Name, virtual/raw size and address, characteristics, Shannon entropy |
| Imports | DLL names and imported function names |
| Exports | Exported function names, ordinals, RVAs |
| Strings | ASCII and UTF-16LE extraction with configurable minimum length |
| Hashes | MD5, SHA1, SHA256 of the entire file |
| Overlay | Detection of data appended beyond the PE structure |
| Output | Human-readable tables (default) or JSON (`--json`), file output (`-o`) |

## Installation

### Build from source

```
git clone https://github.com/uky007/readpe.git
cd readpe
cargo build --release
```

The binary will be at `target/release/readpe`.

### Cross-compilation

```
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-pc-windows-gnu
```

## Usage

```
readpe <file.exe>              # Show all information
readpe <file.exe> -H           # Headers only
readpe <file.exe> -i           # Imports only
readpe <file.exe> -s           # Sections only
readpe <file.exe> -S           # Strings only
readpe <file.exe> --hashes     # File hashes only
readpe <file.exe> --json       # JSON output
readpe <file.exe> -o report.txt  # Write to file
```

### Example output

```
=== File Info ===
  File:    sample.exe
  Size:    72704 bytes (71.00 KB)
  Type:    PE32 (32-bit)

=== Hashes ===
  MD5:     a1b2c3d4e5f6...
  SHA1:    1234567890ab...
  SHA256:  abcdef012345...

=== COFF Header ===
  Machine:              IMAGE_FILE_MACHINE_I386 (x86) (0x014c)
  NumberOfSections:     5
  TimeDateStamp:        0x65a1b2c3 (2024-01-12 15:30:27 UTC)
  Characteristics:      0x0102
                        - EXECUTABLE_IMAGE
                        - 32BIT_MACHINE

=== Sections (5) ===
  Name         VirtSize     VirtAddr    RawSize      RawAddr  Entropy Characteristics
  .text      0x00008a00 0x0000001000 0x00008c00 0x0000000400  6.4521 CODE | EXECUTE | READ
  .rdata     0x00002600 0x000000a000 0x00002800 0x0000009000  5.1032 INITIALIZED_DATA | READ
  ...
```

## Roadmap

- **v0.2**: Resource directory, Rich header, TLS/Debug directories, suspicious API indicators, anomaly detection
- **v0.3**: .NET metadata, Authenticode signatures, packer detection, entropy histogram
- **Future**: GUI frontend, ELF format support

## License

MIT
