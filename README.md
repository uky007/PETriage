# readpe

A fast, cross-platform PE (Portable Executable) file surface analysis tool with CLI and GUI, written in Rust.

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
| Imports | DLL names and imported function names with suspicious API indicators |
| Exports | Exported function names, ordinals, RVAs |
| Strings | ASCII and UTF-16LE extraction with configurable minimum length |
| Hashes | MD5, SHA1, SHA256 of the entire file |
| Overlay | Detection of data appended beyond the PE structure |
| Suspicious API Indicators | Auto-tags ~130 Windows APIs across 12 risk categories (Process Injection, Code Execution, Network, Evasion, etc.) with severity levels (high/medium/low) |
| Anomaly Detection | 18 heuristic rules detecting packing indicators, W^X violations, missing security features (ASLR/DEP/CFG), timestamp anomalies, structural irregularities, and suspicious API combos |
| Resource Directory | Resource tree enumeration, VS_VERSIONINFO parsing (FileVersion, CompanyName, OriginalFilename, etc.), manifest extraction (UAC requestedExecutionLevel), embedded icon extraction and display (GUI) |
| Output | Human-readable tables (default) or JSON (`--json`), file output (`-o`) |
| GUI | egui-based GUI with tabbed views, drag & drop, filters, entropy color-coding, suspicious API highlighting, embedded icon display (opt-in via `--features gui`) |

## Installation

### Build from source (CLI only)

```
git clone https://github.com/uky007/readpe.git
cd readpe
cargo build --release
```

The binary will be at `target/release/readpe`.

### Build with GUI

```
cargo build --release --features gui
```

GUI requires system libraries for the graphics backend (OpenGL/Vulkan). On Debian/Ubuntu:

```
sudo apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev libgtk-3-dev
```

### Cross-compilation

```
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-pc-windows-gnu
```

## Usage

### CLI

```
readpe <file.exe>              # Show all information
readpe <file.exe> -H           # Headers only
readpe <file.exe> -i           # Imports only
readpe <file.exe> -s           # Sections only
readpe <file.exe> -S           # Strings only
readpe <file.exe> --hashes     # File hashes only
readpe <file.exe> -r           # Resources only
readpe <file.exe> --json       # JSON output
readpe <file.exe> --json | jq '.suspicious_summary'              # Suspicious API summary
readpe <file.exe> --json | jq '.imports[].functions[] | select(.risk != null)'  # Risky APIs only
readpe <file.exe> --json | jq '.anomalies'                      # All anomalies
readpe <file.exe> --json | jq '.anomalies[] | select(.severity == "critical")'  # Critical anomalies only
readpe <file.exe> --json | jq '.resources'                                     # Resources
readpe <file.exe> --json | jq '.resources.version_info'                        # Version info
readpe <file.exe> --json | jq '.resources.manifest'                            # Manifest XML
readpe <file.exe> -o report.txt  # Write to file
```

### GUI (requires `--features gui` build)

```
readpe --gui                   # Open with file dialog
readpe --gui <file.exe>        # Open file directly in GUI
```

The GUI provides:

- **Tabbed interface** — File Info, Headers, Sections, Imports, Exports, Strings, Overlay, Resources
- **Drag & drop** — Drop PE files onto the window to analyze
- **Left sidebar** — Toggle analysis options and re-analyze without restarting
- **Import filter** — Search API names across DLLs, "Suspicious only" toggle to surface risky APIs
- **String filter** — Filter by text and encoding (ASCII / UTF-16)
- **Entropy color-coding** — Section entropy highlighted green (<6) / yellow (6–7) / red (7–8)
- **Suspicious API indicators** — Color-coded severity badges (red/yellow/cyan) on File Info and Imports tabs
- **Embedded icon display** — Extracts and renders PE embedded icons (RT_GROUP_ICON / RT_ICON); primary icon shown on File Info tab, all icon groups on Resources tab. Useful for identifying malware impersonating legitimate software
- **Hash copy buttons** — One-click copy of MD5/SHA1/SHA256
- **Virtual scroll** — Handles tens of thousands of strings without lag

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

=== Imports (4 DLLs, 32 functions) ===
  KERNEL32.dll (18 functions)
    - CreateProcessW [HIGH] Code Execution
    - VirtualAllocEx [HIGH] Process Injection
    - WriteProcessMemory [HIGH] Process Injection
    - VirtualProtect [HIGH] Evasion
    - GetComputerNameA [MED] Info Gathering
    - CreateFileA [LOW] File / Registry
    - ReadFile
    - CloseHandle [LOW] Anti-Debug
    ...

=== Suspicious API Summary ===
  Total suspicious APIs: 14
  HIGH: 6 MEDIUM: 5 LOW: 3

  Category                 Count
  ------------------------ -----
  Process Injection            3
  Code Execution               2
  Network                      2
  ...

=== Anomaly Detection ===
  CRITICAL: 2 WARNING: 5 INFO: 3

  [CRITICAL] Code Integrity: Section '.xpack' is both writable and executable (W^X violation)
  [CRITICAL] Suspicious Combo: Process Injection + Evasion APIs both present — possible code injection technique
  [WARNING] Packing: Executable section '.text' has high entropy (6.8921)
  [WARNING] Security: ASLR (DYNAMIC_BASE) is disabled
  [WARNING] Security: DEP (NX_COMPAT) is disabled
  [WARNING] Timestamp: Timestamp (1998-03-15 00:00:00 UTC) is before year 2000 — possible forgery
  [WARNING] Structure: Overlay data detected (4096 bytes at offset 0x12000)
  [INFO] Security: Control Flow Guard (GUARD_CF) is not enabled
  [INFO] Structure: Non-standard section name '.xpack'
  ...

=== Resources (12 entries) ===
  Version Info:
    FileVersion:    10.0.19041.1
    ProductVersion: 10.0.19041.1
    FileType:       Application (1)
    FileOS:         0x40004
    FileFlags:      0x0
    String Info:
      CompanyName:             Microsoft Corporation
      FileDescription:         Windows Notepad
      OriginalFilename:        NOTEPAD.EXE

  Manifest:
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
      <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
          <requestedPrivileges>
            <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
          </requestedPrivileges>
        </security>
      </trustInfo>
    </assembly>

  Type                 Name             Language       Size          RVA
  -------------------- ---------------- ---------- -------- ------------
  RT_ICON              #1               en-US          1128 0x00003a000
  RT_VERSION           #1               en-US           836 0x00003c000
  RT_MANIFEST          #1               en-US           522 0x00003d000
  ...
```

## Roadmap

- **v0.2**: Rich header, TLS/Debug directories
- **v0.3**: .NET metadata, Authenticode signatures, packer detection, entropy histogram
- **Future**: ELF format support

## License

Apache-2.0
