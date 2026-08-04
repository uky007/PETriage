# PETriage -- Description & Feature List

## Motivation

Before performing deeper analysis such as dynamic analysis or detailed reverse engineering, malware analysts gather surface-level information about a sample -- file structure, packer presence, imported APIs, and metadata -- to determine the best approach for further investigation. This triage stage has well-established tools: PEStudio and CFF Explorer are widely used references, but they are Windows-only graphical applications, unavailable natively on Linux or macOS. Some analysts deliberately run Linux or macOS as their host OS to prevent accidental malware detonation, relegating Windows to a VM guest. In such environments, even a quick triage requires spinning up a guest OS.

Furthermore, existing tools tend to be specialized: Detect It Easy for packer identification, CFF Explorer for header inspection and editing, PEStudio for anomaly indicators -- triaging a single sample often means cycling through multiple applications.

PETriage was built to close these gaps. It runs natively on Windows, Linux, and macOS, supports CLI, TUI, and GUI workflows, and consolidates the core capabilities of multiple triage tools into one: PE header parsing and editing, packer detection, OPSEC mistake identification (such as leaked debug paths), suspicious API flagging, and structured output for automation -- all in a single cross-platform PE surface analysis tool.

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
| Hashes | MD5, SHA1, SHA256 of the entire file, imphash (Mandiant-compatible import hash) |
| Overlay | Detection and classification of data appended beyond the PE structure |
| Suspicious API Indicators | Auto-tags ~180 Windows APIs across 12 risk categories (Process Injection, Code Execution, Network, Evasion, etc.) with severity levels (high/medium/low) |
| Anomaly Detection | 31 deterministic rules (22 anomaly + 9 OPSEC) detecting packing indicators, W^X violations, missing security features (ASLR/DEP/CFG), timestamp anomalies, timestamp correlation, structural irregularities, suspicious API combos, OPSEC indicators (PDB path leakage), and Rich Header integrity (checksum tampering, missing Rich Header). See [anomaly_rules.md](anomaly_rules.md) for the full rule table |
| Resource Directory | Resource tree enumeration, VS_VERSIONINFO parsing (FileVersion, CompanyName, OriginalFilename, etc.), manifest extraction (UAC requestedExecutionLevel), embedded icon extraction and display (GUI) |
| Rich Header | XOR key extraction, Rich Hash (MD5, YARA/VirusTotal compatible), checksum verification (tampering detection), compiler/linker tool entries (comp_id, prod_id, build_id, count) with Product ID database (~70 entries, VS 6.0--2022). Enables compiler identification, build environment fingerprinting, and attribution |
| TLS Directory | TLS callback detection with VA listing. Critical for malware -- TLS callbacks execute before main() and are commonly used for anti-debug/unpacking |
| Debug Directory | Debug entry enumeration, CodeView (RSDS) parsing with PDB path, GUID, and age extraction. PDB paths are always parsed and surfaced as OPSEC indicators (highlighted in CLI and GUI) |
| Authenticode | Digital signature presence detection, PKCS#7/CMS parsing, X.509 certificate chain extraction (subject, issuer, serial, validity, SHA-1 thumbprint), signer identification, expiry/self-signed/chain warnings. Cross-platform -- no Windows CryptoAPI required. Trust verification is not performed. |
| Known Packer Identification | Heuristic identification of known packers (UPX, MPRESS, ASPack, VMProtect, Themida, PECompact, etc.) based on section names, layout, entropy, entry-point characteristics, and related static markers with multi-signal confidence scoring |
| Compiler / Build Fingerprinting | Build-environment hints such as Rich Header-based MSVC attribution and language/toolchain artifacts including Go build information and build IDs, and .NET CLR metadata such as assembly name, version, and references |
| Expanded OPSEC Detection | Analyst-oriented OPSEC findings such as PDB path leakage and classification, metadata inconsistencies, credential/endpoint patterns, source path username leaks, and CI/CD build traces |
| Output | Human-readable tables (default), JSON (`--json`), NDJSON (`--ndjson`), file output (`-o`) |
| Batch Mode | Analyze all PE files in a directory (`--batch <dir>`) |
| Fail-on | Exit with code 3 if anomalies meet a severity threshold (`--fail-on <severity>`) |
| TUI Hex Viewer | Interactive terminal hex viewer with region navigation -- select PE structures (DOS Header, COFF, sections, overlay) and browse hex dumps with keyboard scrolling (opt-in via `--features tui`) |
| GUI | egui-based GUI with tabbed views, drag & drop, filters, entropy color-coding, suspicious API highlighting, embedded icon display, PE header editor with Save As (opt-in via `--features gui`) |

## Known Limitations

- **Forwarded exports**: Not detected; only name/ordinal/RVA are displayed.
- **Export ordinals**: Computed as `ordinal_base + address_table_index`. goblin does not expose per-export ordinal fields, so PEs with non-contiguous ordinal assignments may show approximated values.
- **Import by ordinal**: Deferred to goblin's output; ordinal-only imports may show as empty names.
- **String extraction**: Capped at 100,000 strings to prevent excessive memory usage on large files.
- **Malformed PEs**: Arithmetic operations on PE header fields use checked arithmetic to avoid panics on crafted inputs. goblin may silently accept structurally invalid files without error. Fuzz testing with adversarial PEs is ongoing.
- **Authenticode trust verification**: Signature parsing and certificate extraction are supported, but trust verification (chain validation against a root store) is not performed. `trust_verified` is always `false`.
- **Authenticode dual-signing**: Only the first WIN_CERTIFICATE entry and first SignerInfo are processed. Dual-signed PEs (e.g., SHA-1 + SHA-256) will only show one signature.
- **PE Header Editor**: Validates optional header size before displaying fields. Malformed PEs with truncated optional headers will show an error message instead of editable fields. Out-of-bounds edits are silently skipped during save.
- **Load Config directory**: Not yet implemented (planned for a future release).
- **RVA-to-offset conversion**: Validated with overflow checks and file boundary verification; however, PEs with unusual section layouts may produce incorrect mappings.
- **Known packer identification**: Heuristic and best-effort. Customized, modified, or uncommon packers may be missed, and some benign binaries with unusual layouts may trigger false positives.
- **Compiler / build fingerprinting**: Best-effort. Toolchain and language hints can often be inferred, but exact compiler or language versions are not always recoverable from stripped or modified binaries.
- **Expanded OPSEC detection**: Some findings are string- or metadata-derived and may be incomplete when strings are obfuscated, stripped, or unavailable.

See [usage.md](usage.md) for real-sample walkthroughs, screenshots, and example triage results.
