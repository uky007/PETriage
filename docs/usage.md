# Usage

## CLI

```
petriage <file.exe>              # Show all information (except strings)
petriage <file.exe> -a           # Show all information including strings
petriage <file.exe> -H           # Headers only
petriage <file.exe> -i           # Imports only
petriage <file.exe> -e           # Exports only
petriage <file.exe> -s           # Sections only
petriage <file.exe> -S           # Strings only
petriage <file.exe> --hashes     # File hashes only
petriage <file.exe> --overlay    # Overlay only
petriage <file.exe> -r           # Resources only
petriage <file.exe> -c           # Authenticode / code signing info
petriage <file.exe> --json       # JSON output
petriage <file.exe> --ndjson     # Compact one-line JSON output
petriage --batch <dir> --ndjson  # Batch-analyze all PEs in a directory (NDJSON output)
petriage --batch <dir> --json    # Batch-analyze all PEs (JSON array output)
petriage <file.exe> --fail-on warning  # Exit code 3 if any warning+ anomaly found
petriage <file.exe> -o report.txt      # Write to file
```

### jq recipes

```
petriage <file.exe> --json | jq '.suspicious_summary'
petriage <file.exe> --json | jq '.imports[].functions[] | select(.risk != null)'
petriage <file.exe> --json | jq '.anomalies'
petriage <file.exe> --json | jq '.anomalies[] | select(.severity == "critical")'
petriage <file.exe> --json | jq '.resources'
petriage <file.exe> --json | jq '.resources.version_info'
petriage <file.exe> --json | jq '.resources.manifest'
petriage <file.exe> --json | jq '.authenticode'
petriage <file.exe> --json | jq '.authenticode.signer'
petriage <file.exe> --json | jq '.rich_header'
petriage <file.exe> --json | jq '.rich_header.rich_hash'
```

## TUI Hex Viewer

Requires `--features tui` build.

```
petriage -x <file.exe>           # Interactive hex viewer (short form)
petriage --view <file.exe>       # Interactive hex viewer (long form)
```

The TUI provides:

- **Split-pane layout** -- Left pane lists PE regions (DOS Header, COFF, Optional Header, sections, overlay); right pane shows hex dump
- **Region navigation** -- Up/Down arrows to select regions; hex view updates instantly
- **Hex scrolling** -- j/k for line scroll, PgUp/PgDn for page scroll, Home/End for jump
- **Classic hex format** -- Offset | hex bytes | ASCII sidebar, 16 bytes per line
- **Alternate screen** -- Launches in alternate terminal screen; restores on exit (like `git log`)

## GUI

Requires `--features gui` build.

```
petriage-gui                     # Open with file dialog
petriage-gui <file.exe>          # Open file directly in GUI
```

The GUI provides:

- **Tabbed interface** -- File Info, Headers, Sections, Imports, Exports, Strings, Overlay, Resources, Rich, TLS, Debug, Signing, Editor
- **Drag & drop** -- Drop PE files onto the window to analyze
- **Left sidebar** -- Toggle analysis options and re-analyze without restarting
- **Import filter** -- Search API names across DLLs, "Suspicious only" toggle to surface risky APIs
- **String filter** -- Filter by text and encoding (ASCII / UTF-16)
- **Entropy color-coding** -- Section entropy highlighted green (<6) / yellow (6--7) / red (7--8)
- **Suspicious API indicators** -- Color-coded severity badges (red/yellow/cyan) on File Info and Imports tabs
- **Embedded icon display** -- Extracts and renders PE embedded icons (RT_GROUP_ICON / RT_ICON); primary icon shown on File Info tab, all icon groups on Resources tab. Useful for identifying malware impersonating legitimate software
- **OPSEC indicators** -- PDB path highlighted in orange on Debug tab and File Info tab with dedicated badge, surfacing developer environment leaks
- **PE Header Editor** -- Edit COFF header (TimeDateStamp, Characteristics), Optional header (AddressOfEntryPoint, ImageBase, DllCharacteristics flags, CheckSum, Subsystem, etc.), and Section headers (Name, VirtualSize, RawSize, Characteristics flags) with hex DragValue inputs and flag checkboxes. Modified fields highlighted. Save As writes patched PE to disk.
- **Hash copy buttons** -- One-click copy of MD5/SHA1/SHA256
- **Virtual scroll** -- Handles tens of thousands of strings without lag

## Example Output

```
=== File Info ===
  File:    sample.exe
  Size:    72704 bytes (71.00 KB)
  Type:    PE32 (32-bit)

=== OPSEC: PDB Path ===
  C:\Users\dev\source\repos\malware\x64\Release\payload.pdb

=== Hashes ===
  MD5:     a1b2c3d4e5f6...
  SHA1:    1234567890ab...
  SHA256:  abcdef012345...
  Imphash: 5a8e4dc5b6f7...

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
  CRITICAL: 2 WARNING: 5 INFO: 4

  [CRITICAL] Code Integrity: Section '.xpack' is both writable and executable (W^X violation)
  [CRITICAL] Suspicious Combo: Process Injection + Evasion APIs both present -- possible code injection technique
  [WARNING] Packing: Executable section '.text' has high entropy (6.8921)
  [WARNING] Security: ASLR (DYNAMIC_BASE) is disabled
  [WARNING] Security: DEP (NX_COMPAT) is disabled
  [WARNING] Timestamp: Timestamp (1998-03-15 00:00:00 UTC) is before year 2000 -- possible forgery
  [WARNING] Structure: Overlay data detected (4096 bytes at offset 0x12000)
  [INFO] [OPSEC-001] OPSEC: PDB debug path found: C:\Users\dev\source\repos\malware\x64\Release\payload.pdb
  [INFO] Security: Control Flow Guard (GUARD_CF) is not enabled
  [INFO] Structure: Non-standard section name '.xpack'
  [INFO] [RICH-002] Rich Header: No Rich Header found -- PE may not have been built with MSVC toolchain
  ...

=== Rich Header ===
  XOR Key:    0xaabbccdd
  Rich Hash:  a1b2c3d4e5f67890abcdef1234567890
  Checksum:   Valid

  CompID         ProdID  BuildID    Count  Description
  ------------ ------  -------  -------  ------------------------------
  0x01070042      263       66        7  [C++] VS 2005 (build 66)
  0x010a71b3      266    29107        1  [LNK] VS 2019 16.7 (build 29110)
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

=== Authenticode / Code Signing ===
  Signed:          Yes
  Parse OK:        Yes
  Trust Verified:  No (not implemented)

  WIN_CERTIFICATE:
    Length:   9640 bytes
    Revision: WIN_CERT_REVISION_2_0 (0x0200)
    Type:     WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002)

  Signer:
    Subject:    Microsoft Corporation
    Issuer:     Microsoft Code Signing PCA 2011
    Serial:     33:00:00:01:c4:22:b2:f7:9b:18:54:...
    Not Before: 2023-05-18 18:09:06 UTC
    Not After:  2024-05-16 18:09:06 UTC
    Thumbprint: a1:b2:c3:d4:e5:f6:...

  Certificate Chain (3 certificates):
    [0] (signer)
      Subject:    Microsoft Corporation
      ...
    [1]
      Subject:    Microsoft Code Signing PCA 2011
      ...
    [2]
      Subject:    Microsoft Root Certificate Authority 2011
      ...
```
