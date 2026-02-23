# PE Surface Analysis Tools Survey

## 1. Existing Tools Overview

| Tool | Platform | Open Source | Interface | Language | Active | Key Strength |
|------|----------|-------------|-----------|----------|--------|--------------|
| PEStudio | Windows only | No (freeware basic) | GUI | Proprietary | Yes | Gold standard for PE triage; VirusTotal, MITRE ATT&CK |
| CFF Explorer | Windows only | No (freeware) | GUI | C++ | Low | Full PE editor with .NET support, scripting, disassembler |
| PE-bear | Win/Linux/macOS | Yes (since 2022) | GUI | C++ (Qt) | Yes | Friendly GUI, handles malformed PEs, signature DB |
| Detect It Easy (DiE) | Win/Linux/macOS | Yes | GUI + CLI | C++ (Qt) | Yes | Best-in-class packer/compiler detection via signatures |
| XPEViewer | Win/Linux/macOS | Yes (MIT) | GUI | C++ (Qt) | Yes | Lightweight cross-platform PE viewer/editor |
| PPEE | Win/Linux/macOS | No (freeware) | GUI | Proprietary | Low | All PE directories, plugin support, anomaly detection |
| readpe/pev (C) | Win/Linux/macOS | Yes (GPL-2.0) | CLI | C | Low | Multiplatform CLI toolkit (readpe, pestr, pescan, etc.) |
| Manalyze | Win/Linux | Yes (GPLv3) | CLI | C++ (Boost) | Low | Plugin architecture, authenticode, findcrypt |
| peframe | Cross-platform | Yes | CLI | Python | Low | Quick malware triage, xor string detection |
| pecli | Cross-platform | Yes (MIT) | CLI | Python | Low | Simple PE CLI analysis, YARA integration |
| capa | Cross-platform | Yes | CLI | Python | Yes | Capability/behavior detection, rule-based |
| pefile | Cross-platform | Yes (MIT) | Library | Python | Yes | De facto Python PE library, battle-tested |
| LIEF | Cross-platform | Yes (Apache 2.0) | Library | C++/Py/Rust | Yes | Multi-format, PE modification, authenticode |
| radare2 | Cross-platform | Yes (LGPLv3) | CLI + TUI | C | Yes | Full RE framework (PE is one of many formats) |
| goblin | Cross-platform | Yes (MIT) | Library | Rust | Yes | Lightweight Rust PE32/64 parsing |
| pelite | Cross-platform | Yes | Library | Rust | Moderate | Zero-alloc PE inspection, pattern scanning |
| exe-rs | Cross-platform | Yes | Library | Rust | Moderate | Imphash, checksums, entropy in Rust |

## 2. Detailed Feature Matrix

| Feature | PEStudio | CFF Explorer | PE-bear | DiE | PPEE | readpe/pev | Manalyze | pefile | LIEF |
|---------|----------|-------------|---------|-----|------|------------|----------|--------|------|
| DOS Header | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| PE/COFF Header | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Optional Header | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Section Headers | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Import Table | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Export Table | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Resources | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Strings | Y | - | - | Y | Y | Y | Y | Y | - |
| Entropy | Y | - | - | Y | Y | - | Y | Y* | - |
| Rich Header | - | - | Y | - | - | - | - | Y | Y |
| TLS Directory | Y | Y | Y | - | Y | - | - | Y | Y |
| Debug Directory | Y | Y | Y | - | Y | - | - | Y | Y |
| Relocations | Y | Y | Y | - | Y | - | - | Y | Y |
| Authenticode | Y | Y | - | - | Y | - | Y | Y | Y |
| Overlay Detection | Y | - | Y | - | Y | - | Y | - | Y |
| Packer Detection | Y | - | Y | Y | - | Y | Y | Y* | - |
| Compiler Detection | - | - | - | Y | - | - | Y | - | - |
| VirusTotal | Y | - | - | - | - | - | Y | - | - |
| File Hashes | Y | - | - | Y | Y | Y | - | - | - |
| Imphash | Y | - | - | - | - | - | - | Y | Y |
| Anomaly Detection | Y | - | - | - | Y | Y | Y | Y | - |
| Hex Editor | - | Y | Y | Y | Y | - | - | - | - |
| PE Editing | - | Y | Y | - | Y | - | - | - | Y |
| .NET Support | Y | Y | - | Y | Y | - | - | Y | Y |
| JSON Output | - | - | - | Y | - | Y | Y | - | - |

*Y\* = available via extension or additional code*

## 3. Validation of Assumptions

### "Linux/macOS lack good native PE analysis tools"

**Confirmed.** While some cross-platform options exist, there are significant gaps:

**Cross-platform GUI tools (PE-bear, DiE, XPEViewer):**
- Require Qt runtime / desktop environment
- Unsuitable for headless servers, scripting, automation, CI/CD pipelines
- DiE has CLI mode (`diec`) but focused on packer/compiler detection only

**Cross-platform CLI tools:**
- **readpe/pev (C)**: Limited features (no Rich header, TLS, debug, authenticode), low maintenance, C codebase hard to extend safely
- **Manalyze (C++)**: Good feature set but requires Boost, doesn't build easily on macOS, development slowed
- **peframe/pecli (Python)**: Slow startup/runtime (Python overhead), not suitable for batch processing large sample sets
- **radare2**: Full RE framework — massive overkill for surface analysis, very steep learning curve

**Libraries (pefile, LIEF, goblin):**
- Excellent for building tools, but not standalone analysis tools
- Require writing wrapper code for each analysis task

**Bottom line:** No fast, comprehensive, actively-maintained, compiled CLI tool for PE surface analysis exists on Linux/macOS. Analysts must either use a Windows VM, chain multiple Python tools together, or accept limited coverage.

### "Most major tools are closed source"

**Partially confirmed.** The two most popular tools in the malware analysis community (PEStudio and CFF Explorer) are indeed closed source. However, PE-bear went open source in 2022, and DiE/XPEViewer have always been open source. The gap is specifically in **CLI tools** — the open source ones (readpe/pev, Manalyze) are poorly maintained.

## 4. Source Code Availability

| Tool | Source Available | License | Repository |
|------|----------------|---------|------------|
| PEStudio | No | Proprietary (free basic) | N/A |
| CFF Explorer | No | Freeware | N/A |
| PE-bear | Yes | GPL | github.com/hasherezade/pe-bear |
| DiE | Yes | MIT | github.com/horsicq/Detect-It-Easy |
| XPEViewer | Yes | MIT | github.com/horsicq/XPEViewer |
| PPEE | No | Freeware | N/A |
| readpe/pev | Yes | GPL-2.0 | github.com/mentebinaria/readpe |
| Manalyze | Yes | GPLv3 | github.com/JusticeRage/Manalyze |
| peframe | Yes | - | github.com/guelfoweb/peframe |
| pecli | Yes | MIT | github.com/Te-k/pecli |
| pefile | Yes | MIT | github.com/erocarrera/pefile |
| LIEF | Yes | Apache 2.0 | github.com/lief-project/LIEF |
| radare2 | Yes | LGPLv3 | github.com/radareorg/radare2 |

## 5. Feature Categories for Surface Analysis

Based on the survey, a comprehensive PE surface analysis tool needs:

### Tier 1: Essential (Every tool has these)
- DOS Header parsing
- PE/COFF Header parsing (machine, timestamp, characteristics)
- Optional Header parsing (magic, entry point, image base, subsystem, DLL characteristics)
- Section Headers (name, virtual/raw size/addr, characteristics, entropy)
- Import Table (DLL names + function names/ordinals)
- Export Table (function names, ordinals, forwarded exports)

### Tier 2: Important (Most serious tools have these)
- Resource Directory parsing (types, names, languages, sizes)
- String extraction (ASCII + Unicode, configurable min length)
- File hashes (MD5, SHA1, SHA256)
- Import hash (imphash)
- Overlay detection (data appended after PE)
- Entry point analysis and validation

### Tier 3: Advanced (Differentiating features)
- Rich Header parsing and XOR key extraction
- TLS Directory and callback detection
- Debug Directory (PDB path, debug type, GUID)
- Digital signature / Authenticode verification
- Packer/compiler detection (signature-based)
- Suspicious API indicator flagging
- Entropy visualization (per-section)
- Anomaly/malformation detection
- Bound/Delay imports
- Relocations
- .NET CLR metadata
- Load Config Directory (SEH, CFG, etc.)
- Certificate table parsing

## 6. Rust Ecosystem for PE Parsing

| Crate | Stars | PE Coverage | Strengths | Weaknesses |
|-------|-------|-------------|-----------|------------|
| goblin | ~1.3k | Good (headers, sections, imports, exports) | Active, well-tested, fuzz-tested, no_std | Limited resources, no Rich header, no TLS/debug dirs |
| pelite | ~250 | Excellent (headers, dirs, Rich, security) | Zero-alloc, pattern scanning, comprehensive | Moderate maintenance, less community |
| exe-rs | ~50 | Good (imphash, entropy, checksums) | PE-specific features | Smaller community, less battle-tested |
| object | ~500 | Basic (unified interface) | Multi-format | Not PE-focused, less detail |

**Recommendation:** Use **goblin** as the primary parser (best maintained, most robust) and supplement with manual parsing for features it doesn't cover (Rich header, TLS, debug, resources, overlay). This is the pragmatic approach — goblin handles the complex parts (import table parsing, section mapping) while manual parsing handles the simpler directory structures.

## 7. Conclusion

There is a clear, validated opportunity for a **fast, cross-platform, CLI-first PE surface analysis tool written in Rust**. The ideal tool (petriage) would:

1. **Run natively** on Linux/macOS/Windows as a single static binary with zero dependencies
2. **Provide comprehensive PE structure analysis** matching PEStudio's read-only analysis features
3. **Be fast** enough for batch processing thousands of samples (Rust advantage over Python)
4. **Output structured data** (JSON) for pipeline integration with other tools
5. **Focus on surface analysis** (no execution, no debugging, no modification) for malware triage
6. **Be open source** and actively maintained

No existing tool fills this exact niche.

## Sources

- [PEStudio](https://www.winitor.com/)
- [CFF Explorer / Explorer Suite](https://ntcore.com/explorer-suite/)
- [PE-bear](https://github.com/hasherezade/pe-bear)
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy)
- [XPEViewer](https://github.com/horsicq/XPEViewer)
- [PPEE](https://www.mzrst.com/)
- [readpe/pev (C)](https://github.com/mentebinaria/readpe)
- [Manalyze](https://github.com/JusticeRage/Manalyze)
- [peframe](https://github.com/guelfoweb/peframe)
- [pecli](https://github.com/Te-k/pecli)
- [pefile](https://github.com/erocarrera/pefile)
- [LIEF](https://github.com/lief-project/LIEF)
- [radare2](https://github.com/radareorg/radare2)
- [goblin (Rust)](https://github.com/m4b/goblin)
- [pelite (Rust)](https://docs.rs/pelite/)
- [exe-rs (Rust)](https://github.com/frank2/exe-rs)
- [Five PE Analysis Tools Worth Looking At](https://www.threatdown.com/blog/five-pe-analysis-tools-worth-looking-at/)
- [REMnux PE Tools](https://docs.remnux.org/discover-the-tools/examine+static+properties/pe+files)
