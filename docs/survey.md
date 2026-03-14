# Survey of Existing PE Analysis Tools

> Status note (March 2026): The entries below are based on project readmes, release pages, and official sites. “Active / lower activity” is an approximate maintenance signal, not a strict quality judgment.

## Why PETriage?

PE surface analysis is a common first step in malware triage. In practice, however, the tool landscape is fragmented:

- the most recognizable PE triage tools are still Windows-centric;
- cross-platform GUI tools exist, but they are primarily interactive viewers/editors rather than automation-first workflows;
- CLI tools exist, but they often trade off coverage, maintenance cadence, ease of deployment, or analyst-oriented triage signals;
- libraries are excellent building blocks, but they are not standalone triage workflows.

PETriage is positioned at the intersection of four requirements that are rarely combined in one workflow:

1. **native use on Linux, macOS, and Windows**  
2. **CLI-first triage and automation**  
3. **broad PE surface coverage**  
4. **analyst-oriented triage signals** such as suspicious API grouping, anomaly detection, and OPSEC-relevant artifacts

In other words, PETriage is not trying to replace every PE tool. It targets the specific gap between GUI-first inspection tools, narrow CLI utilities, and general-purpose PE libraries.

## Existing Tools Overview

| Tool | Platform | Open Source | Interface | Language | Approx. activity | Positioning / notable strength |
|------|----------|-------------|-----------|----------|------------------|--------------------------------|
| **PEStudio** | Windows only | No (basic freeware / commercial Pro) | GUI | Proprietary | Active | Widely used malware initial assessment tool; strong indicators, VirusTotal / ATT&CK-oriented workflow |
| **CFF Explorer** | Windows only | No (freeware) | GUI | C++ | Mature / lower release cadence | Full PE editor with .NET support, scripting, disassembler, and utility features |
| **PE-bear** | Windows / Linux / macOS | Yes | GUI | C++ (Qt) | Active | Fast “first view” GUI for analysts; handles malformed PEs well |
| **Detect It Easy (DiE)** | Windows / Linux / macOS | Yes | GUI + CLI | C++ (Qt) | Active | Signature- and script-driven identification; strong packer / compiler / type detection |
| **XPEViewer** | Windows / Linux / macOS | Yes (MIT) | GUI | C++ (Qt) | Active | Lightweight cross-platform PE viewer/editor |
| **PPEE** | Windows (official site) | No (freeware) | GUI | Proprietary | Lower activity | Detailed PE inspection with plugin support and anomaly-oriented views |
| **readpe / pev** | Windows / Linux / macOS | Yes (GPL-2.0) | CLI | C | Active but narrower scope | Multi-tool PE CLI toolkit for headers, sections, imports, strings, and related utilities |
| **Manalyze** | Windows / Linux | Yes (GPLv3) | CLI | C++ | Mature / lower release cadence | Static analyzer focused on suspicious indicators and plugin-based checks |
| **peframe** | Cross-platform | Yes | CLI | Python | Maintained | Quick static malware triage with a malware-analysis orientation |
| **pecli** | Cross-platform | Yes (MIT) | CLI | Python | Lower activity | Lightweight Python CLI around common PE analysis tasks |
| **capa** | Cross-platform | Yes | CLI | Python | Active | Capability / behavior detection rather than PE surface inspection |
| **pefile** | Cross-platform | Yes (MIT) | Library | Python | Active | De facto Python PE parsing library |
| **LIEF** | Cross-platform | Yes (Apache 2.0) | Library | C++ / Python / Rust | Active | Multi-format parse/modify library with strong PE support |
| **radare2** | Cross-platform | Yes (LGPLv3) | CLI + TUI | C | Active | Full reverse-engineering framework; powerful but much broader than PE triage |
| **goblin** | Cross-platform | Yes (MIT) | Library | Rust | Active | Lightweight Rust binary parser with PE support |
| **pelite** | Cross-platform | Yes | Library | Rust | Moderate | Zero-allocation PE inspection with good PE-specific depth |
| **exe-rs** | Cross-platform | Yes | Library | Rust | Moderate | PE-focused Rust library with malformed-file testing and practical PE helpers |
| **PETriage** | Linux / macOS / Windows | Yes | CLI + optional TUI + optional GUI | Rust | Active | CLI-first PE surface triage with structured output, analyst-oriented signals, and optional interactive interfaces |

## Detailed Feature Matrix (selected tools)

| Feature | PEStudio | CFF Explorer | PE-bear | DiE | PPEE | readpe/pev | Manalyze | pefile | LIEF | PETriage |
|---------|----------|-------------|---------|-----|------|------------|----------|--------|------|----------|
| DOS / COFF / Optional headers | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Section headers | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Section entropy | Y | - | - | Y | Y | - | Y | Y* | - | Y |
| Import table | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Export table | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Resources | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Strings | Y | - | - | Y | Y | Y | Y | Y | - | Y |
| File hashes | Y | - | - | Y | Y | Y | - | - | - | Y |
| Imphash | Y | - | - | - | - | - | - | Y | Y | Y |
| Overlay detection | Y | - | Y | - | Y | - | Y | - | Y | Y |
| Rich Header | Y | - | Y | - | - | - | - | Y | Y | Y |
| TLS directory / callbacks | Y | Y | Y | - | Y | - | - | Y | Y | Y |
| Debug directory / PDB path | Y | Y | Y | - | Y | - | - | Y | Y | Y |
| Authenticode presence / parsing | Y | Y | - | - | Y | - | Y | Y | Y | Y |
| Suspicious API indicators | Y | - | - | - | - | - | partial | - | - | Y |
| Anomaly / malformation detection | Y | - | - | - | Y | Y | Y | Y | - | Y |
| Packer / compiler detection | Y | - | Y | Y | - | Y | Y | Y* | - | partial / planned |
| JSON / machine-readable output | limited / XML in pro workflow | - | - | Y | - | Y | Y | - | library API | Y |
| Batch-oriented CLI workflow | limited / pro batch mode | - | - | Y (`diec`) | - | Y | Y | via scripts | via scripts | Y |
| Optional GUI / TUI in same project | GUI only | GUI only | GUI only | GUI + CLI | GUI only | CLI only | CLI only | library | library | CLI + TUI + GUI |

\* `Y*` indicates support available via library use, extension code, or surrounding tooling rather than a default end-user workflow.

**Note:** `capa` is intentionally excluded from this matrix because it focuses on capability detection rather than PE surface inspection.

## What existing tools do well

### Windows-first GUI tools
**PEStudio** and **CFF Explorer** remain important reference points. PEStudio is still one of the strongest “initial assessment” experiences for Windows binaries, while CFF Explorer remains a capable PE editor with broad inspection and modification functionality.

### Cross-platform GUI tools
**PE-bear**, **DiE**, and **XPEViewer** reduce the need for Windows in many interactive tasks. PE-bear is especially useful as a “first view” GUI for malformed or suspicious PEs. DiE is particularly strong for signature-driven packer / compiler / file-type identification. XPEViewer offers a lighter viewer/editor workflow.

### CLI tools
**readpe / pev**, **Manalyze**, **peframe**, and **pecli** provide useful command-line options. Their trade-offs differ: some are narrower toolkits, some are mature but slower-moving, and some depend on Python packaging/runtime or older dependency stacks.

### Libraries
**pefile**, **LIEF**, **goblin**, **pelite**, and **exe-rs** are excellent building blocks for custom tooling. They are best understood as enablers rather than direct competitors to an analyst-facing triage workflow.

## Where PETriage fits

PETriage is essentially a compiled, CLI-first PE triage workflow that keeps optional TUI/GUI follow-up in the same project while emphasizing analyst-oriented signals and structured output.

## Key observations

### 1) “Linux/macOS lack good native PE analysis tools”
**Partially confirmed.**

There are now several usable cross-platform options, especially on the GUI side (PE-bear, DiE, XPEViewer). However, trade-offs remain:

- GUI-first tools emphasize interactive inspection over scripting and large-scale automation.
- Some CLI tools are narrower in coverage or rely on older / heavier dependency stacks.
- Libraries remain powerful but require custom wrapper code to produce a complete analyst-facing workflow.

A more precise conclusion is:

> Linux and macOS do have workable PE analysis options, but the combination of broad PE surface coverage, native compiled CLI automation, analyst-oriented triage signals, and optional interactive inspection is still uncommon in a single tool.

### 2) “Most major tools are closed source”
**Partially confirmed.**

The most recognizable Windows-centric tools (especially PEStudio and CFF Explorer) are not open-source. At the same time, several strong cross-platform alternatives are open-source, including PE-bear, DiE, XPEViewer, readpe/pev, Manalyze, peframe, pecli, pefile, LIEF, and the Rust library ecosystem. The real gap is not simply “open vs. closed”; it is **workflow fit** for analyst triage across platforms.

### 3) “There is room for a Rust-based PE triage tool”
**Confirmed.**

The Rust ecosystem already provides useful PE building blocks:
- **goblin**: general binary parsing with PE support
- **pelite**: PE-specific, lightweight, and zero-allocation-oriented
- **exe-rs**: PE-specific parsing with malformed-file testing and practical helpers
- **object**: broad executable/object support, less PE-specialized

This makes Rust a practical language choice for a surface-analysis tool that wants both memory safety and native distribution.

## Rust ecosystem notes

| Crate | Role in ecosystem | Strengths | Limits relative to PETriage |
|-------|-------------------|-----------|-----------------------------|
| **goblin** | General binary parser | Active, lightweight, cross-format, widely used | Not a complete analyst workflow by itself |
| **pelite** | PE-focused library | Zero-allocation style, good PE depth | Library-oriented, not a finished triage tool |
| **exe-rs** | PE-focused Rust library | Practical PE helpers, malformed-file testing | Smaller ecosystem footprint |
| **object** | Unified executable/object crate | Broad format support | Less specialized for analyst-facing PE triage |

## Bottom line

The survey does **not** show that PE tooling is absent outside Windows. It shows a more specific gap:

- Windows still has the best-known PE triage GUIs.
- Cross-platform GUI tools are real and useful.
- CLI tools and libraries exist, but each makes different trade-offs in automation, coverage, deployment, or analyst-facing triage context.

PETriage is intended to occupy that gap by combining:

- native use on Linux, macOS, and Windows;
- CLI-first automation with JSON / NDJSON, batch analysis, and fail-on thresholds;
- broad PE surface coverage;
- suspicious API indicators, anomaly detection, and OPSEC-relevant artifacts.

Optional TUI and GUI interfaces support interactive follow-up without changing the core CLI-first workflow.

## Sources

### Official sites / repositories
- PEStudio: https://www.winitor.com/ and https://www.winitor.com/download
- CFF Explorer / Explorer Suite: https://ntcore.com/explorer-suite/
- PE-bear: https://github.com/hasherezade/pe-bear
- Detect It Easy (DiE): https://github.com/horsicq/Detect-It-Easy
- XPEViewer: https://github.com/horsicq/XPEViewer
- readpe / pev: https://github.com/mentebinaria/readpe
- Manalyze: https://github.com/JusticeRage/Manalyze
- peframe: https://github.com/guelfoweb/peframe
- pecli: https://github.com/Te-k/pecli
- pefile: https://github.com/erocarrera/pefile
- LIEF: https://github.com/lief-project/LIEF
- radare2: https://github.com/radareorg/radare2
- goblin: https://github.com/m4b/goblin
- pelite: https://docs.rs/pelite/
- exe-rs: https://github.com/frank2/exe-rs
- object: https://github.com/gimli-rs/object

### Additional references
- REMnux PE tools overview: https://docs.remnux.org/discover-the-tools/examine+static+properties/pe+files
- PEStudio feature overview PDF: https://www.winitor.com/pdf/pestudio.pdf