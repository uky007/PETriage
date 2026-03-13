# Survey of Existing PE Analysis Tools

## Why petriage?

Most PE surface analysis tools have significant trade-offs that limit their usefulness for cross-platform malware triage workflows.

## Comparison

| Tool | Platform | Interface | Language | Status |
|------|----------|-----------|----------|--------|
| **PEStudio** | Windows only | GUI | Proprietary | Active, closed-source |
| **CFF Explorer** | Windows only | GUI | C++ | Active |
| **PE-bear** | Cross-platform | GUI only | C++ | Active |
| **XPEViewer** | Cross-platform | GUI only | C++ | Active |
| **pefile** | Cross-platform | Library | Python | Active, slow on large files |
| **peframe** | Cross-platform | CLI | Python | Maintained, slow |
| **pev/readpe** | Linux/macOS | CLI | C | Unmaintained, limited features |
| **petriage** | Cross-platform | CLI + TUI + GUI | Rust | Active |

## Key differentiators

- **Cross-platform CLI**: PEStudio and CFF Explorer are Windows-only. PE-bear and XPEViewer are cross-platform but GUI-only, unsuitable for scripting and automation.
- **Performance**: Python-based tools (pefile, peframe) are significantly slower than compiled alternatives. petriage processes files in milliseconds.
- **Composability**: JSON/NDJSON output enables integration with `jq`, SIEMs, and automation pipelines. Most GUI tools lack machine-readable output.
- **Single binary**: No runtime dependencies for the CLI. No Python environment, no .NET framework, no JVM.
- **Maintained**: pev/readpe (C) is effectively unmaintained and lacks modern features like anomaly detection, Rich Header analysis, and Authenticode parsing.
