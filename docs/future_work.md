# Future Work

## v0.5.0

### Packer detection model upgrade
- Migrate from single `build_fingerprint.packer` to a dedicated `packers` report model supporting multiple candidates, `signature_type`, `rule_id`, and ambiguous candidate sets
- Add `--packers-strict` flag for high-confidence-only filtering
- Expand regression tests for NSIS/Inno overlay detection, `.packed` ambiguous name handling, and multi-packer scenarios

### DLL Side-Loading detection
- Detect DLLs designed for DLL Side-Loading attacks (proxy DLLs, export forwarding patterns)
- Check for known side-loading target DLL names

### Malformed PE resilience
- Fallback raw-byte analysis when goblin parse fails (e.g., Lumma Stealer payloads with anti-analysis)
- Partial parse recovery for heavily modified PEs

### Overlay edge case
- Adjust overlay start to `max(end_of_pe, cert_end)` when certificate table is present but doesn't cover the entire tail

## Later

- Load Config directory parsing
- Entropy histogram visualization
- Robust Rust detection (richer PDB extraction, symbol heuristics)
- Offline signature packs (PEiD/DiE-like) with curated ruleset provenance
- ELF format support
