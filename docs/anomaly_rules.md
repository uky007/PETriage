# Detection Rules

PETriage ships **31 deterministic detection rules** — **22 anomaly rules** plus **9 OPSEC
rules**. Every rule is derived from documented PE semantics and real-world attacker
tradecraft; none are probabilistic or ML-based, so every hit is explainable.

PETriage is a **triage aid, not a verdict engine**. Rules do not label a sample
malicious — they surface a signal, ranked by severity and accompanied by the evidence
and threshold that produced it, so an analyst (or an automation gate) can make the call.
The goal is not "zero false positives" but making a weak signal a *three-second
dismissal*: see the evidence, move on.

## Output streams

Findings are emitted through two complementary schemas:

| Stream | Fields | Purpose |
|---|---|---|
| **Anomaly** | `rule_id`, `category`, `severity`, `evidence`, `threshold` | Structural / heuristic irregularities |
| **OPSEC finding** | `id`, `finding_type`, `severity`, `source`, `confidence` | Operational-security surface (leaks, masquerading) |

`OPSEC-001/004/005/006` appear in **both** streams: they raise an anomaly *and* produce a
richer OPSEC finding with a confidence score. The other OPSEC rules emit findings only.

Severity is one of `critical`, `warning`, `info`. Use `--fail-on <severity>` to exit
non-zero when any finding meets or exceeds a threshold (CI/automation).

---

## Anomaly rules (22)

### Packing — `PACK`
| ID | Severity | Fires when |
|---|---|---|
| PACK-001 | critical | Any section entropy > 7.0 — likely encrypted or packed |
| PACK-002 | warning | Executable section entropy > 6.5 |
| PACK-003 | warning | Section `raw_size = 0` but `virtual_size > 0` — runtime unpacking suspected |
| PACK-004 | warning | Section `virtual_size > 10 × raw_size` — abnormal expansion ratio |

### Code integrity — `CODE`
| ID | Severity | Fires when |
|---|---|---|
| CODE-001 | critical | Section is both writable and executable (W^X violation) |
| CODE-002 | warning | Entry point resides in a section other than `.text` |

### Security mitigations — `SEC`
| ID | Severity | Fires when |
|---|---|---|
| SEC-001 | warning | ASLR (`DYNAMIC_BASE`) disabled |
| SEC-002 | warning | DEP (`NX_COMPAT`) disabled |
| SEC-003 | info | Control Flow Guard (`GUARD_CF`) not enabled |
| SEC-004 | info | `NO_SEH` set — no Structured Exception Handling |

### Timestamp — `TIME`
| ID | Severity | Fires when |
|---|---|---|
| TIME-001 | warning | COFF timestamp is in the future — **suppressed** when `IMAGE_DEBUG_TYPE_REPRO` is present (reproducible builds put a content hash where the date goes) |
| TIME-002 | warning | COFF timestamp is before 2000-01-01 — possible forgery |
| TIME-003 | info | COFF timestamp is 0 (stripped or not set) |
| TIME-004 | warning | COFF timestamp and CodeView debug timestamp differ by > 24h |

### Structure — `STRUCT`
| ID | Severity | Fires when |
|---|---|---|
| STRUCT-002 | warning | Overlay data appended beyond the PE structure |
| STRUCT-003 | info | Non-standard section name (per the shared `is_standard_section_name` allowlist) |
| STRUCT-004 | warning | Section count is 0, or ≥ 10 |

### Suspicious API combos — `COMBO`
| ID | Severity | Fires when |
|---|---|---|
| COMBO-001 | critical | Process-injection **and** evasion APIs both present — requires **≥ 1 strong injection primitive** (`CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx`, `NtMapViewOfSection`, `QueueUserAPC`, `SetThreadContext`, …); `OpenProcess` alone does not fire it |
| COMBO-002 | warning | Network **and** crypto APIs both present — possible encrypted C2 |

### Rich Header — `RICH`
| ID | Severity | Fires when |
|---|---|---|
| RICH-001 | warning | Rich Header checksum invalid — tampering or false flag (e.g. Olympic Destroyer) |
| RICH-002 | info | No Rich Header, but a > 4 KB executable section exists — may not be MSVC-built |

### Export Directory — `EXPORT`
| ID | Severity | Fires when |
|---|---|---|
| EXPORT-001 | warning / info | Export Directory timestamp is `0xFFFFFFFF` (warning, invalid) or `0` (info, non-standard build) |

---

## OPSEC rules (9)

| ID | Severity | Fires when | Streams |
|---|---|---|---|
| OPSEC-001 | info | PDB debug path present | anomaly |
| OPSEC-002 | info | PDB path classified (`path_class` + username hint) | finding |
| OPSEC-003 | warning | CodeView RSDS structure present but PDB path empty/nulled — deliberate OPSEC countermeasure | finding |
| OPSEC-004 | warning / info | Filename or vendor masquerading: on-disk name vs `OriginalFilename`/`InternalName` mismatch, or a claimed known vendor (Microsoft/Google/…) on an unsigned binary. Downgraded to `info` when `OriginalFilename` already matches the on-disk name | both |
| OPSEC-005 | critical | Hardcoded credential pattern — AWS / Slack / Google / GitHub token | both |
| OPSEC-006 | warning / info | Hardcoded endpoint — internal URL or private IP (`warning`), external URL or public IP (`info`); public IPs are not raised as anomalies | both (warning only) |
| OPSEC-007 | warning / info | Rich Header checksum invalid (`warning`), or a very wide toolset build-id range (`info`) | finding |
| OPSEC-008 | info | PDB path indicates a CI/CD build environment (Azure DevOps / GitHub Actions / build server) | finding |
| OPSEC-009 | warning | Source/build path leaks a developer username (`C:\Users\<name>`, `/home/<name>`, `/Users/<name>`); detected via both string extraction and a raw-byte scan | finding |

---

## False-positive controls

The rules are tuned to keep noise low. The main mechanisms:

- **Severity tiering.** Contextual signals are `info`, not alarms — non-standard section
  names, missing CFG, zero timestamps, wide toolset ranges, etc. never present as
  `warning`/`critical`.
- **Corroboration before escalation.** `COMBO-001` requires a *strong* injection
  primitive, not merely `OpenProcess`, so benign software that calls `OpenProcess` +
  `SetFileAttributes` does not trip a critical. Packer identification uses multi-signal
  confidence scoring with case-variant de-duplication rather than a single section-name
  match.
- **Benign-pattern suppression.**
  - `TIME-001` is suppressed when the `REPRO` debug directory is present — reproducible
    builds encode a content hash where a date would go.
  - `OPSEC-004` downgrades an `InternalName` mismatch to `info` when `OriginalFilename`
    already matches the on-disk name (InternalName is often a product description, not a
    filename).
  - `OPSEC-006` skips public IP addresses; `OPSEC-009` skips `/home/` occurrences that
    are actually URL paths.
- **Single source of truth for "standard".** `is_standard_section_name()` is shared by
  both the Sections display and `STRUCT-003`, so the definition of a normal section name
  cannot drift between the report and the rule.
- **Transparent evidence.** Every finding carries its `evidence` and, where applicable,
  the `threshold` it crossed — so a false positive is dismissible at a glance instead of
  requiring a re-run.

## Validation

- **94 integration tests** (`tests/malformed.rs`) drive the compiled binary against
  hand-constructed PE byte sequences, asserting that each rule fires on exactly the
  structural condition it targets — and that malformed input never panics.
- All rule arithmetic uses checked/float operations to prevent overflow panics on crafted
  PEs.
- Rules are **deterministic**: identical input yields identical output, which makes both
  regression testing and analyst trust straightforward.
