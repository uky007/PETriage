use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn petriage_run(data: &[u8]) -> std::process::Output {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("petriage_test_{}_{}.bin", pid, id));
    std::fs::write(&path, data).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_petriage"))
        .args(["--json"])
        .arg(&path)
        .output()
        .expect("failed to run petriage");
    let _ = std::fs::remove_file(&path);
    output
}

fn assert_no_panic(output: &std::process::Output) {
    // Process should exit normally (not crash/signal)
    assert!(
        output.status.code().is_some(),
        "process should not be killed by signal"
    );
    // Exit code should be 0 (goblin accepted) or 1 (parse error), never anything else
    let code = output.status.code().unwrap();
    assert!(
        code == 0 || code == 1,
        "unexpected exit code: {}",
        code
    );
}

// --- No-panic tests: the tool must not crash on any of these ---

#[test]
fn no_panic_empty_file() {
    let output = petriage_run(b"");
    assert_no_panic(&output);
}

#[test]
fn no_panic_too_small() {
    let output = petriage_run(b"MZ");
    assert_no_panic(&output);
}

#[test]
fn no_panic_invalid_magic() {
    let output = petriage_run(&[0x00; 256]);
    assert_no_panic(&output);
}

#[test]
fn no_panic_e_lfanew_overflow() {
    let mut data = vec![0u8; 128];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 0xFF;
    data[0x3D] = 0xFF;
    data[0x3E] = 0xFF;
    data[0x3F] = 0x7F;
    let output = petriage_run(&data);
    assert_no_panic(&output);
}

#[test]
fn no_panic_truncated_pe_signature() {
    let mut data = vec![0u8; 130];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 128;
    let output = petriage_run(&data);
    assert_no_panic(&output);
}

#[test]
fn no_panic_zero_sections() {
    let mut data = vec![0u8; 512];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 0x80;
    data[0x80] = b'P';
    data[0x81] = b'E';
    data[0x84] = 0x4c;
    data[0x85] = 0x01;
    let output = petriage_run(&data);
    assert_no_panic(&output);
}

#[test]
fn no_panic_section_size_overflow() {
    let mut data = vec![0u8; 512];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 0x80;
    data[0x80] = b'P';
    data[0x81] = b'E';
    data[0x84] = 0x4c;
    data[0x85] = 0x01;
    data[0x86] = 1;
    data[0x94] = 0;
    data[0x95] = 0;
    data[0x98..0x9E].copy_from_slice(b".text\0");
    // raw_size = 0xFFFFFFFF
    data[0xA8] = 0xFF;
    data[0xA9] = 0xFF;
    data[0xAA] = 0xFF;
    data[0xAB] = 0xFF;
    data[0xAC] = 0x00;
    data[0xAD] = 0x02;
    let output = petriage_run(&data);
    assert_no_panic(&output);
}

#[test]
fn no_panic_random_noise() {
    // 1KB of pseudo-random data (deterministic seed)
    let mut data = vec![0u8; 1024];
    let mut state: u32 = 0xDEADBEEF;
    for byte in data.iter_mut() {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        *byte = (state >> 16) as u8;
    }
    data[0] = b'M';
    data[1] = b'Z';
    let output = petriage_run(&data);
    assert_no_panic(&output);
}

// --- JSON error format tests ---

#[test]
fn json_error_on_missing_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_petriage"))
        .args(["--json", "/nonexistent/file.exe"])
        .output()
        .expect("failed to run petriage");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(stderr.trim());
    assert!(parsed.is_ok(), "stderr should be valid JSON: {}", stderr);
    let val = parsed.unwrap();
    assert!(val.get("error").is_some(), "JSON error should have 'error' field");
}

#[test]
fn json_error_on_no_file_arg() {
    let output = Command::new(env!("CARGO_BIN_EXE_petriage"))
        .args(["--json"])
        .output()
        .expect("failed to run petriage");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(stderr.trim());
    assert!(parsed.is_ok(), "stderr should be valid JSON: {}", stderr);
}

// --- Output structure tests ---

#[test]
fn valid_pe_produces_valid_json() {
    // Minimal valid PE
    let mut data = vec![0u8; 1024];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 0x80;
    data[0x80] = b'P';
    data[0x81] = b'E';
    data[0x84] = 0x4c;
    data[0x85] = 0x01;
    data[0x86] = 1;
    // size of optional header = 0xe0
    data[0x94] = 0xe0;
    data[0x95] = 0x00;
    // characteristics = EXECUTABLE_IMAGE
    data[0x96] = 0x02;
    data[0x97] = 0x01;
    // Optional header magic PE32
    data[0x98] = 0x0b;
    data[0x99] = 0x01;

    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(parsed.is_ok(), "stdout should be valid JSON: {}", stdout);
        let val = parsed.unwrap();
        assert!(val.get("file_info").is_some());
    }
}

#[test]
fn anomaly_json_has_rule_id() {
    // Minimal PE that triggers anomalies (no ASLR/DEP, timestamp=0)
    let mut data = vec![0u8; 1024];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 0x80;
    data[0x80] = b'P';
    data[0x81] = b'E';
    data[0x84] = 0x4c;
    data[0x85] = 0x01;
    data[0x86] = 1;
    data[0x94] = 0xe0;
    data[0x95] = 0x00;
    data[0x96] = 0x02;
    data[0x97] = 0x01;
    data[0x98] = 0x0b;
    data[0x99] = 0x01;

    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(anomalies) = val.get("anomalies").and_then(|a| a.as_array()) {
                for anomaly in anomalies {
                    assert!(
                        anomaly.get("rule_id").is_some(),
                        "anomaly missing rule_id: {:?}",
                        anomaly
                    );
                }
            }
        }
    }
}

// --- Overflow regression tests (Chappy review 2026-02-23) ---

#[test]
fn no_panic_section_pointer_plus_size_overflow() {
    // Section with pointer_to_raw_data + size_of_raw_data > u32::MAX
    // This previously caused panic in detect_overlay
    let mut data = vec![0u8; 1024];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 0x80;
    data[0x80] = b'P';
    data[0x81] = b'E';
    data[0x84] = 0x4c;
    data[0x85] = 0x01;
    data[0x86] = 1; // 1 section
    data[0x94] = 0xe0;
    data[0x96] = 0x02;
    data[0x97] = 0x01;
    data[0x98] = 0x0b;
    data[0x99] = 0x01;
    // Section header starts at 0x80 + 4 + 20 + 0xe0 = 0x178
    let sh = 0x178;
    data[sh..sh + 6].copy_from_slice(b".text\0");
    // virtual_size
    data[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    // virtual_address
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    // raw_size = 0xFFFFFFFF
    data[sh + 16..sh + 20].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // raw_addr = 0x80000000
    data[sh + 20..sh + 24].copy_from_slice(&0x80000000u32.to_le_bytes());

    let output = petriage_run(&data);
    assert_no_panic(&output);
}

#[test]
fn no_panic_virtual_size_times_10_overflow() {
    // Section with raw_size such that raw_size * 10 overflows u32
    // This previously caused panic in anomaly rule PACK-004
    let mut data = vec![0u8; 1024];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 0x80;
    data[0x80] = b'P';
    data[0x81] = b'E';
    data[0x84] = 0x4c;
    data[0x85] = 0x01;
    data[0x86] = 1; // 1 section
    data[0x94] = 0xe0;
    data[0x96] = 0x02;
    data[0x97] = 0x01;
    data[0x98] = 0x0b;
    data[0x99] = 0x01;
    let sh = 0x178;
    data[sh..sh + 6].copy_from_slice(b".text\0");
    // virtual_size = 0xFFFFFFFF
    data[sh + 8..sh + 12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // virtual_address
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    // raw_size = 0x20000000 (raw_size * 10 would overflow)
    data[sh + 16..sh + 20].copy_from_slice(&0x20000000u32.to_le_bytes());
    // raw_addr = 0x200
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());

    let output = petriage_run(&data);
    assert_no_panic(&output);
}

#[test]
fn export_ordinal_structure_valid() {
    // Minimal PE32 with an export table (2 named exports)
    // This fixture is self-contained — no dependency on platform or self-binary
    let mut data = vec![0u8; 0x400];

    // DOS Header
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE Signature
    data[0x80] = b'P'; data[0x81] = b'E';

    // COFF Header at 0x84
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());      // 1 section
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());   // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // Optional Header at 0x98
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    data[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes()); // EntryPoint
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    data[0xC0..0xC2].copy_from_slice(&4u16.to_le_bytes());      // MajorOSVersion
    data[0xC8..0xCA].copy_from_slice(&4u16.to_le_bytes());      // MajorSubsystemVersion
    data[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    data[0xDC..0xDE].copy_from_slice(&3u16.to_le_bytes());      // Subsystem: CUI
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes
    // Data Directory[0] — Export: RVA=0x1000, Size=0x80
    data[0xF8..0xFC].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0xFC..0x100].copy_from_slice(&0x80u32.to_le_bytes());

    // Section Header at 0x178
    let sh = 0x178;
    data[sh..sh + 7].copy_from_slice(b".edata\0");
    data[sh + 8..sh + 12].copy_from_slice(&0x100u32.to_le_bytes());  // VirtualSize
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfRawData
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
    data[sh + 36..sh + 40].copy_from_slice(&0x40000040u32.to_le_bytes()); // Characteristics

    // Export Directory at file offset 0x200 (RVA 0x1000)
    // Section maps: RVA 0x1000 → file offset 0x200
    let ed = 0x200;
    data[ed + 12..ed + 16].copy_from_slice(&0x1050u32.to_le_bytes()); // Name RVA
    data[ed + 16..ed + 20].copy_from_slice(&1u32.to_le_bytes());      // OrdinalBase
    data[ed + 20..ed + 24].copy_from_slice(&2u32.to_le_bytes());      // NumberOfFunctions
    data[ed + 24..ed + 28].copy_from_slice(&2u32.to_le_bytes());      // NumberOfNames
    data[ed + 28..ed + 32].copy_from_slice(&0x1028u32.to_le_bytes()); // AddressOfFunctions
    data[ed + 32..ed + 36].copy_from_slice(&0x1030u32.to_le_bytes()); // AddressOfNames
    data[ed + 36..ed + 40].copy_from_slice(&0x1038u32.to_le_bytes()); // AddressOfNameOrdinals

    // Function address table at 0x228 (RVA 0x1028)
    data[0x228..0x22C].copy_from_slice(&0x2000u32.to_le_bytes());
    data[0x22C..0x230].copy_from_slice(&0x2010u32.to_le_bytes());
    // Name pointer table at 0x230 (RVA 0x1030)
    data[0x230..0x234].copy_from_slice(&0x1060u32.to_le_bytes()); // → "Func1"
    data[0x234..0x238].copy_from_slice(&0x106Au32.to_le_bytes()); // → "Func2"
    // Ordinal table at 0x238 (RVA 0x1038)
    data[0x238..0x23A].copy_from_slice(&0u16.to_le_bytes());
    data[0x23A..0x23C].copy_from_slice(&1u16.to_le_bytes());
    // DLL name at 0x250 (RVA 0x1050)
    data[0x250..0x259].copy_from_slice(b"test.dll\0");
    // Export name "Func1" at 0x260 (RVA 0x1060)
    data[0x260..0x266].copy_from_slice(b"Func1\0");
    // Export name "Func2" at 0x26A (RVA 0x106A)
    data[0x26A..0x270].copy_from_slice(b"Func2\0");

    let output = petriage_run(&data);
    assert_eq!(output.status.code(), Some(0), "PE with exports should parse successfully");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let exports = val.get("exports")
        .and_then(|e| e.as_array())
        .expect("JSON should have exports array");
    assert!(exports.len() >= 2, "should have at least 2 exports, got {}", exports.len());
    for exp in exports {
        assert!(exp.get("ordinal").is_some(), "export missing ordinal field: {:?}", exp);
        assert!(exp.get("name").is_some(), "export missing name field: {:?}", exp);
        assert!(exp.get("rva").is_some(), "export missing rva field: {:?}", exp);
    }
}
