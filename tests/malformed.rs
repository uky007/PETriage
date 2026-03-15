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
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout)
            && let Some(anomalies) = val.get("anomalies").and_then(|a| a.as_array()) {
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

// --- Authenticode tests ---

fn petriage_run_with_args(data: &[u8], extra_args: &[&str]) -> std::process::Output {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("petriage_test_{}_{}.bin", pid, id));
    std::fs::write(&path, data).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_petriage"))
        .args(extra_args)
        .arg(&path)
        .output()
        .expect("failed to run petriage");
    let _ = std::fs::remove_file(&path);
    output
}

/// Helper: build a minimal PE32 with an optional header that has 16 data directories,
/// and enough room to set Certificate Table (DD[4]).
fn build_minimal_pe_with_cert_dd(cert_offset: u32, cert_size: u32) -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C] = 0x80;
    data[0x80] = b'P'; data[0x81] = b'E';
    data[0x84] = 0x4c; data[0x85] = 0x01; // i386
    data[0x86] = 1; // 1 section
    data[0x94] = 0xe0; // SizeOfOptionalHeader
    data[0x96] = 0x02; data[0x97] = 0x01; // EXECUTABLE_IMAGE
    data[0x98] = 0x0b; data[0x99] = 0x01; // PE32
    // ImageBase
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes());
    // SectionAlignment
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes());
    // FileAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());
    // SizeOfImage
    data[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes());
    // SizeOfHeaders
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());
    // NumberOfRvaAndSizes = 16
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());
    // Data Directory[4] = Certificate Table (offset 0xF8 + 4*8 = 0x118)
    let dd4_offset = 0xF8 + 4 * 8; // 0x118
    data[dd4_offset..dd4_offset + 4].copy_from_slice(&cert_offset.to_le_bytes());
    data[dd4_offset + 4..dd4_offset + 8].copy_from_slice(&cert_size.to_le_bytes());
    // Section header at 0x178 (after optional header)
    let sh = 0x178;
    data[sh..sh + 6].copy_from_slice(b".text\0");
    data[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    data[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // CODE|EXECUTE|READ
    data
}

#[test]
fn authenticode_unsigned_pe() {
    // PE with no Certificate Table → signed: false
    let data = build_minimal_pe_with_cert_dd(0, 0);
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let auth = val.get("authenticode").expect("should have authenticode field");
        assert_eq!(auth["signed"], false);
        assert_eq!(auth["parse_ok"], false);
        assert_eq!(auth["trust_verified"], false);
    }
}

#[test]
fn authenticode_truncated_cert_table() {
    // Certificate Table points beyond file → signed: true, parse_ok: false
    let data = build_minimal_pe_with_cert_dd(0x8000, 0x100);
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let auth = val.get("authenticode").expect("should have authenticode field");
        assert_eq!(auth["signed"], true);
        assert_eq!(auth["parse_ok"], false);
        let warnings = auth["warnings"].as_array().expect("warnings should be array");
        assert!(!warnings.is_empty(), "should have warning about bounds");
    }
}

#[test]
fn authenticode_wrong_cert_type() {
    // Valid WIN_CERTIFICATE header but wrong wCertificateType → parse_ok: false
    let mut data = build_minimal_pe_with_cert_dd(0x400, 0x20);
    // Extend data to accommodate the certificate at offset 0x400
    data.resize(0x420, 0);
    // WIN_CERTIFICATE header at 0x400
    data[0x400..0x404].copy_from_slice(&0x20u32.to_le_bytes()); // dwLength
    data[0x404..0x406].copy_from_slice(&0x0200u16.to_le_bytes()); // wRevision
    data[0x406..0x408].copy_from_slice(&0x0001u16.to_le_bytes()); // wCertificateType = X509, not PKCS
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let auth = val.get("authenticode").expect("should have authenticode field");
        assert_eq!(auth["signed"], true);
        assert_eq!(auth["parse_ok"], false);
        // Should have win_certificate info
        assert!(auth.get("win_certificate").is_some());
    }
}

#[test]
fn authenticode_garbage_pkcs7() {
    // Correct cert type but garbage PKCS#7 data → parse_ok: false
    let mut data = build_minimal_pe_with_cert_dd(0x400, 0x20);
    data.resize(0x420, 0xAB); // fill with garbage
    // WIN_CERTIFICATE header at 0x400
    data[0x400..0x404].copy_from_slice(&0x20u32.to_le_bytes()); // dwLength
    data[0x404..0x406].copy_from_slice(&0x0200u16.to_le_bytes()); // wRevision
    data[0x406..0x408].copy_from_slice(&0x0002u16.to_le_bytes()); // PKCS_SIGNED_DATA
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let auth = val.get("authenticode").expect("should have authenticode field");
        assert_eq!(auth["signed"], true);
        assert_eq!(auth["parse_ok"], false);
    }
}

#[test]
fn no_panic_authenticode_overflow_length() {
    // dwLength = 0xFFFFFFFF → should not panic
    let mut data = build_minimal_pe_with_cert_dd(0x400, 0x20);
    data.resize(0x420, 0);
    data[0x400..0x404].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // dwLength
    data[0x404..0x406].copy_from_slice(&0x0200u16.to_le_bytes());
    data[0x406..0x408].copy_from_slice(&0x0002u16.to_le_bytes());
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    assert_no_panic(&output);
}

#[test]
fn authenticode_dwlength_exceeds_cert_size() {
    // dwLength (0x100) > cert_size (0x20) → parse_ok: false with specific warning
    let mut data = build_minimal_pe_with_cert_dd(0x400, 0x20);
    data.resize(0x420, 0);
    // WIN_CERTIFICATE header at 0x400: dwLength=0x100 but DD[4] size is only 0x20
    data[0x400..0x404].copy_from_slice(&0x100u32.to_le_bytes()); // dwLength > cert_size
    data[0x404..0x406].copy_from_slice(&0x0200u16.to_le_bytes()); // wRevision
    data[0x406..0x408].copy_from_slice(&0x0002u16.to_le_bytes()); // PKCS_SIGNED_DATA
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let auth = val.get("authenticode").expect("should have authenticode field");
        assert_eq!(auth["signed"], true);
        assert_eq!(auth["parse_ok"], false);
        let warnings = auth["warnings"].as_array().expect("warnings should be array");
        let has_dwlength_warning = warnings.iter().any(|w| {
            w.as_str().is_some_and(|s| s.contains("dwLength") && s.contains("exceeds"))
        });
        assert!(has_dwlength_warning,
            "should warn about dwLength exceeding cert_size, got: {:?}", warnings);
    }
}

#[test]
fn authenticode_wrong_content_type_oid() {
    // Valid DER ContentInfo but with wrong OID (data instead of signedData)
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    // OID 1.2.840.113549.1.7.1 = id-data (wrong, should be 1.2.840.113549.1.7.2 = signedData)
    let content_info_der: &[u8] = &[
        0x30, 0x0F, // SEQUENCE, length 15
        0x06, 0x09, // OID, length 9
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, // 1.2.840.113549.1.7.1 (id-data)
        0xA0, 0x02, // [0] EXPLICIT, length 2
        0x04, 0x00, // OCTET STRING, empty
    ];
    let cert_blob_len = content_info_der.len();
    let win_cert_len = 8 + cert_blob_len; // WIN_CERTIFICATE header (8) + blob
    let dd_size = win_cert_len as u32;
    let mut data = build_minimal_pe_with_cert_dd(0x400, dd_size);
    data.resize(0x400 + win_cert_len, 0);
    // WIN_CERTIFICATE header
    data[0x400..0x404].copy_from_slice(&(win_cert_len as u32).to_le_bytes());
    data[0x404..0x406].copy_from_slice(&0x0200u16.to_le_bytes()); // wRevision
    data[0x406..0x408].copy_from_slice(&0x0002u16.to_le_bytes()); // PKCS_SIGNED_DATA
    // DER blob
    data[0x408..0x408 + cert_blob_len].copy_from_slice(content_info_der);
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let auth = val.get("authenticode").expect("should have authenticode field");
        assert_eq!(auth["signed"], true);
        assert_eq!(auth["parse_ok"], false);
        let warnings = auth["warnings"].as_array().expect("warnings should be array");
        let has_oid_warning = warnings.iter().any(|w| {
            w.as_str().is_some_and(|s| s.contains("content_type") && s.contains("signedData"))
        });
        assert!(has_oid_warning,
            "should warn about wrong content_type OID, got: {:?}", warnings);
    }
}

/// DER TLV (tag-length-value) encoder for constructing test fixtures
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn der_join(items: &[&[u8]]) -> Vec<u8> {
    items.iter().flat_map(|i| i.iter().copied()).collect()
}

/// Build a minimal PE with a syntactically valid self-signed Authenticode signature.
/// The certificate and CMS structures are valid DER parseable by cms/x509-cert crates.
fn build_pe_with_valid_authenticode() -> Vec<u8> {
    // OID encoded values (pre-computed per X.690 base-128 encoding)
    let oid_sha256_rsa: &[u8] = &[0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B]; // 1.2.840.113549.1.1.11
    let oid_rsa: &[u8]        = &[0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01]; // 1.2.840.113549.1.1.1
    let oid_cn: &[u8]         = &[0x55,0x04,0x03];                                 // 2.5.4.3
    let oid_sha256: &[u8]     = &[0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01]; // 2.16.840.1.101.3.4.2.1
    let oid_signed_data: &[u8]= &[0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02]; // 1.2.840.113549.1.7.2
    let oid_data: &[u8]       = &[0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01]; // 1.2.840.113549.1.7.1

    // Shorthand closures for DER construction
    let oid = |v: &[u8]| der_tlv(0x06, v);
    let seq = |items: &[&[u8]]| der_tlv(0x30, &der_join(items));
    let set = |items: &[&[u8]]| der_tlv(0x31, &der_join(items));
    let int = |v: &[u8]| -> Vec<u8> {
        if !v.is_empty() && v[0] & 0x80 != 0 {
            let mut c = vec![0x00]; c.extend_from_slice(v); der_tlv(0x02, &c)
        } else { der_tlv(0x02, v) }
    };
    let utf8 = |s: &str| der_tlv(0x0C, s.as_bytes());
    let bits = |c: &[u8]| { let mut v = vec![0x00]; v.extend_from_slice(c); der_tlv(0x03, &v) };
    let octs = |c: &[u8]| der_tlv(0x04, c);
    let null = || vec![0x05u8, 0x00];
    let utctime = |s: &str| der_tlv(0x17, s.as_bytes());
    let ctx = |n: u8, c: &[u8]| der_tlv(0xA0 | n, c);

    // Name: SEQUENCE { SET { SEQUENCE { OID cn, UTF8String "Test" } } }
    let name = seq(&[&set(&[&seq(&[&oid(oid_cn), &utf8("Test")])])]);

    // AlgorithmIdentifiers
    let alg_sha256_rsa = seq(&[&oid(oid_sha256_rsa), &null()]);
    let alg_rsa = seq(&[&oid(oid_rsa), &null()]);
    let alg_sha256 = seq(&[&oid(oid_sha256), &null()]);

    // Fake RSA public key (structurally valid SEQUENCE { INTEGER, INTEGER })
    let rsa_key = seq(&[&int(&[0x01; 8]), &int(&[0x01, 0x00, 0x01])]);
    let spki = seq(&[&alg_rsa, &bits(&rsa_key)]);

    // Validity (2025-01-01 to 2030-12-31)
    let validity = seq(&[&utctime("250101000000Z"), &utctime("301231235959Z")]);

    // TBSCertificate (v1 — no explicit version tag needed)
    let tbs = seq(&[
        &int(&[0x01]),       // serialNumber
        &alg_sha256_rsa,     // signature algorithm
        &name,               // issuer
        &validity,           // validity
        &name,               // subject (self-signed)
        &spki,               // subjectPublicKeyInfo
    ]);

    // Certificate
    let cert = seq(&[&tbs, &alg_sha256_rsa, &bits(&[0xAA; 16])]);

    // SignerInfo (references the cert via IssuerAndSerialNumber)
    let sid = seq(&[&name, &int(&[0x01])]);
    let signer_info = seq(&[
        &int(&[0x01]),       // version
        &sid,                // sid: IssuerAndSerialNumber { issuer, serial }
        &alg_sha256,         // digestAlgorithm
        &alg_sha256_rsa,     // signatureAlgorithm
        &octs(&[0xBB; 16]),  // signature (fake)
    ]);

    // SignedData
    let signed_data = seq(&[
        &int(&[0x01]),                          // version
        &set(&[&alg_sha256]),                   // digestAlgorithms
        &seq(&[&oid(oid_data)]),                // encapContentInfo (id-data, no eContent)
        &ctx(0, &cert),                          // [0] IMPLICIT certificates (one cert)
        &set(&[&signer_info]),                   // signerInfos
    ]);

    // ContentInfo
    let content_info = seq(&[
        &oid(oid_signed_data),
        &ctx(0, &signed_data),                   // [0] EXPLICIT content
    ]);

    // Build PE with WIN_CERTIFICATE
    let blob = &content_info;
    let win_cert_len = 8 + blob.len();
    let cert_offset: u32 = 0x400;
    let mut pe = build_minimal_pe_with_cert_dd(cert_offset, win_cert_len as u32);
    pe.resize(cert_offset as usize + win_cert_len, 0);
    let off = cert_offset as usize;
    pe[off..off + 4].copy_from_slice(&(win_cert_len as u32).to_le_bytes());
    pe[off + 4..off + 6].copy_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    pe[off + 6..off + 8].copy_from_slice(&0x0002u16.to_le_bytes()); // PKCS_SIGNED_DATA
    pe[off + 8..off + 8 + blob.len()].copy_from_slice(blob);
    pe
}

#[test]
fn authenticode_valid_self_signed() {
    let data = build_pe_with_valid_authenticode();
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    assert_eq!(output.status.code(), Some(0), "should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let auth = val.get("authenticode").expect("should have authenticode field");
    assert_eq!(auth["signed"], true, "should be signed");
    assert_eq!(auth["parse_ok"], true, "should parse OK for valid CMS structure");
    assert_eq!(auth["trust_verified"], false, "trust verification not implemented");

    // Should have a signer with subject "Test"
    let signer = auth.get("signer").expect("should have signer");
    assert!(!signer.is_null(), "signer should not be null");
    assert_eq!(signer["subject"].as_str().unwrap(), "Test");
    assert_eq!(signer["issuer"].as_str().unwrap(), "Test");
    assert_eq!(signer["is_signer"], true);

    // Should have certificate chain
    let certs = auth["certificates"].as_array().expect("should have certificates array");
    assert!(!certs.is_empty(), "should have at least one certificate");

    // Should have WIN_CERTIFICATE info
    let wc = auth.get("win_certificate").expect("should have win_certificate");
    assert!(wc["length"].as_u64().unwrap() > 8, "win_cert length should be > 8");
    assert_eq!(wc["revision"].as_str().unwrap(), "WIN_CERT_REVISION_2_0");
    assert_eq!(wc["certificate_type"].as_str().unwrap(), "WIN_CERT_TYPE_PKCS_SIGNED_DATA");
}

#[test]
fn authenticode_not_in_json_when_flag_off() {
    // Without -c flag, authenticode should not appear in JSON
    let data = build_minimal_pe_with_cert_dd(0, 0);
    let output = petriage_run_with_args(&data, &["--json", "-H"]); // headers only
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        assert!(val.get("authenticode").is_none(),
            "authenticode should not appear when flag is off");
    }
}

// --- Rich Header tests ---

#[test]
fn rich_header_present_in_pe_with_rich() {
    // Build a minimal PE that has a Rich Header between 0x80 and e_lfanew
    let mut data = vec![0u8; 1024];
    data[0] = b'M'; data[1] = b'Z';
    // e_lfanew = 0x100 (gives room for Rich Header between 0x80 and 0x100)
    data[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes());

    let xor_key: u32 = 0xAABBCCDD;

    // DanS signature at 0x80 (XOR encoded)
    let dans = 0x536E6144u32 ^ xor_key;
    data[0x80..0x84].copy_from_slice(&dans.to_le_bytes());
    // 3 padding dwords (XOR key)
    for i in 0..3 {
        let off = 0x84 + i * 4;
        data[off..off + 4].copy_from_slice(&xor_key.to_le_bytes());
    }

    // One Rich entry at 0x90: comp_id=0x00930042 (prod_id=0x0093, build_id=0x0042), count=7
    let comp_id = 0x00930042u32 ^ xor_key;
    let count = 7u32 ^ xor_key;
    data[0x90..0x94].copy_from_slice(&comp_id.to_le_bytes());
    data[0x94..0x98].copy_from_slice(&count.to_le_bytes());

    // "Rich" marker at 0x98
    data[0x98..0x9C].copy_from_slice(&0x68636952u32.to_le_bytes());
    // XOR key at 0x9C
    data[0x9C..0xA0].copy_from_slice(&xor_key.to_le_bytes());

    // PE signature at 0x100
    data[0x100] = b'P'; data[0x101] = b'E';
    data[0x104] = 0x4c; data[0x105] = 0x01; // i386
    data[0x106..0x108].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    data[0x114..0x116].copy_from_slice(&0xE0u16.to_le_bytes()); // SizeOfOptionalHeader
    data[0x116..0x118].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics
    data[0x118..0x11A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32

    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let rich = val.get("rich_header").expect("should have rich_header field");
        assert_eq!(rich["xor_key_raw"], 0xAABBCCDDu32 as i64);
        let entries = rich["entries"].as_array().expect("entries should be array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["build_id"], 0x0042);
        assert_eq!(entries[0]["prod_id"], 0x0093);
        assert_eq!(entries[0]["count"], 7);
    }
}

#[test]
fn rich_header_absent_when_no_rich() {
    // Standard minimal PE without Rich Header
    let data = build_minimal_pe_with_cert_dd(0, 0);
    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        assert!(val.get("rich_header").is_none(),
            "rich_header should not appear when no Rich Header exists");
    }
}

// --- TLS Directory tests ---

#[test]
fn tls_absent_when_no_tls_directory() {
    let data = build_minimal_pe_with_cert_dd(0, 0);
    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        assert!(val.get("tls").is_none(),
            "tls should not appear when no TLS directory exists");
    }
}

#[test]
fn tls_present_with_tls_directory() {
    // Build a PE with TLS Directory (DD[9])
    let mut data = vec![0u8; 0x600];
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80] = b'P'; data[0x81] = b'E';
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());      // 1 section
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());   // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    data[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes
    // Data Directory[9] = TLS: RVA=0x1000, Size=0x18 (24 bytes for PE32)
    let dd9_offset = 0xF8 + 9 * 8;
    data[dd9_offset..dd9_offset + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    data[dd9_offset + 4..dd9_offset + 8].copy_from_slice(&0x18u32.to_le_bytes());

    // Section header at 0x178
    let sh = 0x178;
    data[sh..sh + 6].copy_from_slice(b".tls\0\0");
    data[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes());  // VirtualSize
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfRawData
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
    data[sh + 36..sh + 40].copy_from_slice(&0xC0000040u32.to_le_bytes()); // READ|WRITE|INITIALIZED_DATA

    // TLS Directory at file offset 0x200 (RVA 0x1000), PE32 format (24 bytes)
    let tls_off = 0x200;
    // RawDataStartVA = 0
    // RawDataEndVA = 0
    // AddressOfIndex = 0
    // AddressOfCallBacks = 0x401080 (VA), which is RVA 0x1080
    data[tls_off + 12..tls_off + 16].copy_from_slice(&0x401080u32.to_le_bytes());
    // SizeOfZeroFill = 0
    // Characteristics = 0

    // Callback array at file offset 0x280 (RVA 0x1080): one callback, then null terminator
    data[0x280..0x284].copy_from_slice(&0x401100u32.to_le_bytes()); // callback VA
    data[0x284..0x288].copy_from_slice(&0u32.to_le_bytes()); // null terminator

    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let tls = val.get("tls").expect("should have tls field");
        assert_eq!(tls["callback_count"], 1);
        let callbacks = tls["callbacks"].as_array().expect("callbacks should be array");
        assert_eq!(callbacks.len(), 1);
    }
}

// --- Debug Directory tests ---

#[test]
fn debug_absent_when_no_debug_directory() {
    let data = build_minimal_pe_with_cert_dd(0, 0);
    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        assert!(val.get("debug").is_none(),
            "debug should not appear when no Debug directory exists");
    }
}

#[test]
fn debug_codeview_rsds_parsed() {
    // Build a PE with Debug Directory containing a CodeView RSDS entry
    let mut data = vec![0u8; 0x600];
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80] = b'P'; data[0x81] = b'E';
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());      // 1 section
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());   // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    data[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes
    // Data Directory[6] = Debug: RVA=0x1000, Size=0x1C (28 bytes = 1 entry)
    let dd6_offset = 0xF8 + 6 * 8;
    data[dd6_offset..dd6_offset + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    data[dd6_offset + 4..dd6_offset + 8].copy_from_slice(&0x1Cu32.to_le_bytes());

    // Section header at 0x178
    let sh = 0x178;
    data[sh..sh + 7].copy_from_slice(b".rdata\0");
    data[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes());  // VirtualSize
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfRawData
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
    data[sh + 36..sh + 40].copy_from_slice(&0x40000040u32.to_le_bytes()); // READ|INITIALIZED_DATA

    // Debug Directory at file offset 0x200 (RVA 0x1000)
    let dd = 0x200;
    // +0: Characteristics (u32) = 0
    // +4: TimeDateStamp (u32) = 0x60000000
    data[dd + 4..dd + 8].copy_from_slice(&0x60000000u32.to_le_bytes());
    // +8: MajorVersion = 0, +10: MinorVersion = 0
    // +12: Type (u32) = 2 (CodeView)
    data[dd + 12..dd + 16].copy_from_slice(&2u32.to_le_bytes());
    // +16: SizeOfData = 0x40
    data[dd + 16..dd + 20].copy_from_slice(&0x40u32.to_le_bytes());
    // +20: AddressOfRawData (RVA) = 0x1080
    data[dd + 20..dd + 24].copy_from_slice(&0x1080u32.to_le_bytes());
    // +24: PointerToRawData (file offset) = 0x280
    data[dd + 24..dd + 28].copy_from_slice(&0x280u32.to_le_bytes());

    // CodeView RSDS data at file offset 0x280
    let cv = 0x280;
    // RSDS signature
    data[cv..cv + 4].copy_from_slice(&0x53445352u32.to_le_bytes());
    // GUID: 16 bytes
    data[cv + 4..cv + 8].copy_from_slice(&0x11223344u32.to_le_bytes()); // Data1
    data[cv + 8..cv + 10].copy_from_slice(&0x5566u16.to_le_bytes());    // Data2
    data[cv + 10..cv + 12].copy_from_slice(&0x7788u16.to_le_bytes());   // Data3
    data[cv + 12..cv + 20].copy_from_slice(&[0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]); // Data4
    // Age
    data[cv + 20..cv + 24].copy_from_slice(&1u32.to_le_bytes());
    // PDB path
    let pdb = b"C:\\build\\test.pdb\0";
    data[cv + 24..cv + 24 + pdb.len()].copy_from_slice(pdb);

    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let debug = val.get("debug").expect("should have debug field");
        let entries = debug["entries"].as_array().expect("entries should be array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["debug_type"], "CodeView");
        assert_eq!(entries[0]["debug_type_raw"], 2);
        assert_eq!(entries[0]["age"], 1);
        let pdb_path = entries[0]["pdb_path"].as_str().expect("should have pdb_path");
        assert_eq!(pdb_path, "C:\\build\\test.pdb");
        let guid = entries[0]["guid"].as_str().expect("should have guid");
        assert_eq!(guid, "11223344-5566-7788-99AA-BBCCDDEEFF00");
    }
}

// --- Filter regression tests (rich_header/tls/debug gated by show_all) ---

#[test]
fn headers_only_excludes_rich_tls_debug() {
    let data = build_minimal_pe_with_cert_dd(0, 0);
    let output = petriage_run_with_args(&data, &["--json", "-H"]);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        // -H should include dos_header and coff_header
        assert!(val.get("dos_header").is_some(), "dos_header should be present with -H");
        assert!(val.get("coff_header").is_some(), "coff_header should be present with -H");
        // -H should NOT include rich_header, tls, or debug (they require show_all)
        assert!(val.get("rich_header").is_none(),
            "rich_header should not appear with -H only");
        assert!(val.get("tls").is_none(),
            "tls should not appear with -H only");
        assert!(val.get("debug").is_none(),
            "debug should not appear with -H only");
    }
}

// --- imphash tests ---

fn build_pe_with_imports() -> Vec<u8> {
    // Build a minimal PE32 with an import table importing KERNEL32.dll!ExitProcess
    let mut data = vec![0u8; 0x600];
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80] = b'P'; data[0x81] = b'E';
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());      // 1 section
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());   // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    data[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes
    // Data Directory[1] = Import Table: RVA=0x1000, Size=0x28 (2 entries: 1 real + 1 null terminator)
    let dd1_offset = 0xF8 + 8;
    data[dd1_offset..dd1_offset + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    data[dd1_offset + 4..dd1_offset + 8].copy_from_slice(&0x28u32.to_le_bytes());

    // Section header at 0x178
    let sh = 0x178;
    data[sh..sh + 7].copy_from_slice(b".rdata\0");
    data[sh + 8..sh + 12].copy_from_slice(&0x400u32.to_le_bytes());  // VirtualSize
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data[sh + 16..sh + 20].copy_from_slice(&0x400u32.to_le_bytes());  // SizeOfRawData
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
    data[sh + 36..sh + 40].copy_from_slice(&0x40000040u32.to_le_bytes()); // READ|INITIALIZED_DATA

    // Import Directory Table at file offset 0x200 (RVA 0x1000)
    // Entry 1: KERNEL32.dll
    let idt = 0x200;
    // OriginalFirstThunk (ILT RVA) = 0x1080
    data[idt..idt + 4].copy_from_slice(&0x1080u32.to_le_bytes());
    // TimeDateStamp = 0
    // ForwarderChain = 0
    // Name RVA = 0x10C0
    data[idt + 12..idt + 16].copy_from_slice(&0x10C0u32.to_le_bytes());
    // FirstThunk (IAT RVA) = 0x1090
    data[idt + 16..idt + 20].copy_from_slice(&0x1090u32.to_le_bytes());
    // Entry 2: null terminator (20 bytes of zeros at idt+20..idt+40 — already zero)

    // Import Lookup Table (ILT) at file offset 0x280 (RVA 0x1080)
    // Entry: Hint/Name RVA = 0x10A0
    data[0x280..0x284].copy_from_slice(&0x10A0u32.to_le_bytes());
    // Null terminator
    data[0x284..0x288].copy_from_slice(&0u32.to_le_bytes());

    // Import Address Table (IAT) at file offset 0x290 (RVA 0x1090)
    data[0x290..0x294].copy_from_slice(&0x10A0u32.to_le_bytes());
    data[0x294..0x298].copy_from_slice(&0u32.to_le_bytes());

    // Hint/Name Table at file offset 0x2A0 (RVA 0x10A0)
    // Hint (u16) = 0
    data[0x2A0..0x2A2].copy_from_slice(&0u16.to_le_bytes());
    // Name = "ExitProcess\0"
    data[0x2A2..0x2AE].copy_from_slice(b"ExitProcess\0");

    // DLL Name at file offset 0x2C0 (RVA 0x10C0)
    data[0x2C0..0x2CD].copy_from_slice(b"KERNEL32.dll\0");

    data
}

#[test]
fn imphash_present_with_imports() {
    let data = build_pe_with_imports();
    let output = petriage_run_with_args(&data, &["--json", "--hashes"]);
    assert_eq!(output.status.code(), Some(0), "should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let hashes = val.get("hashes").expect("should have hashes field");
    let imphash = hashes.get("imphash").expect("should have imphash field");
    let imphash_str = imphash.as_str().expect("imphash should be a string");
    assert_eq!(imphash_str.len(), 32, "imphash should be 32 hex chars, got '{}'", imphash_str);
    assert!(imphash_str.chars().all(|c| c.is_ascii_hexdigit()),
        "imphash should be hex, got '{}'", imphash_str);
}

#[test]
fn imphash_absent_without_imports() {
    // Minimal PE with no import table
    let data = build_minimal_pe_with_cert_dd(0, 0);
    let output = petriage_run_with_args(&data, &["--json", "--hashes"]);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let hashes = val.get("hashes").expect("should have hashes field");
        // imphash should be null or absent (skip_serializing_if = "Option::is_none")
        assert!(hashes.get("imphash").is_none() || hashes["imphash"].is_null(),
            "imphash should be absent/null without imports");
    }
}

// --- --batch --ndjson tests ---

#[test]
fn batch_ndjson_processes_pe_files() {
    let dir = std::env::temp_dir().join(format!("petriage_batch_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);

    // Write 2 minimal PEs and 1 non-PE file
    let pe_data = build_minimal_pe_with_cert_dd(0, 0);
    std::fs::write(dir.join("file1.exe"), &pe_data).unwrap();
    std::fs::write(dir.join("file2.dll"), &pe_data).unwrap();
    std::fs::write(dir.join("readme.txt"), b"not a PE file").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_petriage"))
        .args(["--ndjson", "--batch"])
        .arg(&dir)
        .output()
        .expect("failed to run petriage");

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(output.status.code(), Some(0), "batch should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "should have 2 NDJSON lines (2 PE files), got {}", lines.len());
    for line in &lines {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(parsed.is_ok(), "each NDJSON line should be valid JSON: {}", line);
    }
}

// --- --fail-on tests ---

#[test]
fn fail_on_info_exits_3_with_anomalies() {
    // Minimal PE that triggers at least one info-level anomaly (e.g., no CFG)
    let data = build_minimal_pe_with_cert_dd(0, 0);
    let output = petriage_run_with_args(&data, &["--json", "--fail-on", "info"]);
    // This PE has anomalies (no ASLR/DEP/CFG, timestamp=0, etc.)
    assert_eq!(output.status.code(), Some(3),
        "should exit 3 when anomalies match --fail-on info");
}

#[test]
fn fail_on_critical_exits_0_without_critical() {
    // Minimal PE — typically no critical anomalies (no high entropy, no W^X)
    let mut data = vec![0u8; 1024];
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C] = 0x80;
    data[0x80] = b'P'; data[0x81] = b'E';
    data[0x84] = 0x4c; data[0x85] = 0x01;
    data[0x86] = 0; // 0 sections → no section-based critical anomalies
    data[0x94] = 0xe0;
    data[0x96] = 0x02; data[0x97] = 0x01;
    data[0x98] = 0x0b; data[0x99] = 0x01;
    // Set DLL characteristics to include ASLR+DEP to avoid those anomalies triggering as critical
    // DllCharacteristics at offset 0xDE (0x98 + 0x46)
    data[0xDE..0xE0].copy_from_slice(&0x0160u16.to_le_bytes()); // DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    let output = petriage_run_with_args(&data, &["--json", "--fail-on", "critical"]);
    let code = output.status.code().unwrap();
    assert!(code == 0, "should exit 0 when no critical anomalies, got exit code {}", code);
}

// --- --batch -o (output file) tests ---

#[test]
fn batch_json_output_file() {
    let dir = std::env::temp_dir().join(format!("petriage_batch_json_o_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let pe_data = build_minimal_pe_with_cert_dd(0, 0);
    std::fs::write(dir.join("a.exe"), &pe_data).unwrap();
    std::fs::write(dir.join("b.exe"), &pe_data).unwrap();

    let out_file = std::env::temp_dir().join(format!("petriage_batch_out_{}.json", std::process::id()));

    let output = Command::new(env!("CARGO_BIN_EXE_petriage"))
        .args(["--batch"])
        .arg(&dir)
        .args(["--json", "-o"])
        .arg(&out_file)
        .output()
        .expect("failed to run petriage");

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(output.status.code(), Some(0), "batch --json -o should exit 0");
    assert!(out_file.exists(), "output file should be created");

    let content = std::fs::read_to_string(&out_file).expect("should read output file");
    let _ = std::fs::remove_file(&out_file);

    let val: serde_json::Value = serde_json::from_str(&content)
        .expect("output file should be valid JSON");
    let arr = val.as_array().expect("JSON should be an array");
    assert_eq!(arr.len(), 2, "should have 2 results in JSON array");

    // stdout should NOT contain the JSON (it went to the file)
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("[{"), "JSON should not be on stdout when -o is used");
}

#[test]
fn batch_ndjson_output_file() {
    let dir = std::env::temp_dir().join(format!("petriage_batch_ndjson_o_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let pe_data = build_minimal_pe_with_cert_dd(0, 0);
    std::fs::write(dir.join("x.exe"), &pe_data).unwrap();
    std::fs::write(dir.join("y.exe"), &pe_data).unwrap();
    std::fs::write(dir.join("not_pe.txt"), b"hello").unwrap();

    let out_file = std::env::temp_dir().join(format!("petriage_batch_out_{}.ndjson", std::process::id()));

    let output = Command::new(env!("CARGO_BIN_EXE_petriage"))
        .args(["--batch"])
        .arg(&dir)
        .args(["--ndjson", "-o"])
        .arg(&out_file)
        .output()
        .expect("failed to run petriage");

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(output.status.code(), Some(0), "batch --ndjson -o should exit 0");
    assert!(out_file.exists(), "output file should be created");

    let content = std::fs::read_to_string(&out_file).expect("should read output file");
    let _ = std::fs::remove_file(&out_file);

    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2, "should have 2 NDJSON lines, got {}", lines.len());
    for line in &lines {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(parsed.is_ok(), "each line should be valid JSON: {}", line);
    }
}

#[test]
fn batch_output_write_failure_exits_2() {
    let dir = std::env::temp_dir().join(format!("petriage_batch_wf_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let pe_data = build_minimal_pe_with_cert_dd(0, 0);
    std::fs::write(dir.join("a.exe"), &pe_data).unwrap();

    // Use a path that cannot be written (directory that doesn't exist)
    let bad_path = std::path::PathBuf::from("/nonexistent_dir_12345/output.json");

    let output = Command::new(env!("CARGO_BIN_EXE_petriage"))
        .args(["--batch"])
        .arg(&dir)
        .args(["--json", "-o"])
        .arg(&bad_path)
        .output()
        .expect("failed to run petriage");

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(output.status.code(), Some(2),
        "should exit 2 on write failure, got {}", output.status.code().unwrap());
}

// --- --json --batch error output format test ---

#[test]
fn batch_json_error_is_json_on_stderr() {
    let dir = std::env::temp_dir().join(format!("petriage_batch_jsonerr_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);

    // Write a broken PE (not parseable) with .exe extension so batch picks it up
    std::fs::write(dir.join("broken.exe"), b"MZ\x00\x00not a real PE").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_petriage"))
        .args(["--json", "--batch"])
        .arg(&dir)
        .output()
        .expect("failed to run petriage");

    let _ = std::fs::remove_dir_all(&dir);

    let stderr = String::from_utf8_lossy(&output.stderr);
    // stderr should contain JSON error, not plain text
    for line in stderr.lines() {
        if line.is_empty() { continue; }
        let parsed: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|_| panic!("stderr line should be valid JSON, got: {}", line));
        assert!(parsed.get("error").is_some() || parsed.get("warning").is_some(),
            "JSON stderr should have 'error' or 'warning' key, got: {}", line);
    }
}

// ========================================================================
// OPSEC-001: PDB path detection tests
// ========================================================================

/// Build a minimal PE32 with a CodeView debug directory containing a PDB path.
fn build_pe_with_pdb_path(pdb: &str) -> Vec<u8> {
    let mut data = vec![0u8; 0x800];

    // DOS header
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature
    data[0x80] = b'P'; data[0x81] = b'E';

    // COFF header at 0x84
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());      // 1 section
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());   // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // Optional header at 0x98
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    data[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes

    // Data Directory[6] = Debug Directory: RVA=0x1000, Size=28 (1 entry)
    let dd6_offset = 0xF8 + 6 * 8;
    data[dd6_offset..dd6_offset + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    data[dd6_offset + 4..dd6_offset + 8].copy_from_slice(&28u32.to_le_bytes());

    // Section header at 0x178 (.rdata covering RVA 0x1000)
    let sh = 0x178;
    data[sh..sh + 7].copy_from_slice(b".rdata\0");
    data[sh + 8..sh + 12].copy_from_slice(&0x600u32.to_le_bytes());  // VirtualSize
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data[sh + 16..sh + 20].copy_from_slice(&0x600u32.to_le_bytes());  // SizeOfRawData
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
    data[sh + 36..sh + 40].copy_from_slice(&0x40000040u32.to_le_bytes()); // READ|INITIALIZED_DATA

    // Debug Directory Entry at file offset 0x200 (RVA 0x1000), 28 bytes
    let dde = 0x200;
    // Characteristics (0), TimeDateStamp, MajorVersion, MinorVersion
    data[dde + 12..dde + 16].copy_from_slice(&2u32.to_le_bytes()); // Type = CodeView
    let cv_size = (24 + pdb.len() + 1) as u32; // RSDS header + PDB path + null
    data[dde + 16..dde + 20].copy_from_slice(&cv_size.to_le_bytes()); // SizeOfData
    data[dde + 20..dde + 24].copy_from_slice(&0x1080u32.to_le_bytes()); // AddressOfRawData (RVA)
    data[dde + 24..dde + 28].copy_from_slice(&0x280u32.to_le_bytes()); // PointerToRawData (file offset)

    // CodeView RSDS data at file offset 0x280
    let cv = 0x280;
    data[cv..cv + 4].copy_from_slice(&0x53445352u32.to_le_bytes()); // "RSDS"
    // GUID (16 bytes) at cv+4..cv+20 — leave as zeros
    // Age at cv+20
    data[cv + 20..cv + 24].copy_from_slice(&1u32.to_le_bytes());
    // PDB path at cv+24
    let pdb_bytes = pdb.as_bytes();
    data[cv + 24..cv + 24 + pdb_bytes.len()].copy_from_slice(pdb_bytes);
    data[cv + 24 + pdb_bytes.len()] = 0; // null terminator

    data
}

#[test]
fn opsec_001_fires_with_pdb_path() {
    let pdb = r"C:\Users\attacker\repos\malware\Release\payload.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let anomalies = val.get("anomalies").expect("should have anomalies");
    let arr = anomalies.as_array().expect("anomalies should be array");
    let opsec = arr.iter().find(|a| a.get("rule_id").and_then(|v| v.as_str()) == Some("OPSEC-001"));
    assert!(opsec.is_some(), "OPSEC-001 anomaly should be present, anomalies: {:?}", arr);
    let opsec = opsec.unwrap();
    assert_eq!(opsec.get("severity").and_then(|v| v.as_str()), Some("info"));
    assert_eq!(opsec.get("category").and_then(|v| v.as_str()), Some("OPSEC"));
    let evidence = opsec.get("evidence").and_then(|v| v.as_str()).unwrap_or("");
    assert!(evidence.contains("payload.pdb"), "evidence should contain PDB path, got: {}", evidence);
}

#[test]
fn opsec_001_fires_even_with_hashes_only() {
    // OPSEC-001 anomaly should still appear in anomalies even with --hashes
    let pdb = r"C:\Users\dev\build\test.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json", "--hashes"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let anomalies = val.get("anomalies").expect("should have anomalies");
    let arr = anomalies.as_array().expect("anomalies should be array");
    let opsec = arr.iter().find(|a| a.get("rule_id").and_then(|v| v.as_str()) == Some("OPSEC-001"));
    assert!(opsec.is_some(), "OPSEC-001 should fire even with --hashes filter");
}

#[test]
fn hashes_only_excludes_debug_and_opsec_section() {
    // --hashes should NOT include debug or OPSEC section in JSON output
    let pdb = r"C:\Users\dev\build\test.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json", "--hashes"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    assert!(val.get("debug").is_none(),
        "debug field should be absent with --hashes, got: {}", stdout);
    assert!(val.get("opsec").is_none(),
        "opsec field should be absent with --hashes, got: {}", stdout);
}

#[test]
fn hashes_only_text_excludes_opsec_header() {
    // Text output with --hashes should NOT contain any OPSEC section
    let pdb = r"C:\Users\dev\build\test.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--hashes"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("OPSEC: PDB Path"),
        "text output with --hashes should not contain OPSEC: PDB Path section, got:\n{}", stdout);
    assert!(!stdout.contains("OPSEC Analysis"),
        "text output with --hashes should not contain OPSEC Analysis section, got:\n{}", stdout);
    assert!(stdout.contains("Hashes"),
        "text output with --hashes should contain Hashes section");
}

// --- Rich Header enhanced tests ---

/// Build a PE with a Rich Header and a correctly computed XOR key (checksum).
/// The checksum algorithm:
///   checksum = dans_offset
///     + sum(byte[i].rotate_left(i)) for i in 0..dans_offset, skip 0x3C..0x40
///     + sum(comp_id.rotate_left(count & 0x1F)) for each entry
fn build_pe_with_valid_rich_checksum() -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    data[0] = b'M'; data[1] = b'Z';
    // e_lfanew = 0x100
    let e_lfanew: u32 = 0x100;
    data[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    let dans_offset: usize = 0x80;
    // One entry: comp_id=0x00930042, count=7
    let comp_id: u32 = 0x00930042;
    let count: u32 = 7;

    // Compute checksum (which will become the XOR key)
    let mut checksum: u32 = dans_offset as u32;
    for (i, &byte) in data[..dans_offset].iter().enumerate() {
        if (0x3C..0x40).contains(&i) { continue; }
        checksum = checksum.wrapping_add((byte as u32).rotate_left(i as u32));
    }
    checksum = checksum.wrapping_add(comp_id.rotate_left(count & 0x1F));
    let xor_key = checksum;

    // DanS at 0x80
    let dans = 0x536E6144u32 ^ xor_key;
    data[0x80..0x84].copy_from_slice(&dans.to_le_bytes());
    // 3 padding dwords
    for i in 0..3 {
        let off = 0x84 + i * 4;
        data[off..off + 4].copy_from_slice(&xor_key.to_le_bytes());
    }
    // Entry at 0x90
    data[0x90..0x94].copy_from_slice(&(comp_id ^ xor_key).to_le_bytes());
    data[0x94..0x98].copy_from_slice(&(count ^ xor_key).to_le_bytes());
    // "Rich" marker at 0x98
    data[0x98..0x9C].copy_from_slice(&0x68636952u32.to_le_bytes());
    data[0x9C..0xA0].copy_from_slice(&xor_key.to_le_bytes());

    // PE signature at 0x100
    data[0x100] = b'P'; data[0x101] = b'E';
    data[0x104] = 0x4c; data[0x105] = 0x01; // i386
    data[0x106..0x108].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    data[0x114..0x116].copy_from_slice(&0xE0u16.to_le_bytes()); // SizeOfOptionalHeader
    data[0x116..0x118].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics
    data[0x118..0x11A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    // SectionAlignment, FileAlignment, SizeOfImage, SizeOfHeaders
    let opt_base = 0x118;
    data[opt_base + 0x20..opt_base + 0x24].copy_from_slice(&0x1000u32.to_le_bytes());
    data[opt_base + 0x24..opt_base + 0x28].copy_from_slice(&0x200u32.to_le_bytes());
    data[opt_base + 0x38..opt_base + 0x3C].copy_from_slice(&0x3000u32.to_le_bytes());
    data[opt_base + 0x3C..opt_base + 0x40].copy_from_slice(&0x200u32.to_le_bytes());
    // NumberOfRvaAndSizes
    data[opt_base + 0x5C..opt_base + 0x60].copy_from_slice(&16u32.to_le_bytes());
    // Section header
    let sh = 0x100 + 0x18 + 0xE0; // 0x1F8
    if sh + 40 <= data.len() {
        data[sh..sh + 6].copy_from_slice(b".text\0");
        data[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
        data[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    }
    data
}

#[test]
fn rich_header_hash_computed() {
    // Verify the rich_hash field is computed (MD5 of XOR-decoded data)
    let data = build_pe_with_valid_rich_checksum();
    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let rich = val.get("rich_header").expect("should have rich_header");
        let hash = rich.get("rich_hash").expect("should have rich_hash field");
        let hash_str = hash.as_str().expect("rich_hash should be string");
        assert_eq!(hash_str.len(), 32, "MD5 hash should be 32 hex chars, got: {}", hash_str);
        assert!(hash_str.chars().all(|c| c.is_ascii_hexdigit()),
            "rich_hash should be hex: {}", hash_str);
    }
}

#[test]
fn rich_header_checksum_valid() {
    // PE built with correctly computed XOR key → checksum_valid: true
    let data = build_pe_with_valid_rich_checksum();
    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let rich = val.get("rich_header").expect("should have rich_header");
        assert_eq!(rich["checksum_valid"], true,
            "correctly computed XOR key should give checksum_valid: true");
    }
}

#[test]
fn rich_header_checksum_invalid_triggers_rich_001() {
    // PE with wrong XOR key → checksum_valid: false + RICH-001 anomaly
    let mut data = vec![0u8; 1024];
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes());

    let xor_key: u32 = 0xDEADBEEF; // deliberately wrong
    let dans = 0x536E6144u32 ^ xor_key;
    data[0x80..0x84].copy_from_slice(&dans.to_le_bytes());
    for i in 0..3 {
        let off = 0x84 + i * 4;
        data[off..off + 4].copy_from_slice(&xor_key.to_le_bytes());
    }
    let comp_id = 0x00930042u32 ^ xor_key;
    let count = 7u32 ^ xor_key;
    data[0x90..0x94].copy_from_slice(&comp_id.to_le_bytes());
    data[0x94..0x98].copy_from_slice(&count.to_le_bytes());
    data[0x98..0x9C].copy_from_slice(&0x68636952u32.to_le_bytes());
    data[0x9C..0xA0].copy_from_slice(&xor_key.to_le_bytes());

    data[0x100] = b'P'; data[0x101] = b'E';
    data[0x104] = 0x4c; data[0x105] = 0x01;
    data[0x106..0x108].copy_from_slice(&1u16.to_le_bytes());
    data[0x114..0x116].copy_from_slice(&0xE0u16.to_le_bytes());
    data[0x116..0x118].copy_from_slice(&0x0102u16.to_le_bytes());
    data[0x118..0x11A].copy_from_slice(&0x010Bu16.to_le_bytes());

    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let rich = val.get("rich_header").expect("should have rich_header");
        assert_eq!(rich["checksum_valid"], false,
            "wrong XOR key should give checksum_valid: false");
        // Check RICH-001 anomaly
        let anomalies = val["anomalies"].as_array().expect("should have anomalies");
        assert!(anomalies.iter().any(|a| a["rule_id"] == "RICH-001"),
            "RICH-001 should fire for invalid checksum, anomalies: {:?}", anomalies);
    }
}

#[test]
fn rich_header_entries_have_comp_id_and_description() {
    let data = build_pe_with_valid_rich_checksum();
    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let rich = val.get("rich_header").expect("should have rich_header");
        let entries = rich["entries"].as_array().expect("entries should be array");
        assert!(!entries.is_empty(), "should have at least one entry");
        let e = &entries[0];
        // comp_id should be hex string like "0x00930042"
        let comp_id = e["comp_id"].as_str().expect("comp_id should be string");
        assert!(comp_id.starts_with("0x"), "comp_id should be hex: {}", comp_id);
        // description should exist
        assert!(e.get("description").is_some(), "should have description field");
        let desc = e["description"].as_str().expect("description should be string");
        assert!(!desc.is_empty(), "description should not be empty");
    }
}

#[test]
fn rich_002_fires_for_pe_without_rich_header() {
    // PE without Rich Header but with executable code section > 0x1000 bytes
    let mut data = build_minimal_pe_with_cert_dd(0, 0);
    // Extend to have a code section with raw_size > 0x1000
    data.resize(0x2200, 0);
    // Update section's SizeOfRawData to 0x2000 (> 0x1000 threshold)
    let sh = 0x178; // section header offset in build_minimal_pe_with_cert_dd
    data[sh + 16..sh + 20].copy_from_slice(&0x2000u32.to_le_bytes());
    let output = petriage_run(&data);
    if output.status.code() == Some(0) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .expect("stdout should be valid JSON");
        let anomalies = val["anomalies"].as_array().expect("should have anomalies");
        assert!(anomalies.iter().any(|a| a["rule_id"] == "RICH-002"),
            "RICH-002 should fire for PE without Rich Header, anomalies: {:?}", anomalies);
    }
}

// ========================================================================
// OPSEC-002: PDB path classification tests
// ========================================================================

#[test]
fn opsec_002_pdb_path_classification() {
    let pdb = r"C:\Users\attacker\repos\malware\Release\payload.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let opsec = val.get("opsec").expect("should have opsec section");
    let findings = opsec["findings"].as_array().expect("findings should be array");
    let pdb_finding = findings.iter()
        .find(|f| f["id"] == "OPSEC-002")
        .expect("OPSEC-002 finding should be present");
    assert_eq!(pdb_finding["type"], "pdb_path");
    assert_eq!(pdb_finding["severity"], "info");
    let evidence = &pdb_finding["evidence"];
    assert_eq!(evidence["path_class"], "windows_user_profile");
    assert_eq!(evidence["username_hint"], "attacker");
}

#[test]
fn opsec_002_posix_path() {
    let pdb = "/home/dev/project/build/test.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = val["opsec"]["findings"].as_array().unwrap();
    let f = findings.iter().find(|f| f["id"] == "OPSEC-002").unwrap();
    assert_eq!(f["evidence"]["path_class"], "posix_home");
    assert_eq!(f["evidence"]["username_hint"], "dev");
}

// ========================================================================
// OPSEC-003: Nulled CodeView PDB path tests
// ========================================================================

#[test]
fn opsec_003_nulled_pdb_path() {
    // Build a PE with CodeView RSDS but empty/nulled PDB path
    let data = build_pe_with_pdb_path("");
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let opsec = val.get("opsec").expect("should have opsec section");
    let findings = opsec["findings"].as_array().unwrap();
    let nulled = findings.iter()
        .find(|f| f["id"] == "OPSEC-003")
        .expect("OPSEC-003 should fire for nulled PDB path");
    assert_eq!(nulled["type"], "nulled_pdb");
    assert_eq!(nulled["severity"], "warning");
}

// ========================================================================
// OPSEC-005: Credential pattern tests
// ========================================================================

/// Build a PE with strings embedded in a section
fn build_pe_with_strings(strings: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; 0x1000];

    // DOS header
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature at 0x80
    data[0x80] = b'P'; data[0x81] = b'E';

    // COFF header at 0x84
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());      // 1 section
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());   // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // Optional header at 0x98
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    data[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes

    // Section header at 0x178
    let sh = 0x178;
    data[sh..sh + 6].copy_from_slice(b".data\0");
    data[sh + 8..sh + 12].copy_from_slice(&0x800u32.to_le_bytes());  // VirtualSize
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data[sh + 16..sh + 20].copy_from_slice(&0x800u32.to_le_bytes());  // SizeOfRawData
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
    data[sh + 36..sh + 40].copy_from_slice(&0xC0000040u32.to_le_bytes()); // READ|WRITE|INITIALIZED

    // Embed strings at file offset 0x200
    let mut offset = 0x200;
    for s in strings {
        let bytes = s.as_bytes();
        if offset + bytes.len() + 1 < data.len() {
            data[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len() + 1; // null separator
        }
    }

    data
}

#[test]
fn opsec_005_aws_key_detection() {
    let data = build_pe_with_strings(&[
        "AKIAIOSFODNN7EXAMPLE",
        "some normal string here",
    ]);
    let output = petriage_run_with_args(&data, &["--json", "-a", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let opsec = val.get("opsec").expect("should have opsec section");
    let findings = opsec["findings"].as_array().unwrap();
    let cred = findings.iter().find(|f| f["id"] == "OPSEC-005");
    assert!(cred.is_some(), "OPSEC-005 should fire for AWS key, findings: {:?}", findings);
    let cred = cred.unwrap();
    assert_eq!(cred["severity"], "critical");
    assert_eq!(cred["evidence"]["pattern"], "aws_access_key_id");
}

#[test]
fn opsec_005_slack_token_detection() {
    let data = build_pe_with_strings(&[
        "xoxb-1234567890-abcdefghij",
    ]);
    let output = petriage_run_with_args(&data, &["--json", "-a", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = val["opsec"]["findings"].as_array().unwrap();
    let cred = findings.iter().find(|f|
        f["id"] == "OPSEC-005" && f["evidence"]["pattern"] == "slack_token");
    assert!(cred.is_some(), "OPSEC-005 should fire for Slack token");
}

#[test]
fn opsec_005_github_token_detection() {
    let data = build_pe_with_strings(&[
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    ]);
    let output = petriage_run_with_args(&data, &["--json", "-a", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = val["opsec"]["findings"].as_array().unwrap();
    let cred = findings.iter().find(|f|
        f["id"] == "OPSEC-005" && f["evidence"]["pattern"] == "github_token");
    assert!(cred.is_some(), "OPSEC-005 should fire for GitHub token");
}

// ========================================================================
// OPSEC-006: Endpoint detection tests
// ========================================================================

#[test]
fn opsec_006_internal_url_detection() {
    let data = build_pe_with_strings(&[
        "http://localhost:8080/api/callback",
        "some padding string here",
    ]);
    let output = petriage_run_with_args(&data, &["--json", "-a", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let opsec = val.get("opsec").expect("should have opsec section");
    let findings = opsec["findings"].as_array().unwrap();
    let endpoint = findings.iter().find(|f|
        f["id"] == "OPSEC-006" && f["evidence"]["class"] == "internal");
    assert!(endpoint.is_some(), "OPSEC-006 should fire for localhost URL");
    assert_eq!(endpoint.unwrap()["severity"], "warning");
}

#[test]
fn opsec_006_private_ip_detection() {
    let data = build_pe_with_strings(&[
        "connect to 192.168.1.100 for updates",
    ]);
    let output = petriage_run_with_args(&data, &["--json", "-a", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = val["opsec"]["findings"].as_array().unwrap();
    let ip = findings.iter().find(|f|
        f["id"] == "OPSEC-006" && f["evidence"].get("ip").is_some());
    assert!(ip.is_some(), "OPSEC-006 should fire for private IP, findings: {:?}", findings);
    assert_eq!(ip.unwrap()["evidence"]["class"], "private");
}

// ========================================================================
// OPSEC summary and JSON schema tests
// ========================================================================

#[test]
fn opsec_json_schema_structure() {
    let pdb = r"C:\Users\dev\repos\project\test.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let opsec = val.get("opsec").expect("should have opsec section");

    // Verify summary structure
    let summary = &opsec["summary"];
    assert!(summary["finding_count"].as_u64().unwrap() > 0);
    assert!(summary["max_severity"].is_string());
    assert!(summary["types"].is_object());

    // Verify finding structure
    let findings = opsec["findings"].as_array().unwrap();
    for f in findings {
        assert!(f["id"].is_string(), "finding missing id");
        assert!(f["type"].is_string(), "finding missing type");
        assert!(f["severity"].is_string(), "finding missing severity");
        assert!(f["source"].is_string(), "finding missing source");
        assert!(f["description"].is_string(), "finding missing description");
        assert!(f["evidence"].is_object(), "finding missing evidence");
        assert!(f["confidence"].is_f64(), "finding missing confidence");
    }
}

#[test]
fn opsec_strict_extracts_strings_for_scanning() {
    // Without -a/-S, --opsec-strict should still scan strings for credentials
    let data = build_pe_with_strings(&[
        "AKIAIOSFODNN7EXAMPLE",
    ]);
    let output = petriage_run_with_args(&data, &["--json", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // strings section should NOT be in output (not requested with -a/-S)
    assert!(val.get("strings").is_none(), "strings should not be in output without -a/-S");
    // but OPSEC should detect the credential
    let opsec = val.get("opsec").expect("should have opsec section with --opsec-strict");
    let findings = opsec["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["id"] == "OPSEC-005"),
        "OPSEC-005 should fire with --opsec-strict even without -a");
}

// ========================================================================
// Regression tests for review findings
// ========================================================================

#[test]
fn opsec_001_does_not_fire_on_empty_pdb_path() {
    // OPSEC-001 should not emit "PDB debug path found: " for nulled PDB paths.
    // OPSEC-003 handles those instead.
    let data = build_pe_with_pdb_path("");
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let anomalies = val["anomalies"].as_array().unwrap();
    let opsec_001 = anomalies.iter()
        .find(|a| a["rule_id"] == "OPSEC-001");
    assert!(opsec_001.is_none(),
        "OPSEC-001 should not fire for empty PDB path, anomalies: {:?}", anomalies);
    // OPSEC-003 should fire instead (via opsec.findings)
    let findings = val["opsec"]["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["id"] == "OPSEC-003"),
        "OPSEC-003 should fire for empty PDB path");
}

/// Encode string as null-terminated UTF-16LE bytes
fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for c in s.encode_utf16() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn pad_to_dword(buf: &mut Vec<u8>) {
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

/// Build a VS_VERSIONINFO version string entry (key=value pair)
fn build_ver_string(key: &str, value: &str) -> Vec<u8> {
    let key_bytes = encode_utf16le(key);
    let value_bytes = encode_utf16le(value);
    let value_wchars = value.len() + 1; // including null
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u16.to_le_bytes()); // placeholder wLength
    buf.extend_from_slice(&(value_wchars as u16).to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes()); // wType = text
    buf.extend_from_slice(&key_bytes);
    pad_to_dword(&mut buf);
    buf.extend_from_slice(&value_bytes);
    pad_to_dword(&mut buf);
    let len = buf.len() as u16;
    buf[0..2].copy_from_slice(&len.to_le_bytes());
    buf
}

/// Build a complete VS_VERSIONINFO resource with given string entries
fn build_vs_versioninfo(strings: &[(&str, &str)]) -> Vec<u8> {
    // StringTable children
    let mut table_children = Vec::new();
    for (k, v) in strings {
        table_children.extend_from_slice(&build_ver_string(k, v));
    }

    // StringTable: key="040904b0"
    let table_key = encode_utf16le("040904b0");
    let mut table = Vec::new();
    table.extend_from_slice(&0u16.to_le_bytes()); // placeholder wLength
    table.extend_from_slice(&0u16.to_le_bytes()); // wValueLength = 0
    table.extend_from_slice(&1u16.to_le_bytes()); // wType = text
    table.extend_from_slice(&table_key);
    pad_to_dword(&mut table);
    table.extend_from_slice(&table_children);
    pad_to_dword(&mut table);
    let tlen = table.len() as u16;
    table[0..2].copy_from_slice(&tlen.to_le_bytes());

    // StringFileInfo
    let sfi_key = encode_utf16le("StringFileInfo");
    let mut sfi = Vec::new();
    sfi.extend_from_slice(&0u16.to_le_bytes()); // placeholder wLength
    sfi.extend_from_slice(&0u16.to_le_bytes()); // wValueLength = 0
    sfi.extend_from_slice(&1u16.to_le_bytes()); // wType = text
    sfi.extend_from_slice(&sfi_key);
    pad_to_dword(&mut sfi);
    sfi.extend_from_slice(&table);
    pad_to_dword(&mut sfi);
    let slen = sfi.len() as u16;
    sfi[0..2].copy_from_slice(&slen.to_le_bytes());

    // VS_FIXEDFILEINFO (52 bytes)
    let mut fixed = vec![0u8; 52];
    fixed[0..4].copy_from_slice(&0xFEEF04BDu32.to_le_bytes()); // signature
    fixed[4..8].copy_from_slice(&0x00010000u32.to_le_bytes()); // struc version

    // VS_VERSIONINFO root
    let root_key = encode_utf16le("VS_VERSION_INFO");
    let mut root = Vec::new();
    root.extend_from_slice(&0u16.to_le_bytes()); // placeholder wLength
    root.extend_from_slice(&52u16.to_le_bytes()); // wValueLength = sizeof(FIXEDFILEINFO)
    root.extend_from_slice(&0u16.to_le_bytes()); // wType = binary
    root.extend_from_slice(&root_key);
    pad_to_dword(&mut root);
    root.extend_from_slice(&fixed);
    pad_to_dword(&mut root);
    root.extend_from_slice(&sfi);
    pad_to_dword(&mut root);
    let rlen = root.len() as u16;
    root[0..2].copy_from_slice(&rlen.to_le_bytes());
    root
}

/// Build a PE with a VERSIONINFO resource containing the given company name.
/// No certificate table, so authenticode.signed = false.
fn build_pe_with_version_info(company: &str) -> Vec<u8> {
    let ver_data = build_vs_versioninfo(&[("CompanyName", company)]);
    let mut data = vec![0u8; 0x2000];

    // DOS header
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature
    data[0x80] = b'P'; data[0x81] = b'E';

    // COFF header at 0x84
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    data[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());      // 2 sections
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());   // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // Optional header at 0x98
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    data[0xD0..0xD4].copy_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes

    // Data Directory[2] = Resource Directory: RVA=0x2000, Size=0x1000
    let dd2 = 0xF8 + 2 * 8;
    data[dd2..dd2 + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    data[dd2 + 4..dd2 + 8].copy_from_slice(&0x1000u32.to_le_bytes());

    // Section 1 (.text) at 0x178
    let sh1 = 0x178;
    data[sh1..sh1 + 6].copy_from_slice(b".text\0");
    data[sh1 + 8..sh1 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    data[sh1 + 12..sh1 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    data[sh1 + 16..sh1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    data[sh1 + 20..sh1 + 24].copy_from_slice(&0x200u32.to_le_bytes());
    data[sh1 + 36..sh1 + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

    // Section 2 (.rsrc) at 0x1A0
    let sh2 = 0x1A0;
    data[sh2..sh2 + 6].copy_from_slice(b".rsrc\0");
    data[sh2 + 8..sh2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    data[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    data[sh2 + 16..sh2 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    data[sh2 + 20..sh2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    data[sh2 + 36..sh2 + 40].copy_from_slice(&0x40000040u32.to_le_bytes());

    // Resource directory at file offset 0x400 (RVA 0x2000)
    let rb = 0x400;

    // Level 0: 1 ID entry for RT_VERSION (type 16)
    data[rb + 14..rb + 16].copy_from_slice(&1u16.to_le_bytes());
    data[rb + 16..rb + 20].copy_from_slice(&16u32.to_le_bytes());
    data[rb + 20..rb + 24].copy_from_slice(&0x80000018u32.to_le_bytes());

    // Level 1 at rb+0x18
    let l1 = rb + 0x18;
    data[l1 + 14..l1 + 16].copy_from_slice(&1u16.to_le_bytes());
    data[l1 + 16..l1 + 20].copy_from_slice(&1u32.to_le_bytes());
    data[l1 + 20..l1 + 24].copy_from_slice(&0x80000030u32.to_le_bytes());

    // Level 2 at rb+0x30
    let l2 = rb + 0x30;
    data[l2 + 14..l2 + 16].copy_from_slice(&1u16.to_le_bytes());
    data[l2 + 16..l2 + 20].copy_from_slice(&0x0409u32.to_le_bytes());
    data[l2 + 20..l2 + 24].copy_from_slice(&0x48u32.to_le_bytes());

    // Data entry at rb+0x48
    let de = rb + 0x48;
    let ver_rva = 0x2000u32 + 0x58;
    data[de..de + 4].copy_from_slice(&ver_rva.to_le_bytes());
    data[de + 4..de + 8].copy_from_slice(&(ver_data.len() as u32).to_le_bytes());

    // VS_VERSIONINFO data at rb+0x58
    let vo = rb + 0x58;
    data[vo..vo + ver_data.len()].copy_from_slice(&ver_data);

    data
}

#[test]
fn opsec_004_vendor_mismatch_fires_for_unsigned_vendor_claim() {
    // PE claims CompanyName="Microsoft Corporation" but has no certificate table.
    // Authenticode is evaluated (signed=false), so vendor mismatch should fire.
    let data = build_pe_with_version_info("Microsoft Corporation");
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let anomalies = val["anomalies"].as_array().expect("should have anomalies");
    let vendor = anomalies.iter()
        .find(|a| a["rule_id"] == "OPSEC-004"
            && a["description"].as_str().unwrap_or("").contains("not signed"));
    assert!(vendor.is_some(),
        "OPSEC-004 vendor mismatch should fire for unsigned vendor claim, anomalies: {:?}", anomalies);
}

#[test]
fn opsec_004_vendor_mismatch_absent_when_authenticode_not_evaluated() {
    // With --hashes, authenticode is not parsed, so vendor mismatch should NOT fire,
    // even when the PE claims a known vendor. "Not evaluated" != "unsigned".
    let data = build_pe_with_version_info("Microsoft Corporation");
    let output = petriage_run_with_args(&data, &["--json", "--hashes"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let anomalies = val["anomalies"].as_array().unwrap();
    let vendor = anomalies.iter()
        .find(|a| a["rule_id"] == "OPSEC-004"
            && a["description"].as_str().unwrap_or("").contains("vendor"));
    assert!(vendor.is_none(),
        "OPSEC-004 vendor mismatch should not fire when authenticode is not evaluated");
}

#[test]
fn opsec_004_signed_but_unparseable_is_not_unsigned() {
    // When a PE has a certificate table entry but it can't be parsed
    // (signed=true, parse_ok=false), the description must NOT say "not signed".
    // It should either not fire or say "could not be verified".
    let data = build_pe_with_version_info("Microsoft Corporation");
    // Adding a broken certificate table to make signed=true, parse_ok=false
    let mut data = data;
    // Set Data Directory[4] (Certificate Table) to point to garbage
    let dd4 = 0xF8 + 4 * 8;
    data[dd4..dd4 + 4].copy_from_slice(&0x1C00u32.to_le_bytes()); // offset
    data[dd4 + 4..dd4 + 8].copy_from_slice(&0x100u32.to_le_bytes()); // size
    // Write minimal WIN_CERTIFICATE header at file offset 0x1C00
    let cert_off = 0x1C00;
    if cert_off + 8 <= data.len() {
        data[cert_off..cert_off + 4].copy_from_slice(&0x100u32.to_le_bytes()); // dwLength
        data[cert_off + 4..cert_off + 6].copy_from_slice(&0x0200u16.to_le_bytes()); // wRevision
        data[cert_off + 6..cert_off + 8].copy_from_slice(&0x0002u16.to_le_bytes()); // wCertType=PKCS7
    }
    let output = petriage_run_with_args(&data, &["--json", "-c"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let anomalies = val["anomalies"].as_array().unwrap();
    let false_unsigned = anomalies.iter()
        .find(|a| a["rule_id"] == "OPSEC-004"
            && a["description"].as_str().unwrap_or("").contains("not signed"));
    assert!(false_unsigned.is_none(),
        "OPSEC-004 should not say 'not signed' for signed-but-unparseable PE, anomalies: {:?}", anomalies);
}

#[test]
fn opsec_section_absent_in_limited_output_mode() {
    // In limited output modes like --hashes, the structured opsec section
    // should not appear in JSON (anomalies still present).
    let pdb = r"C:\Users\dev\repos\project\test.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json", "--hashes"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(val.get("opsec").is_none(),
        "opsec section should be absent with --hashes");
    // But anomalies should still contain OPSEC-001
    let anomalies = val["anomalies"].as_array().unwrap();
    assert!(anomalies.iter().any(|a| a["rule_id"] == "OPSEC-001"),
        "OPSEC-001 anomaly should still be present with --hashes");
}

#[test]
fn opsec_strict_with_high_min_str_len() {
    // --opsec-strict should use min_len=6 for credential scanning,
    // even when -a is used with a high --min-str-len that would miss short patterns.
    let data = build_pe_with_strings(&[
        "xoxb-1234567890-abcdefghij",
    ]);
    // Use -a with a high min-str-len that would skip the token
    let output = petriage_run_with_args(&data, &["--json", "-a", "--min-str-len", "30", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let opsec = val.get("opsec")
        .expect("should have opsec section with --opsec-strict");
    let findings = opsec["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["id"] == "OPSEC-005"),
        "OPSEC-005 should fire with --opsec-strict even when --min-str-len is high, findings: {:?}", findings);
}

#[test]
fn opsec_strict_forces_opsec_section_in_limited_mode() {
    // --opsec-strict should include the opsec section even with --hashes
    let pdb = r"C:\Users\dev\repos\project\test.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json", "--hashes", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(val.get("opsec").is_some(),
        "opsec section should be present with --opsec-strict even in limited mode");
}

// --- .NET detection tests ---

fn build_pe_with_dotnet() -> Vec<u8> {
    // Build a PE with Data Directory 14 (COM_DESCRIPTOR) pointing to COR20 header
    // and BSJB metadata root
    let mut data = vec![0u8; 0x2000];

    // DOS header
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature at 0x80
    data[0x80] = b'P'; data[0x81] = b'E';

    // COFF header at 0x84
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());      // 1 section
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());   // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // Optional header at 0x98
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    data[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes

    // Data Directory[14] = COM_DESCRIPTOR: RVA=0x1000, Size=72
    let dd14_offset = 0xF8 + 14 * 8;
    data[dd14_offset..dd14_offset + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    data[dd14_offset + 4..dd14_offset + 8].copy_from_slice(&72u32.to_le_bytes());

    // Section header at 0x178 (.text covering RVA 0x1000)
    let sh = 0x178;
    data[sh..sh + 6].copy_from_slice(b".text\0");
    data[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes());  // VirtualSize
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data[sh + 16..sh + 20].copy_from_slice(&0x1800u32.to_le_bytes()); // SizeOfRawData
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
    data[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // CODE|EXECUTE|READ

    // IMAGE_COR20_HEADER at file offset 0x200 (RVA 0x1000)
    let cor = 0x200;
    data[cor..cor + 4].copy_from_slice(&72u32.to_le_bytes()); // cb
    data[cor + 4..cor + 6].copy_from_slice(&2u16.to_le_bytes()); // MajorRuntimeVersion
    data[cor + 6..cor + 8].copy_from_slice(&5u16.to_le_bytes()); // MinorRuntimeVersion
    // MetaData RVA = 0x1048 (file offset 0x248), Size = 0x100
    data[cor + 8..cor + 12].copy_from_slice(&0x1048u32.to_le_bytes());
    data[cor + 12..cor + 16].copy_from_slice(&0x100u32.to_le_bytes());
    // Flags = IL_ONLY (0x01)
    data[cor + 16..cor + 20].copy_from_slice(&0x01u32.to_le_bytes());

    // Metadata root at file offset 0x248 (RVA 0x1048)
    let meta = 0x248;
    // BSJB signature
    data[meta..meta + 4].copy_from_slice(&0x424A5342u32.to_le_bytes());
    // MajorVersion=1, MinorVersion=1
    data[meta + 4..meta + 6].copy_from_slice(&1u16.to_le_bytes());
    data[meta + 6..meta + 8].copy_from_slice(&1u16.to_le_bytes());
    // Reserved
    data[meta + 8..meta + 12].copy_from_slice(&0u32.to_le_bytes());
    // Length of version string = 12 (padded to 12 from "v4.0.30319\0\0")
    data[meta + 12..meta + 16].copy_from_slice(&12u32.to_le_bytes());
    // Version string
    let ver = b"v4.0.30319\0\0";
    data[meta + 16..meta + 16 + ver.len()].copy_from_slice(ver);

    // After version string: Flags(2) + NumberOfStreams(2)
    let soff = meta + 16 + 12; // 0x274
    data[soff..soff + 2].copy_from_slice(&0u16.to_le_bytes()); // Flags
    data[soff + 2..soff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 stream (#Strings)

    // Stream header: offset, size, name
    let shdr = soff + 4;
    data[shdr..shdr + 4].copy_from_slice(&0xC0u32.to_le_bytes()); // offset from metadata root
    data[shdr + 4..shdr + 8].copy_from_slice(&0x40u32.to_le_bytes()); // size
    let sname = b"#Strings\0\0\0\0"; // padded to 12 bytes (4-byte aligned)
    data[shdr + 8..shdr + 8 + sname.len()].copy_from_slice(sname);

    // #Strings heap at meta + 0xC0 = 0x308
    let strings_off = meta + 0xC0;
    data[strings_off] = 0; // first entry is always empty
    let module_name = b"TestModule\0";
    data[strings_off + 1..strings_off + 1 + module_name.len()].copy_from_slice(module_name);

    data
}

#[test]
fn dotnet_detection_with_clr_header() {
    let data = build_pe_with_dotnet();
    let output = petriage_run_with_args(&data, &["--json", "-a"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let dotnet = val.get("dotnet")
        .expect("should have dotnet section with -a");
    assert!(dotnet["runtime_version"].as_str().unwrap().contains("4.0.30319"),
        "runtime_version should contain v4.0.30319, got: {}", dotnet["runtime_version"]);
    let flags = dotnet["flags"].as_array().unwrap();
    assert!(flags.iter().any(|f| f.as_str() == Some("IL_ONLY")),
        "flags should contain IL_ONLY, got: {:?}", flags);

    // Build fingerprint should show .NET
    let fp = val.get("build_fingerprint").expect("should have build_fingerprint");
    assert_eq!(fp["compiler"].as_str(), Some(".NET"));
    assert!(fp["is_managed"].as_bool() == Some(true));
}

// --- Go detection tests ---

#[test]
fn go_detection_with_markers() {
    let mut data = build_pe_with_strings(&[
        "runtime.go",
        "GOMAXPROCS",
        "some other string",
    ]);
    // Also embed a Go build ID marker
    let marker = b"\xff Go build ID: \"abc123/def456/ghi789/jkl012\"\n \xff";
    let offset = 0x400;
    if offset + marker.len() < data.len() {
        data[offset..offset + marker.len()].copy_from_slice(marker);
    }
    let output = petriage_run_with_args(&data, &["--json", "-a"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let go = val.get("go").expect("should have go section");
    let markers = go["markers"].as_array().unwrap();
    assert!(markers.len() >= 2, "should have at least 2 markers, got: {:?}", markers);
    assert!(go["build_id"].is_string(), "should have build_id");
    assert_eq!(go["build_id"].as_str(), Some("abc123/def456/ghi789/jkl012"));

    // Build fingerprint should show Go
    let fp = val.get("build_fingerprint").expect("should have build_fingerprint");
    assert_eq!(fp["compiler"].as_str(), Some("Go"));
}

#[test]
fn go_detection_absent_with_single_marker() {
    // Only one marker - should not detect Go (needs >= 2)
    let data = build_pe_with_strings(&[
        "runtime.go",
        "some other string",
    ]);
    let output = petriage_run_with_args(&data, &["--json", "-a"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    assert!(val.get("go").is_none(),
        "go section should be absent with only 1 marker");
}

// --- Overlay classification tests ---

#[test]
fn overlay_classification_zip() {
    let mut data = build_pe_with_pdb_path("test.pdb");
    // Append ZIP magic as overlay (after sections end)
    data.extend_from_slice(b"PK\x03\x04rest_of_zip_data_here");
    let output = petriage_run_with_args(&data, &["--json", "--overlay"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let overlay = val.get("overlay").expect("should have overlay");
    assert!(overlay["present"].as_bool() == Some(true));
    let classification = overlay["classification"].as_array()
        .expect("overlay should have classification");
    assert!(classification.iter().any(|c| c["format"].as_str() == Some("ZIP")),
        "classification should include ZIP, got: {:?}", classification);
}

#[test]
fn overlay_classification_nsis() {
    let mut data = build_pe_with_pdb_path("test.pdb");
    // NSIS magic: 0xDEADBEEF (little-endian in overlay)
    data.extend_from_slice(&[0xef, 0xbe, 0xad, 0xde]);
    data.extend_from_slice(b"nsis_data_here");
    let output = petriage_run_with_args(&data, &["--json", "--overlay"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let overlay = val.get("overlay").expect("should have overlay");
    let classification = overlay["classification"].as_array()
        .expect("overlay should have classification");
    assert!(classification.iter().any(|c| c["format"].as_str() == Some("NSIS")),
        "classification should include NSIS, got: {:?}", classification);
}

// --- CI/CD path hint tests ---

#[test]
fn opsec_008_cicd_azure_devops_path() {
    let pdb = r"D:\agent\_work\1\s\src\Release\payload.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json", "-a", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let opsec = val.get("opsec").expect("should have opsec section");
    let findings = opsec["findings"].as_array().unwrap();
    let ci_finding = findings.iter().find(|f| f["id"] == "OPSEC-008");
    assert!(ci_finding.is_some(),
        "OPSEC-008 should fire for Azure DevOps path, findings: {:?}", findings);
    let ci = ci_finding.unwrap();
    assert_eq!(ci["type"].as_str(), Some("ci_cd_trace"));
    let ev = ci["evidence"].as_object().unwrap();
    assert_eq!(ev.get("ci_system").and_then(|v| v.as_str()), Some("ci_azure_devops"));
}

#[test]
fn opsec_008_cicd_github_actions_path() {
    let pdb = r"C:\actions-runner\_work\project\src\Release\app.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json", "-a", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let opsec = val.get("opsec").expect("should have opsec section");
    let findings = opsec["findings"].as_array().unwrap();
    let ci_finding = findings.iter().find(|f| f["id"] == "OPSEC-008");
    assert!(ci_finding.is_some(),
        "OPSEC-008 should fire for GitHub Actions path");
    assert_eq!(ci_finding.unwrap()["evidence"]["ci_system"].as_str(), Some("ci_github_actions"));
}

#[test]
fn opsec_008_cicd_jenkins_path() {
    let pdb = r"C:\jenkins\workspace\project\bin\Release\app.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json", "-a", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let opsec = val.get("opsec").expect("should have opsec section");
    let findings = opsec["findings"].as_array().unwrap();
    let ci_finding = findings.iter().find(|f| f["id"] == "OPSEC-008");
    assert!(ci_finding.is_some(),
        "OPSEC-008 should fire for Jenkins path");
    assert_eq!(ci_finding.unwrap()["evidence"]["ci_system"].as_str(), Some("ci_build_server"));
}

// --- Timestamp correlation tests ---

#[test]
fn time_004_coff_debug_timestamp_mismatch() {
    // Build PE with debug timestamp that differs significantly from COFF timestamp
    let mut data = build_pe_with_pdb_path("test.pdb");

    // Set COFF timestamp to 2024-01-01 00:00:00 UTC (1704067200)
    let coff_ts: u32 = 1704067200;
    data[0x88..0x8C].copy_from_slice(&coff_ts.to_le_bytes());

    // Debug directory entry timestamp at file offset 0x200 + 4 = 0x204
    // (IMAGE_DEBUG_DIRECTORY: Characteristics(4), TimeDateStamp(4))
    let debug_ts: u32 = 1704067200 + 200000; // ~2.3 days later
    data[0x204..0x208].copy_from_slice(&debug_ts.to_le_bytes());

    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let anomalies = val["anomalies"].as_array().expect("should have anomalies");
    let time004 = anomalies.iter().find(|a| a["rule_id"] == "TIME-004");
    assert!(time004.is_some(),
        "TIME-004 should fire for timestamp mismatch > 24h, anomalies: {:?}", anomalies);
    assert_eq!(time004.unwrap()["severity"].as_str(), Some("warning"));
}

#[test]
fn time_004_no_fire_when_timestamps_close() {
    // Build PE where COFF and debug timestamps are within 24h
    let mut data = build_pe_with_pdb_path("test.pdb");

    let coff_ts: u32 = 1704067200;
    data[0x88..0x8C].copy_from_slice(&coff_ts.to_le_bytes());

    // Debug timestamp only 1 hour apart
    let debug_ts: u32 = 1704067200 + 3600;
    data[0x204..0x208].copy_from_slice(&debug_ts.to_le_bytes());

    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let anomalies = val["anomalies"].as_array().expect("should have anomalies");
    let time004 = anomalies.iter().find(|a| a["rule_id"] == "TIME-004");
    assert!(time004.is_none(),
        "TIME-004 should not fire when timestamps are within 24h");
}

// --- InternalName mismatch tests ---

fn build_pe_with_version_info_kv(kv: &[(&str, &str)]) -> Vec<u8> {
    let ver_data = build_vs_versioninfo(kv);
    let mut data = vec![0u8; 0x2000];

    // DOS header
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature
    data[0x80] = b'P'; data[0x81] = b'E';

    // COFF header at 0x84
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    data[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());      // 2 sections
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());   // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // Optional header at 0x98
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    data[0xD0..0xD4].copy_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes

    // Data Directory[2] = Resource Directory: RVA=0x2000, Size=0x1000
    let dd2 = 0xF8 + 2 * 8;
    data[dd2..dd2 + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    data[dd2 + 4..dd2 + 8].copy_from_slice(&0x1000u32.to_le_bytes());

    // Section 1 (.text) at 0x178
    let sh1 = 0x178;
    data[sh1..sh1 + 6].copy_from_slice(b".text\0");
    data[sh1 + 8..sh1 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    data[sh1 + 12..sh1 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    data[sh1 + 16..sh1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    data[sh1 + 20..sh1 + 24].copy_from_slice(&0x200u32.to_le_bytes());
    data[sh1 + 36..sh1 + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

    // Section 2 (.rsrc) at 0x1A0
    let sh2 = 0x1A0;
    data[sh2..sh2 + 6].copy_from_slice(b".rsrc\0");
    data[sh2 + 8..sh2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    data[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    data[sh2 + 16..sh2 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    data[sh2 + 20..sh2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    data[sh2 + 36..sh2 + 40].copy_from_slice(&0x40000040u32.to_le_bytes());

    // Resource directory at file offset 0x400 (RVA 0x2000)
    let rb = 0x400;

    // Level 0: 1 ID entry for RT_VERSION (type 16)
    data[rb + 14..rb + 16].copy_from_slice(&1u16.to_le_bytes());
    data[rb + 16..rb + 20].copy_from_slice(&16u32.to_le_bytes());
    data[rb + 20..rb + 24].copy_from_slice(&0x80000018u32.to_le_bytes());

    // Level 1 at rb+0x18
    let l1 = rb + 0x18;
    data[l1 + 14..l1 + 16].copy_from_slice(&1u16.to_le_bytes());
    data[l1 + 16..l1 + 20].copy_from_slice(&1u32.to_le_bytes());
    data[l1 + 20..l1 + 24].copy_from_slice(&0x80000030u32.to_le_bytes());

    // Level 2 at rb+0x30
    let l2 = rb + 0x30;
    data[l2 + 14..l2 + 16].copy_from_slice(&1u16.to_le_bytes());
    data[l2 + 16..l2 + 20].copy_from_slice(&0x0409u32.to_le_bytes());
    data[l2 + 20..l2 + 24].copy_from_slice(&0x48u32.to_le_bytes());

    // Data entry at rb+0x48
    let de = rb + 0x48;
    let ver_rva = 0x2000u32 + 0x58;
    data[de..de + 4].copy_from_slice(&ver_rva.to_le_bytes());
    data[de + 4..de + 8].copy_from_slice(&(ver_data.len() as u32).to_le_bytes());

    // VS_VERSIONINFO data at rb+0x58
    let vo = rb + 0x58;
    data[vo..vo + ver_data.len()].copy_from_slice(&ver_data);

    data
}

#[test]
fn opsec_004_internal_name_mismatch() {
    // PE with InternalName different from on-disk filename
    let data = build_pe_with_version_info_kv(&[("InternalName", "totally_different.exe")]);
    let output = petriage_run_with_args(&data, &["--json", "-a", "--opsec-strict"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let opsec = val.get("opsec").expect("should have opsec section");
    let findings = opsec["findings"].as_array().unwrap();
    let mismatch = findings.iter().find(|f| {
        f["id"] == "OPSEC-004"
            && f["description"].as_str().unwrap_or("").contains("InternalName")
    });
    assert!(mismatch.is_some(),
        "OPSEC-004 should fire for InternalName mismatch, findings: {:?}", findings);
}

// --- Build fingerprint tests ---

#[test]
fn build_fingerprint_absent_in_limited_mode() {
    let data = build_pe_with_pdb_path("test.pdb");
    let output = petriage_run_with_args(&data, &["--json", "--hashes"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    assert!(val.get("build_fingerprint").is_none(),
        "build_fingerprint should be absent in limited mode");
    assert!(val.get("dotnet").is_none(),
        "dotnet should be absent in limited mode");
    assert!(val.get("go").is_none(),
        "go should be absent in limited mode");
}

#[test]
fn build_fingerprint_rust_from_pdb_path() {
    let pdb = r"C:\Users\dev\repos\myapp\target\release\deps\myapp.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json", "-a"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON");
    let fp = val.get("build_fingerprint").expect("should have build_fingerprint");
    assert_eq!(fp["compiler"].as_str(), Some("Rust"),
        "should detect Rust from PDB path containing target/release");
}

// --- No-panic test for dotnet with truncated metadata ---

#[test]
fn no_panic_dotnet_truncated_metadata() {
    // Build a PE with DD[14] pointing to data but metadata is truncated
    let mut data = vec![0u8; 0x400];
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80] = b'P'; data[0x81] = b'E';
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes());
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes());
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes());
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());
    data[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes());
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());
    // DD[14] = RVA 0x1000, Size 72
    let dd14 = 0xF8 + 14 * 8;
    data[dd14..dd14 + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    data[dd14 + 4..dd14 + 8].copy_from_slice(&72u32.to_le_bytes());
    // Section at 0x178
    let sh = 0x178;
    data[sh..sh + 6].copy_from_slice(b".text\0");
    data[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes());
    data[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    data[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());
    data[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
    data[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    // COR20 header at 0x200 but metadata RVA points to garbage
    let cor = 0x200;
    data[cor..cor + 4].copy_from_slice(&72u32.to_le_bytes());
    data[cor + 4..cor + 6].copy_from_slice(&2u16.to_le_bytes());
    data[cor + 6..cor + 8].copy_from_slice(&5u16.to_le_bytes());
    data[cor + 8..cor + 12].copy_from_slice(&0x1100u32.to_le_bytes()); // points beyond section
    data[cor + 12..cor + 16].copy_from_slice(&0x100u32.to_le_bytes());

    let output = petriage_run_with_args(&data, &["--json"]);
    assert_no_panic(&output);
}

// ========================================================================
// Regression tests for v0.4.0 review findings
// ========================================================================

#[test]
fn signed_pe_no_overlay_false_positive() {
    // A PE with a certificate table should NOT trigger STRUCT-002 (overlay detected).
    // The certificate table sits after sections but is not overlay data.
    let data = build_pe_with_valid_authenticode();
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let anomalies = val["anomalies"].as_array().unwrap();
    let overlay_anomaly = anomalies.iter()
        .find(|a| a["rule_id"] == "STRUCT-002");
    assert!(overlay_anomaly.is_none(),
        "STRUCT-002 should not fire for signed PE with certificate table, anomalies: {:?}", anomalies);
}

#[test]
fn go_detection_requires_structural_marker() {
    // Two string-only markers (runtime.go + GOMAXPROCS) without any structural
    // marker (section name or build ID) should NOT detect Go.
    let data = build_pe_with_strings(&[
        "runtime.go",
        "GOMAXPROCS",
        "some other string",
    ]);
    let output = petriage_run_with_args(&data, &["--json", "-a"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(val.get("go").is_none(),
        "Go should not be detected with only string markers (no structural marker)");
}

#[test]
fn cicd_path_detected_under_user_profile() {
    // CI/CD paths like C:\Users\runneradmin\actions-runner\_work\... should be
    // classified as CI (not WindowsUserProfile) because CI patterns are checked first.
    let pdb = r"C:\Users\runneradmin\actions-runner\_work\proj\test.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let opsec = val.get("opsec").expect("should have opsec");
    let findings = opsec["findings"].as_array().unwrap();
    let ci = findings.iter().find(|f| f["id"] == "OPSEC-008");
    assert!(ci.is_some(),
        "OPSEC-008 should fire for CI path under C:\\Users, findings: {:?}", findings);
}

#[test]
fn cicd_path_jenkins_under_home() {
    // /home/jenkins/workspace/project/build/test.pdb should be CI, not PosixHome
    let pdb = "/home/jenkins/workspace/project/build/test.pdb";
    let data = build_pe_with_pdb_path(pdb);
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let opsec = val.get("opsec").expect("should have opsec");
    let findings = opsec["findings"].as_array().unwrap();
    let ci = findings.iter().find(|f| f["id"] == "OPSEC-008");
    assert!(ci.is_some(),
        "OPSEC-008 should fire for Jenkins path under /home, findings: {:?}", findings);
}

// ========================================================================
// Packer detection regression tests
// ========================================================================

/// Build a PE with custom section names
fn build_pe_with_sections(names: &[&str]) -> Vec<u8> {
    let num_sections = names.len().min(8) as u16;
    let mut data = vec![0u8; 0x1000];

    // DOS header
    data[0] = b'M'; data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature
    data[0x80] = b'P'; data[0x81] = b'E';

    // COFF header at 0x84
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
    data[0x86..0x88].copy_from_slice(&num_sections.to_le_bytes());
    data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
    data[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes());

    // Optional header at 0x98
    data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes());
    data[0xB4..0xB8].copy_from_slice(&0x400000u32.to_le_bytes());
    data[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());
    data[0xD0..0xD4].copy_from_slice(&0x10000u32.to_le_bytes());
    data[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());
    data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());

    // Section headers at 0x178
    for (i, name) in names.iter().enumerate().take(8) {
        let sh = 0x178 + i * 40;
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(8);
        data[sh..sh + copy_len].copy_from_slice(&name_bytes[..copy_len]);
        let rva = (0x1000 + i * 0x1000) as u32;
        data[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes());
        data[sh + 12..sh + 16].copy_from_slice(&rva.to_le_bytes());
        data[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[sh + 20..sh + 24].copy_from_slice(&(0x200 + i as u32 * 0x200).to_le_bytes());
        data[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    }

    data
}

#[test]
fn packer_single_section_no_score_inflation() {
    // A PE with only ".themida" should NOT have matched.len() >= 2
    // (case-variant dedup must prevent inflation)
    let data = build_pe_with_sections(&[".themida"]);
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let fp = val.get("build_fingerprint").expect("should have build_fingerprint");
    let pk = fp.get("packer").expect("should detect packer for .themida section");
    let evidence = pk["evidence"].as_array().unwrap();
    assert_eq!(evidence.len(), 1,
        "single section should produce 1 evidence, got: {:?}", evidence);
    let conf = pk["confidence"].as_f64().unwrap();
    assert!(conf <= 0.55,
        "single spoofable section should have low confidence, got: {}", conf);
}

#[test]
fn packer_upx_detection_with_anomaly_corroboration() {
    // UPX with both sections should have high confidence
    let data = build_pe_with_sections(&["UPX0", "UPX1"]);
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let fp = val.get("build_fingerprint").expect("should have build_fingerprint");
    let pk = fp.get("packer").expect("should detect packer");
    assert_eq!(pk["name"].as_str(), Some("UPX"));
    let conf = pk["confidence"].as_f64().unwrap();
    assert!(conf >= 0.60, "UPX with 2 sections should be >= 0.60, got: {}", conf);
}

#[test]
fn packer_pecompact_single_section_no_dedup_inflation() {
    // PEC2 alone should match once, not twice (pec2+PEC2 case dedup)
    let data = build_pe_with_sections(&["PEC2"]);
    let output = petriage_run_with_args(&data, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let fp = val.get("build_fingerprint").expect("should have build_fingerprint");
    let pk = fp.get("packer").expect("should detect packer for PEC2 section");
    let evidence = pk["evidence"].as_array().unwrap();
    assert_eq!(evidence.len(), 1,
        "PEC2 single section should produce 1 evidence, got: {:?}", evidence);
}
