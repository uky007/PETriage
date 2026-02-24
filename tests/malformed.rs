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
            w.as_str().map_or(false, |s| s.contains("dwLength") && s.contains("exceeds"))
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
            w.as_str().map_or(false, |s| s.contains("content_type") && s.contains("signedData"))
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
