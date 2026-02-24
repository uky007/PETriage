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
        let pad = 0u32 ^ xor_key;
        let off = 0x84 + i * 4;
        data[off..off + 4].copy_from_slice(&pad.to_le_bytes());
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
    let dd1_offset = 0xF8 + 1 * 8;
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
