use std::collections::HashMap;
use std::time::SystemTime;

use goblin::pe::PE;
use md5::Digest;
use serde::Serialize;

use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;

pub struct AnalysisOptions {
    pub show_headers: bool,
    pub show_sections: bool,
    pub show_imports: bool,
    pub show_exports: bool,
    pub show_strings: bool,
    pub show_hashes: bool,
    pub show_overlay: bool,
    pub show_resources: bool,
    pub show_authenticode: bool,
    pub show_all: bool,
    pub min_str_len: usize,
    pub file_name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalysisResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_info: Option<FileInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dos_header: Option<DosHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coff_header: Option<CoffHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional_header: Option<OptionalHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sections: Option<Vec<SectionInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports: Option<Vec<ImportEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exports: Option<Vec<ExportEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<Vec<StringEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<HashInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<OverlayInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticode: Option<AuthenticodeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_header: Option<RichHeaderInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<DebugInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious_summary: Option<SuspiciousSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomalies: Option<Vec<Anomaly>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileInfo {
    pub name: String,
    pub size: usize,
    pub pe_type: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DosHeader {
    pub e_magic: String,
    pub e_lfanew: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct CoffHeader {
    pub machine: String,
    pub machine_raw: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub time_date_stamp_str: String,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
    pub characteristics_str: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OptionalHeader {
    pub magic: String,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u64,
    pub address_of_entry_point: u64,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: String,
    pub dll_characteristics: u16,
    pub dll_characteristics_str: Vec<String>,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DataDirectory {
    pub name: String,
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_address: u32,
    pub characteristics: u32,
    pub characteristics_str: Vec<String>,
    pub entropy: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportEntry {
    pub dll: String,
    pub functions: Vec<FunctionInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FunctionInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<ApiRisk>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiRisk {
    pub category: String,
    pub severity: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SuspiciousSummary {
    pub total_suspicious: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub categories: Vec<CategoryCount>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CategoryCount {
    pub category: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Anomaly {
    pub rule_id: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExportEntry {
    pub name: String,
    pub ordinal: usize,
    pub rva: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct StringEntry {
    pub offset: usize,
    pub value: String,
    pub encoding: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct HashInfo {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OverlayInfo {
    pub offset: usize,
    pub size: usize,
    pub present: bool,
}

#[derive(Clone, Debug)]
pub struct IconGroup {
    pub name: String,
    pub ico_bytes: Vec<u8>,
    pub images: Vec<IconImage>,
}

#[derive(Clone, Debug)]
pub struct IconImage {
    pub width: u32,
    pub height: u32,
    pub bit_count: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResourceInfo {
    pub total_entries: usize,
    pub entries: Vec<ResourceEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(skip)]
    pub icon_data: Vec<IconGroup>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResourceEntry {
    pub resource_type: String,
    pub type_id: u32,
    pub name: String,
    pub language: u32,
    pub language_str: String,
    pub size: u32,
    pub rva: u32,
    pub file_offset: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct VersionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<FixedFileInfo>,
    pub string_info: Vec<VersionString>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FixedFileInfo {
    pub file_version: String,
    pub product_version: String,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_type_str: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VersionString {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthenticodeInfo {
    pub signed: bool,
    pub parse_ok: bool,
    pub trust_verified: bool,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub win_certificate: Option<WinCertificateInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<CertificateEntry>,
    pub certificates: Vec<CertificateEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WinCertificateInfo {
    pub length: u32,
    pub revision: String,
    pub revision_raw: u16,
    pub certificate_type: String,
    pub certificate_type_raw: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificateEntry {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub thumbprint_sha1: String,
    pub is_signer: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RichHeaderInfo {
    pub xor_key: String,
    pub xor_key_raw: u32,
    pub entries: Vec<RichEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RichEntry {
    pub build_id: u16,
    pub prod_id: u16,
    pub count: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct TlsInfo {
    pub raw_data_start: String,
    pub raw_data_end: String,
    pub address_of_index: String,
    pub address_of_callbacks: String,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub callbacks: Vec<String>,
    pub callback_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct DebugInfo {
    pub entries: Vec<DebugEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DebugEntry {
    pub debug_type: String,
    pub debug_type_raw: u32,
    pub timestamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub size_of_data: u32,
    pub pointer_to_raw_data: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdb_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age: Option<u32>,
}

pub fn analyze(data: &[u8], pe: &PE, opts: &AnalysisOptions) -> AnalysisResult {
    let pe_type = if pe.is_64 { "PE32+ (64-bit)" } else { "PE32 (32-bit)" }.to_string();

    let file_info = Some(FileInfo {
        name: opts.file_name.clone(),
        size: data.len(),
        pe_type,
    });

    let dos_header = if opts.show_headers {
        Some(parse_dos_header(data))
    } else {
        None
    };

    let coff_header = if opts.show_headers {
        Some(parse_coff_header(pe))
    } else {
        None
    };

    let optional_header = if opts.show_headers {
        parse_optional_header(pe)
    } else {
        None
    };

    let sections = if opts.show_sections {
        Some(parse_sections(data, pe))
    } else {
        None
    };

    let imports = if opts.show_imports {
        Some(parse_imports(pe))
    } else {
        None
    };

    let exports = if opts.show_exports {
        Some(parse_exports(pe))
    } else {
        None
    };

    let strings = if opts.show_strings {
        Some(extract_strings(data, opts.min_str_len))
    } else {
        None
    };

    let mut hashes = if opts.show_hashes {
        Some(compute_hashes(data))
    } else {
        None
    };
    if let Some(ref mut h) = hashes {
        h.imphash = compute_imphash(pe);
    }

    let overlay = if opts.show_overlay {
        Some(detect_overlay(data, pe))
    } else {
        None
    };

    let resources = if opts.show_resources {
        parse_resources(data, pe)
    } else {
        None
    };

    let authenticode = if opts.show_authenticode {
        Some(parse_authenticode(data, pe))
    } else {
        None
    };

    let rich_header = if opts.show_all { parse_rich_header(data) } else { None };
    let tls = if opts.show_all { parse_tls(data, pe) } else { None };
    // Always parse debug for anomaly detection (OPSEC-001),
    // but only include in output when show_all so that "only" flags
    // like --hashes don't get an unexpected OPSEC section.
    let debug = parse_debug(data, pe);

    let suspicious_summary = imports.as_ref().map(|imp| build_suspicious_summary(imp));

    let anomalies = Some(detect_anomalies(
        &sections, &coff_header, &optional_header, &overlay, &suspicious_summary, &debug,
    ));

    let debug_output = if opts.show_all { debug } else { None };

    AnalysisResult {
        file_info,
        dos_header,
        coff_header,
        optional_header,
        sections,
        imports,
        exports,
        strings,
        hashes,
        overlay,
        resources,
        authenticode,
        rich_header,
        tls,
        debug: debug_output,
        suspicious_summary,
        anomalies,
    }
}

fn detect_anomalies(
    sections: &Option<Vec<SectionInfo>>,
    coff_header: &Option<CoffHeader>,
    optional_header: &Option<OptionalHeader>,
    overlay: &Option<OverlayInfo>,
    suspicious_summary: &Option<SuspiciousSummary>,
    debug: &Option<DebugInfo>,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    let standard_names: &[&str] = &[
        ".text", ".data", ".rdata", ".rsrc", ".reloc",
        ".bss", ".idata", ".edata", ".tls", ".pdata",
    ];

    // Section-based rules
    if let Some(sections) = sections {
        for sec in sections {
            // Rule 1: Entropy > 7.0 — likely encrypted or packed
            if sec.entropy > 7.0 {
                anomalies.push(Anomaly {
                    rule_id: "PACK-001".into(),
                    category: "Packing".into(),
                    severity: "critical".into(),
                    description: format!(
                        "Section '{}' has very high entropy ({:.4}) — likely encrypted or packed",
                        sec.name, sec.entropy
                    ),
                    evidence: Some(format!("entropy={:.4}", sec.entropy)),
                    threshold: Some("7.0".into()),
                });
            }
            // Rule 2: Entropy > 6.5 and executable
            else if sec.entropy > 6.5 && sec.characteristics & 0x20000000 != 0 {
                anomalies.push(Anomaly {
                    rule_id: "PACK-002".into(),
                    category: "Packing".into(),
                    severity: "warning".into(),
                    description: format!(
                        "Executable section '{}' has high entropy ({:.4})",
                        sec.name, sec.entropy
                    ),
                    evidence: Some(format!("entropy={:.4}, characteristics={:#x}", sec.entropy, sec.characteristics)),
                    threshold: Some("6.5".into()),
                });
            }

            // Rule 3: raw_size=0, virtual_size > 0
            if sec.raw_size == 0 && sec.virtual_size > 0 {
                anomalies.push(Anomaly {
                    rule_id: "PACK-003".into(),
                    category: "Packing".into(),
                    severity: "warning".into(),
                    description: format!(
                        "Section '{}' has raw_size=0 but virtual_size={:#x} — runtime unpacking suspected",
                        sec.name, sec.virtual_size
                    ),
                    evidence: Some(format!("raw_size=0, virtual_size={:#x}", sec.virtual_size)),
                    threshold: None,
                });
            }

            // Rule 4: virtual_size > 10 * raw_size
            let ratio = if sec.raw_size > 0 { sec.virtual_size as f64 / sec.raw_size as f64 } else { 0.0 };
            if sec.raw_size > 0 && ratio > 10.0 {
                anomalies.push(Anomaly {
                    rule_id: "PACK-004".into(),
                    category: "Packing".into(),
                    severity: "warning".into(),
                    description: format!(
                        "Section '{}' has abnormal expansion ratio (virtual={:#x}, raw={:#x}, ratio={:.1}x)",
                        sec.name, sec.virtual_size, sec.raw_size, ratio
                    ),
                    evidence: Some(format!("ratio={:.1}x", ratio)),
                    threshold: Some("10.0x".into()),
                });
            }

            // Rule 5: W^X violation (Write + Execute)
            if sec.characteristics & 0x80000000 != 0 && sec.characteristics & 0x20000000 != 0 {
                anomalies.push(Anomaly {
                    rule_id: "CODE-001".into(),
                    category: "Code Integrity".into(),
                    severity: "critical".into(),
                    description: format!(
                        "Section '{}' is both writable and executable (W^X violation)",
                        sec.name
                    ),
                    evidence: Some(format!("characteristics={:#x}", sec.characteristics)),
                    threshold: None,
                });
            }

            // Rule 15: Non-standard section name
            if !standard_names.contains(&sec.name.as_str()) {
                anomalies.push(Anomaly {
                    rule_id: "STRUCT-003".into(),
                    category: "Structure".into(),
                    severity: "info".into(),
                    description: format!("Non-standard section name '{}'", sec.name),
                    evidence: Some(sec.name.clone()),
                    threshold: None,
                });
            }
        }

        // Rule 6: Entry point not in .text
        if let Some(opt) = optional_header {
            let ep = opt.address_of_entry_point;
            if ep > 0 {
                let ep_section = sections.iter().find(|s| {
                    let start = s.virtual_address as u64;
                    let end = start + s.virtual_size as u64;
                    ep >= start && ep < end
                });
                if let Some(sec) = ep_section {
                    if sec.name != ".text" {
                        anomalies.push(Anomaly {
                            rule_id: "CODE-002".into(),
                            category: "Code Integrity".into(),
                            severity: "warning".into(),
                            description: format!(
                                "Entry point ({:#x}) is in section '{}' instead of '.text'",
                                ep, sec.name
                            ),
                            evidence: Some(format!("entry_point={:#x}, section={}", ep, sec.name)),
                            threshold: None,
                        });
                    }
                }
            }
        }

        // Rule 16: Section count 0 or >= 10
        if sections.is_empty() {
            anomalies.push(Anomaly {
                rule_id: "STRUCT-004".into(),
                category: "Structure".into(),
                severity: "warning".into(),
                description: "PE has no sections".into(),
                evidence: Some("section_count=0".into()),
                threshold: None,
            });
        } else if sections.len() >= 10 {
            anomalies.push(Anomaly {
                rule_id: "STRUCT-004".into(),
                category: "Structure".into(),
                severity: "warning".into(),
                description: format!("Unusual number of sections ({})", sections.len()),
                evidence: Some(format!("section_count={}", sections.len())),
                threshold: Some("10".into()),
            });
        }
    }

    // Security feature checks (Rules 7-10)
    if let Some(opt) = optional_header {
        let dll_chars = opt.dll_characteristics;

        // Rule 7: ASLR disabled
        if dll_chars & 0x0040 == 0 {
            anomalies.push(Anomaly {
                rule_id: "SEC-001".into(),
                category: "Security".into(),
                severity: "warning".into(),
                description: "ASLR (DYNAMIC_BASE) is disabled".into(),
                evidence: Some(format!("dll_characteristics={:#06x}", dll_chars)),
                threshold: None,
            });
        }

        // Rule 8: DEP disabled
        if dll_chars & 0x0100 == 0 {
            anomalies.push(Anomaly {
                rule_id: "SEC-002".into(),
                category: "Security".into(),
                severity: "warning".into(),
                description: "DEP (NX_COMPAT) is disabled".into(),
                evidence: Some(format!("dll_characteristics={:#06x}", dll_chars)),
                threshold: None,
            });
        }

        // Rule 9: CFG disabled
        if dll_chars & 0x4000 == 0 {
            anomalies.push(Anomaly {
                rule_id: "SEC-003".into(),
                category: "Security".into(),
                severity: "info".into(),
                description: "Control Flow Guard (GUARD_CF) is not enabled".into(),
                evidence: Some(format!("dll_characteristics={:#06x}", dll_chars)),
                threshold: None,
            });
        }

        // Rule 10: NO_SEH set
        if dll_chars & 0x0400 != 0 {
            anomalies.push(Anomaly {
                rule_id: "SEC-004".into(),
                category: "Security".into(),
                severity: "info".into(),
                description: "NO_SEH is set — SEH-based protections are disabled".into(),
                evidence: Some(format!("dll_characteristics={:#06x}", dll_chars)),
                threshold: None,
            });
        }
    }

    // Timestamp checks (Rules 11-13)
    if let Some(coff) = coff_header {
        let ts = coff.time_date_stamp;
        if ts == 0 {
            // Rule 13: Timestamp is 0
            anomalies.push(Anomaly {
                rule_id: "TIME-003".into(),
                category: "Timestamp".into(),
                severity: "info".into(),
                description: "Timestamp is 0 (stripped or not set)".into(),
                evidence: Some("time_date_stamp=0".into()),
                threshold: None,
            });
        } else {
            // Rule 11: Timestamp in future
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            if now > 0 && ts > now {
                anomalies.push(Anomaly {
                    rule_id: "TIME-001".into(),
                    category: "Timestamp".into(),
                    severity: "warning".into(),
                    description: format!(
                        "Timestamp ({}) is in the future", coff.time_date_stamp_str
                    ),
                    evidence: Some(format!("time_date_stamp={:#x} ({})", ts, coff.time_date_stamp_str)),
                    threshold: Some(format!("now={:#x}", now)),
                });
            }

            // Rule 12: Timestamp before 2000 (946684800 = 2000-01-01 UTC)
            if ts < 946_684_800 {
                anomalies.push(Anomaly {
                    rule_id: "TIME-002".into(),
                    category: "Timestamp".into(),
                    severity: "warning".into(),
                    description: format!(
                        "Timestamp ({}) is before year 2000 — possible forgery",
                        coff.time_date_stamp_str
                    ),
                    evidence: Some(format!("time_date_stamp={:#x} ({})", ts, coff.time_date_stamp_str)),
                    threshold: Some("946684800 (2000-01-01)".into()),
                });
            }
        }
    }

    // Rule 14: Overlay detected
    if let Some(overlay) = overlay {
        if overlay.present {
            anomalies.push(Anomaly {
                rule_id: "STRUCT-002".into(),
                category: "Structure".into(),
                severity: "warning".into(),
                description: format!(
                    "Overlay data detected ({} bytes at offset {:#x})",
                    overlay.size, overlay.offset
                ),
                evidence: Some(format!("offset={:#x}, size={}", overlay.offset, overlay.size)),
                threshold: None,
            });
        }
    }

    // Suspicious combo rules (Rules 17-18)
    if let Some(summary) = suspicious_summary {
        let has_category = |name: &str| {
            summary.categories.iter().any(|c| c.category == name)
        };

        // Rule 17: Process Injection + Evasion
        if has_category("Process Injection") && has_category("Evasion") {
            anomalies.push(Anomaly {
                rule_id: "COMBO-001".into(),
                category: "Suspicious Combo".into(),
                severity: "critical".into(),
                description: "Process Injection + Evasion APIs both present — possible code injection technique".into(),
                evidence: Some("categories=[Process Injection, Evasion]".into()),
                threshold: None,
            });
        }

        // Rule 18: Network + Crypto
        if has_category("Network") && has_category("Crypto") {
            anomalies.push(Anomaly {
                rule_id: "COMBO-002".into(),
                category: "Suspicious Combo".into(),
                severity: "warning".into(),
                description: "Network + Crypto APIs both present — possible encrypted C2 communication".into(),
                evidence: Some("categories=[Network, Crypto]".into()),
                threshold: None,
            });
        }
    }

    // OPSEC-001: PDB debug path found
    if let Some(dbg) = debug {
        for entry in &dbg.entries {
            if let Some(ref pdb) = entry.pdb_path {
                anomalies.push(Anomaly {
                    rule_id: "OPSEC-001".into(),
                    category: "OPSEC".into(),
                    severity: "info".into(),
                    description: format!("PDB debug path found: {}", pdb),
                    evidence: Some(pdb.clone()),
                    threshold: None,
                });
            }
        }
    }

    anomalies
}

fn parse_dos_header(data: &[u8]) -> DosHeader {
    let e_magic = if data.len() >= 2 {
        format!("{:#06x} ({})", u16::from_le_bytes([data[0], data[1]]),
            if data[0] == b'M' && data[1] == b'Z' { "MZ" } else { "Unknown" })
    } else {
        "N/A".to_string()
    };

    let e_lfanew = if data.len() >= 0x3c + 4 {
        u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]])
    } else {
        0
    };

    DosHeader { e_magic, e_lfanew }
}

fn parse_coff_header(pe: &PE) -> CoffHeader {
    let header = &pe.header.coff_header;

    let machine = match header.machine {
        0x014c => "IMAGE_FILE_MACHINE_I386 (x86)",
        0x0200 => "IMAGE_FILE_MACHINE_IA64 (Itanium)",
        0x8664 => "IMAGE_FILE_MACHINE_AMD64 (x64)",
        0xAA64 => "IMAGE_FILE_MACHINE_ARM64",
        0x01c0 => "IMAGE_FILE_MACHINE_ARM",
        0x01c4 => "IMAGE_FILE_MACHINE_ARMNT",
        _ => "Unknown",
    }.to_string();

    let timestamp = header.time_date_stamp;
    let time_str = format_timestamp(timestamp);

    let chars = header.characteristics;
    let mut characteristics_str = Vec::new();
    if chars & 0x0001 != 0 { characteristics_str.push("RELOCS_STRIPPED".into()); }
    if chars & 0x0002 != 0 { characteristics_str.push("EXECUTABLE_IMAGE".into()); }
    if chars & 0x0004 != 0 { characteristics_str.push("LINE_NUMS_STRIPPED".into()); }
    if chars & 0x0008 != 0 { characteristics_str.push("LOCAL_SYMS_STRIPPED".into()); }
    if chars & 0x0020 != 0 { characteristics_str.push("LARGE_ADDRESS_AWARE".into()); }
    if chars & 0x0100 != 0 { characteristics_str.push("32BIT_MACHINE".into()); }
    if chars & 0x0200 != 0 { characteristics_str.push("DEBUG_STRIPPED".into()); }
    if chars & 0x2000 != 0 { characteristics_str.push("DLL".into()); }

    CoffHeader {
        machine,
        machine_raw: header.machine,
        number_of_sections: header.number_of_sections,
        time_date_stamp: timestamp,
        time_date_stamp_str: time_str,
        pointer_to_symbol_table: header.pointer_to_symbol_table,
        number_of_symbols: header.number_of_symbol_table,
        size_of_optional_header: header.size_of_optional_header,
        characteristics: chars,
        characteristics_str,
    }
}

fn parse_optional_header(pe: &PE) -> Option<OptionalHeader> {
    let opt = pe.header.optional_header.as_ref()?;
    let std = &opt.standard_fields;
    let win = &opt.windows_fields;

    let magic = match std.magic {
        0x10b => "PE32 (0x10b)",
        0x20b => "PE32+ (0x20b)",
        _ => "Unknown",
    }.to_string();

    let subsystem = match win.subsystem {
        0 => "UNKNOWN",
        1 => "NATIVE",
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        5 => "OS2_CUI",
        7 => "POSIX_CUI",
        9 => "WINDOWS_CE_GUI",
        10 => "EFI_APPLICATION",
        11 => "EFI_BOOT_SERVICE_DRIVER",
        12 => "EFI_RUNTIME_DRIVER",
        13 => "EFI_ROM",
        14 => "XBOX",
        16 => "WINDOWS_BOOT_APPLICATION",
        _ => "Unknown",
    }.to_string();

    let dll_chars = win.dll_characteristics;
    let mut dll_chars_str = Vec::new();
    if dll_chars & 0x0020 != 0 { dll_chars_str.push("HIGH_ENTROPY_VA".into()); }
    if dll_chars & 0x0040 != 0 { dll_chars_str.push("DYNAMIC_BASE (ASLR)".into()); }
    if dll_chars & 0x0080 != 0 { dll_chars_str.push("FORCE_INTEGRITY".into()); }
    if dll_chars & 0x0100 != 0 { dll_chars_str.push("NX_COMPAT (DEP)".into()); }
    if dll_chars & 0x0200 != 0 { dll_chars_str.push("NO_ISOLATION".into()); }
    if dll_chars & 0x0400 != 0 { dll_chars_str.push("NO_SEH".into()); }
    if dll_chars & 0x0800 != 0 { dll_chars_str.push("NO_BIND".into()); }
    if dll_chars & 0x1000 != 0 { dll_chars_str.push("APPCONTAINER".into()); }
    if dll_chars & 0x2000 != 0 { dll_chars_str.push("WDM_DRIVER".into()); }
    if dll_chars & 0x4000 != 0 { dll_chars_str.push("GUARD_CF".into()); }
    if dll_chars & 0x8000 != 0 { dll_chars_str.push("TERMINAL_SERVER_AWARE".into()); }

    let dd_names = [
        "Export Table", "Import Table", "Resource Table", "Exception Table",
        "Certificate Table", "Base Relocation Table", "Debug", "Architecture",
        "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
        "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved",
    ];

    let data_directories: Vec<DataDirectory> = opt.data_directories.dirs().enumerate()
        .filter(|(_, (_, dd))| dd.virtual_address != 0 || dd.size != 0)
        .map(|(i, (_, dd))| DataDirectory {
            name: dd_names.get(i).unwrap_or(&"Unknown").to_string(),
            virtual_address: dd.virtual_address,
            size: dd.size,
        })
        .collect();

    Some(OptionalHeader {
        magic,
        major_linker_version: std.major_linker_version,
        minor_linker_version: std.minor_linker_version,
        size_of_code: std.size_of_code,
        address_of_entry_point: std.address_of_entry_point,
        image_base: win.image_base,
        section_alignment: win.section_alignment,
        file_alignment: win.file_alignment,
        major_os_version: win.major_operating_system_version,
        minor_os_version: win.minor_operating_system_version,
        size_of_image: win.size_of_image,
        size_of_headers: win.size_of_headers,
        checksum: win.check_sum,
        subsystem,
        dll_characteristics: dll_chars,
        dll_characteristics_str: dll_chars_str,
        number_of_rva_and_sizes: win.number_of_rva_and_sizes,
        data_directories,
    })
}

fn parse_sections(data: &[u8], pe: &PE) -> Vec<SectionInfo> {
    pe.sections.iter().map(|sec| {
        let name = String::from_utf8_lossy(
            &sec.name[..sec.name.iter().position(|&b| b == 0).unwrap_or(sec.name.len())]
        ).to_string();

        let raw_offset = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        let entropy = if raw_size > 0 && raw_offset + raw_size <= data.len() {
            calculate_entropy(&data[raw_offset..raw_offset + raw_size])
        } else {
            0.0
        };

        let chars = sec.characteristics;
        let mut chars_str = Vec::new();
        if chars & 0x00000020 != 0 { chars_str.push("CODE".into()); }
        if chars & 0x00000040 != 0 { chars_str.push("INITIALIZED_DATA".into()); }
        if chars & 0x00000080 != 0 { chars_str.push("UNINITIALIZED_DATA".into()); }
        if chars & 0x02000000 != 0 { chars_str.push("DISCARDABLE".into()); }
        if chars & 0x10000000 != 0 { chars_str.push("SHARED".into()); }
        if chars & 0x20000000 != 0 { chars_str.push("EXECUTE".into()); }
        if chars & 0x40000000 != 0 { chars_str.push("READ".into()); }
        if chars & 0x80000000 != 0 { chars_str.push("WRITE".into()); }

        SectionInfo {
            name,
            virtual_size: sec.virtual_size,
            virtual_address: sec.virtual_address,
            raw_size: sec.size_of_raw_data,
            raw_address: sec.pointer_to_raw_data,
            characteristics: chars,
            characteristics_str: chars_str,
            entropy,
        }
    }).collect()
}

fn parse_imports(pe: &PE) -> Vec<ImportEntry> {
    let risk_db = build_risk_db();
    let mut result = Vec::new();
    for import in &pe.imports {
        let dll = import.dll.to_string();
        let func_name = import.name.to_string();
        let risk = classify_api(&func_name, &risk_db);
        let func_info = FunctionInfo { name: func_name, risk };

        if let Some(entry) = result.iter_mut().find(|e: &&mut ImportEntry| e.dll == dll) {
            entry.functions.push(func_info);
        } else {
            result.push(ImportEntry {
                dll,
                functions: vec![func_info],
            });
        }
    }
    result
}

fn classify_api(name: &str, db: &HashMap<&str, (&str, &str)>) -> Option<ApiRisk> {
    db.get(name).map(|(category, severity)| ApiRisk {
        category: category.to_string(),
        severity: severity.to_string(),
    })
}

fn build_risk_db() -> HashMap<&'static str, (&'static str, &'static str)> {
    let entries: &[(&str, &str, &str)] = &[
        // Process Injection
        ("CreateRemoteThread", "Process Injection", "high"),
        ("CreateRemoteThreadEx", "Process Injection", "high"),
        ("VirtualAllocEx", "Process Injection", "high"),
        ("VirtualAllocExNuma", "Process Injection", "high"),
        ("WriteProcessMemory", "Process Injection", "high"),
        ("NtMapViewOfSection", "Process Injection", "high"),
        ("NtWriteVirtualMemory", "Process Injection", "high"),
        ("NtAllocateVirtualMemory", "Process Injection", "high"),
        ("QueueUserAPC", "Process Injection", "high"),
        ("NtQueueApcThread", "Process Injection", "high"),
        ("SetThreadContext", "Process Injection", "high"),
        ("NtSetContextThread", "Process Injection", "high"),
        ("RtlCreateUserThread", "Process Injection", "high"),
        ("OpenProcess", "Process Injection", "medium"),

        // Code Execution
        ("WinExec", "Code Execution", "high"),
        ("ShellExecuteA", "Code Execution", "high"),
        ("ShellExecuteW", "Code Execution", "high"),
        ("ShellExecuteExA", "Code Execution", "high"),
        ("ShellExecuteExW", "Code Execution", "high"),
        ("CreateProcessA", "Code Execution", "high"),
        ("CreateProcessW", "Code Execution", "high"),
        ("CreateProcessInternalA", "Code Execution", "high"),
        ("CreateProcessInternalW", "Code Execution", "high"),
        ("system", "Code Execution", "high"),
        ("_wsystem", "Code Execution", "high"),
        ("CreateProcessAsUserA", "Code Execution", "high"),
        ("CreateProcessAsUserW", "Code Execution", "high"),
        ("CreateProcessWithLogonW", "Code Execution", "high"),
        ("CreateProcessWithTokenW", "Code Execution", "high"),
        ("NtCreateProcess", "Code Execution", "high"),
        ("NtCreateProcessEx", "Code Execution", "high"),

        // Keylogging / Input Capture
        ("SetWindowsHookExA", "Keylogging / Input", "high"),
        ("SetWindowsHookExW", "Keylogging / Input", "high"),
        ("GetAsyncKeyState", "Keylogging / Input", "high"),
        ("GetKeyState", "Keylogging / Input", "medium"),
        ("GetKeyboardState", "Keylogging / Input", "medium"),
        ("GetRawInputData", "Keylogging / Input", "medium"),
        ("RegisterRawInputDevices", "Keylogging / Input", "medium"),
        ("MapVirtualKeyA", "Keylogging / Input", "low"),
        ("MapVirtualKeyW", "Keylogging / Input", "low"),

        // Anti-Debug
        ("IsDebuggerPresent", "Anti-Debug", "high"),
        ("CheckRemoteDebuggerPresent", "Anti-Debug", "high"),
        ("NtQueryInformationProcess", "Anti-Debug", "high"),
        ("OutputDebugStringA", "Anti-Debug", "medium"),
        ("OutputDebugStringW", "Anti-Debug", "medium"),
        ("NtSetInformationThread", "Anti-Debug", "high"),
        ("NtClose", "Anti-Debug", "low"),
        ("CloseHandle", "Anti-Debug", "low"),

        // Anti-VM / Anti-Sandbox
        ("GetTickCount", "Anti-VM", "medium"),
        ("GetTickCount64", "Anti-VM", "medium"),
        ("QueryPerformanceCounter", "Anti-VM", "medium"),
        ("QueryPerformanceFrequency", "Anti-VM", "low"),
        ("Sleep", "Anti-VM", "low"),
        ("SleepEx", "Anti-VM", "low"),
        ("GetCursorPos", "Anti-VM", "low"),
        ("GetForegroundWindow", "Anti-VM", "low"),

        // Persistence
        ("RegSetValueExA", "Persistence", "high"),
        ("RegSetValueExW", "Persistence", "high"),
        ("RegCreateKeyExA", "Persistence", "high"),
        ("RegCreateKeyExW", "Persistence", "high"),
        ("CreateServiceA", "Persistence", "high"),
        ("CreateServiceW", "Persistence", "high"),
        ("StartServiceA", "Persistence", "medium"),
        ("StartServiceW", "Persistence", "medium"),
        ("ChangeServiceConfigA", "Persistence", "high"),
        ("ChangeServiceConfigW", "Persistence", "high"),
        ("OpenSCManagerA", "Persistence", "medium"),
        ("OpenSCManagerW", "Persistence", "medium"),

        // Privilege Escalation
        ("AdjustTokenPrivileges", "Privilege Escalation", "high"),
        ("OpenProcessToken", "Privilege Escalation", "high"),
        ("OpenThreadToken", "Privilege Escalation", "medium"),
        ("LookupPrivilegeValueA", "Privilege Escalation", "high"),
        ("LookupPrivilegeValueW", "Privilege Escalation", "high"),
        ("ImpersonateLoggedOnUser", "Privilege Escalation", "high"),
        ("DuplicateTokenEx", "Privilege Escalation", "high"),
        ("SetTokenInformation", "Privilege Escalation", "medium"),

        // Crypto
        ("CryptEncrypt", "Crypto", "high"),
        ("CryptDecrypt", "Crypto", "high"),
        ("CryptGenKey", "Crypto", "medium"),
        ("CryptAcquireContextA", "Crypto", "medium"),
        ("CryptAcquireContextW", "Crypto", "medium"),
        ("CryptCreateHash", "Crypto", "low"),
        ("CryptHashData", "Crypto", "low"),
        ("CryptDeriveKey", "Crypto", "medium"),
        ("CryptImportKey", "Crypto", "medium"),
        ("CryptExportKey", "Crypto", "medium"),
        ("BCryptEncrypt", "Crypto", "high"),
        ("BCryptDecrypt", "Crypto", "high"),
        ("BCryptGenerateSymmetricKey", "Crypto", "medium"),

        // Network
        ("InternetOpenA", "Network", "high"),
        ("InternetOpenW", "Network", "high"),
        ("InternetOpenUrlA", "Network", "high"),
        ("InternetOpenUrlW", "Network", "high"),
        ("InternetConnectA", "Network", "high"),
        ("InternetConnectW", "Network", "high"),
        ("InternetReadFile", "Network", "medium"),
        ("InternetWriteFile", "Network", "medium"),
        ("HttpOpenRequestA", "Network", "medium"),
        ("HttpOpenRequestW", "Network", "medium"),
        ("HttpSendRequestA", "Network", "high"),
        ("HttpSendRequestW", "Network", "high"),
        ("URLDownloadToFileA", "Network", "high"),
        ("URLDownloadToFileW", "Network", "high"),
        ("URLDownloadToCacheFileA", "Network", "high"),
        ("URLDownloadToCacheFileW", "Network", "high"),
        ("WSAStartup", "Network", "medium"),
        ("WSASocketA", "Network", "medium"),
        ("WSASocketW", "Network", "medium"),
        ("connect", "Network", "medium"),
        ("send", "Network", "medium"),
        ("recv", "Network", "medium"),
        ("sendto", "Network", "medium"),
        ("recvfrom", "Network", "medium"),
        ("socket", "Network", "medium"),
        ("bind", "Network", "low"),
        ("listen", "Network", "low"),
        ("accept", "Network", "low"),
        ("WinHttpOpen", "Network", "high"),
        ("WinHttpConnect", "Network", "high"),
        ("WinHttpOpenRequest", "Network", "medium"),
        ("WinHttpSendRequest", "Network", "high"),
        ("WinHttpReadData", "Network", "medium"),

        // File / Registry Operations
        ("DeleteFileA", "File / Registry", "high"),
        ("DeleteFileW", "File / Registry", "high"),
        ("MoveFileA", "File / Registry", "medium"),
        ("MoveFileW", "File / Registry", "medium"),
        ("MoveFileExA", "File / Registry", "medium"),
        ("MoveFileExW", "File / Registry", "medium"),
        ("CopyFileA", "File / Registry", "medium"),
        ("CopyFileW", "File / Registry", "medium"),
        ("CreateFileA", "File / Registry", "low"),
        ("CreateFileW", "File / Registry", "low"),
        ("WriteFile", "File / Registry", "low"),
        ("ReadFile", "File / Registry", "low"),
        ("RegOpenKeyExA", "File / Registry", "low"),
        ("RegOpenKeyExW", "File / Registry", "low"),
        ("RegQueryValueExA", "File / Registry", "low"),
        ("RegQueryValueExW", "File / Registry", "low"),
        ("RegDeleteKeyA", "File / Registry", "high"),
        ("RegDeleteKeyW", "File / Registry", "high"),
        ("RegDeleteValueA", "File / Registry", "high"),
        ("RegDeleteValueW", "File / Registry", "high"),

        // Evasion
        ("VirtualProtect", "Evasion", "high"),
        ("VirtualProtectEx", "Evasion", "high"),
        ("NtUnmapViewOfSection", "Evasion", "high"),
        ("SetFileTime", "Evasion", "high"),
        ("SetFileAttributesA", "Evasion", "medium"),
        ("SetFileAttributesW", "Evasion", "medium"),
        ("NtSetInformationFile", "Evasion", "medium"),
        ("CreateFileMappingA", "Evasion", "medium"),
        ("CreateFileMappingW", "Evasion", "medium"),
        ("MapViewOfFile", "Evasion", "medium"),
        ("UnmapViewOfFile", "Evasion", "low"),

        // Info Gathering
        ("GetComputerNameA", "Info Gathering", "medium"),
        ("GetComputerNameW", "Info Gathering", "medium"),
        ("GetUserNameA", "Info Gathering", "medium"),
        ("GetUserNameW", "Info Gathering", "medium"),
        ("GetSystemInfo", "Info Gathering", "medium"),
        ("GetNativeSystemInfo", "Info Gathering", "medium"),
        ("GetVersionExA", "Info Gathering", "low"),
        ("GetVersionExW", "Info Gathering", "low"),
        ("GetSystemDirectoryA", "Info Gathering", "low"),
        ("GetSystemDirectoryW", "Info Gathering", "low"),
        ("GetWindowsDirectoryA", "Info Gathering", "low"),
        ("GetWindowsDirectoryW", "Info Gathering", "low"),
        ("GetTempPathA", "Info Gathering", "low"),
        ("GetTempPathW", "Info Gathering", "low"),
        ("GetModuleFileNameA", "Info Gathering", "low"),
        ("GetModuleFileNameW", "Info Gathering", "low"),
        ("GetCurrentProcessId", "Info Gathering", "low"),
        ("GetCurrentProcess", "Info Gathering", "low"),
        ("GetEnvironmentVariableA", "Info Gathering", "low"),
        ("GetEnvironmentVariableW", "Info Gathering", "low"),
        ("GetAdaptersInfo", "Info Gathering", "medium"),
        ("GetAdaptersAddresses", "Info Gathering", "medium"),
        ("NetUserEnum", "Info Gathering", "medium"),
        ("NetShareEnum", "Info Gathering", "medium"),
        ("LookupAccountSidA", "Info Gathering", "low"),
        ("LookupAccountSidW", "Info Gathering", "low"),
        ("GetModuleHandleA", "Info Gathering", "low"),
        ("GetModuleHandleW", "Info Gathering", "low"),
        ("GetProcAddress", "Info Gathering", "medium"),
        ("LoadLibraryA", "Info Gathering", "medium"),
        ("LoadLibraryW", "Info Gathering", "medium"),
        ("LoadLibraryExA", "Info Gathering", "medium"),
        ("LoadLibraryExW", "Info Gathering", "medium"),
    ];

    entries.iter().map(|&(name, cat, sev)| (name, (cat, sev))).collect()
}

fn build_suspicious_summary(imports: &[ImportEntry]) -> SuspiciousSummary {
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut cat_counts: HashMap<String, usize> = HashMap::new();

    for entry in imports {
        for func in &entry.functions {
            if let Some(ref risk) = func.risk {
                match risk.severity.as_str() {
                    "high" => high += 1,
                    "medium" => medium += 1,
                    "low" => low += 1,
                    _ => {}
                }
                *cat_counts.entry(risk.category.clone()).or_insert(0) += 1;
            }
        }
    }

    let total_suspicious = high + medium + low;
    let mut categories: Vec<CategoryCount> = cat_counts
        .into_iter()
        .map(|(category, count)| CategoryCount { category, count })
        .collect();
    categories.sort_by(|a, b| b.count.cmp(&a.count));

    SuspiciousSummary {
        total_suspicious,
        high_count: high,
        medium_count: medium,
        low_count: low,
        categories,
    }
}

fn parse_exports(pe: &PE) -> Vec<ExportEntry> {
    let ordinal_base = pe.export_data
        .as_ref()
        .map(|d| d.export_directory_table.ordinal_base as usize)
        .unwrap_or(0);

    // goblin exposes each Export with an offset (file offset) and rva.
    // The ordinal for a named export is looked up via the ordinal table
    // (name_index -> ordinal_table[name_index] + ordinal_base).
    // goblin's export list is ordered by address table index, so
    // ordinal = ordinal_base + index is correct for the address table.
    // However, there is no per-Export ordinal field in goblin, so we
    // use this as the best available approximation.
    pe.exports.iter().enumerate().map(|(i, exp)| {
        ExportEntry {
            name: exp.name.unwrap_or("(ordinal only)").to_string(),
            ordinal: ordinal_base.saturating_add(i),
            rva: exp.rva,
        }
    }).collect()
}

const MAX_STRINGS: usize = 100_000;

fn extract_strings(data: &[u8], min_len: usize) -> Vec<StringEntry> {
    let mut strings = Vec::new();

    // ASCII strings
    let mut current = Vec::new();
    let mut start = 0;
    for (i, &byte) in data.iter().enumerate() {
        if byte >= 0x20 && byte < 0x7f {
            if current.is_empty() {
                start = i;
            }
            current.push(byte);
        } else {
            if current.len() >= min_len {
                strings.push(StringEntry {
                    offset: start,
                    value: String::from_utf8_lossy(&current).to_string(),
                    encoding: "ASCII".to_string(),
                });
                if strings.len() >= MAX_STRINGS {
                    strings.sort_by_key(|s| s.offset);
                    return strings;
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        strings.push(StringEntry {
            offset: start,
            value: String::from_utf8_lossy(&current).to_string(),
            encoding: "ASCII".to_string(),
        });
    }

    if strings.len() >= MAX_STRINGS {
        strings.sort_by_key(|s| s.offset);
        return strings;
    }

    // UTF-16LE strings
    if data.len() >= 2 {
        let mut current_u16 = Vec::new();
        let mut start_u16 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            let wchar = u16::from_le_bytes([data[i], data[i + 1]]);
            if wchar >= 0x20 && wchar < 0x7f {
                if current_u16.is_empty() {
                    start_u16 = i;
                }
                current_u16.push(wchar);
            } else {
                if current_u16.len() >= min_len {
                    let s: String = current_u16.iter()
                        .filter_map(|&c| char::from_u32(c as u32))
                        .collect();
                    // Only add if it doesn't duplicate an ASCII string at the same position
                    if !strings.iter().any(|e| e.offset == start_u16 && e.value == s) {
                        strings.push(StringEntry {
                            offset: start_u16,
                            value: s,
                            encoding: "UTF-16LE".to_string(),
                        });
                        if strings.len() >= MAX_STRINGS {
                            strings.sort_by_key(|s| s.offset);
                            return strings;
                        }
                    }
                }
                current_u16.clear();
            }
            i += 2;
        }
        if current_u16.len() >= min_len && strings.len() < MAX_STRINGS {
            let s: String = current_u16.iter()
                .filter_map(|&c| char::from_u32(c as u32))
                .collect();
            if !strings.iter().any(|e| e.offset == start_u16 && e.value == s) {
                strings.push(StringEntry {
                    offset: start_u16,
                    value: s,
                    encoding: "UTF-16LE".to_string(),
                });
            }
        }
    }

    strings.sort_by_key(|s| s.offset);
    strings
}

fn compute_hashes(data: &[u8]) -> HashInfo {
    let md5_result = {
        let mut hasher = Md5::new();
        Digest::update(&mut hasher, data);
        format!("{:x}", hasher.finalize())
    };

    let sha1_result = {
        let mut hasher = Sha1::new();
        Digest::update(&mut hasher, data);
        format!("{:x}", hasher.finalize())
    };

    let sha256_result = {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, data);
        format!("{:x}", hasher.finalize())
    };

    HashInfo {
        md5: md5_result,
        sha1: sha1_result,
        sha256: sha256_result,
        imphash: None,
    }
}

fn compute_imphash(pe: &PE) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for import in &pe.imports {
        let dll_raw = import.dll.to_lowercase();
        let dll = dll_raw
            .strip_suffix(".dll")
            .or_else(|| dll_raw.strip_suffix(".ocx"))
            .or_else(|| dll_raw.strip_suffix(".sys"))
            .unwrap_or(&dll_raw);
        let func = if import.name.is_empty() {
            format!("ord{}", import.ordinal)
        } else {
            import.name.to_lowercase()
        };
        parts.push(format!("{}.{}", dll, func));
    }
    if parts.is_empty() {
        return None;
    }
    let joined = parts.join(",");
    let mut hasher = Md5::new();
    Digest::update(&mut hasher, joined.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

fn detect_overlay(data: &[u8], pe: &PE) -> OverlayInfo {
    // The overlay starts after the last section's raw data
    let end_of_pe = pe.sections.iter()
        .filter_map(|s| s.pointer_to_raw_data.checked_add(s.size_of_raw_data))
        .map(|v| v as usize)
        .max()
        .unwrap_or(0);

    if end_of_pe < data.len() && end_of_pe > 0 {
        OverlayInfo {
            offset: end_of_pe,
            size: data.len() - end_of_pe,
            present: true,
        }
    } else {
        OverlayInfo {
            offset: 0,
            size: 0,
            present: false,
        }
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn format_timestamp(timestamp: u32) -> String {
    if timestamp == 0 {
        return "N/A".to_string();
    }
    // Simple UTC conversion
    let secs = timestamp as i64;
    // Unix epoch: 1970-01-01
    // Calculate date components
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simple days-to-date conversion
    let mut y = 1970i64;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let days_in_months: [i64; 12] = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0;
    for (i, &dm) in days_in_months.iter().enumerate() {
        if remaining_days < dm {
            m = i + 1;
            break;
        }
        remaining_days -= dm;
    }
    let d = remaining_days + 1;

    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, m, d, hours, minutes, seconds)
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// --- Resource directory parsing ---

fn rva_to_offset(rva: u32, pe: &PE, data_len: usize) -> Option<usize> {
    for sec in &pe.sections {
        let sec_rva = sec.virtual_address;
        let sec_end = match sec_rva.checked_add(sec.virtual_size) {
            Some(v) => v,
            None => continue, // skip this section on overflow
        };
        if rva >= sec_rva && rva < sec_end {
            let delta = rva - sec_rva;
            let offset = match sec.pointer_to_raw_data.checked_add(delta) {
                Some(v) => v as usize,
                None => continue,
            };
            if offset < data_len {
                return Some(offset);
            }
        }
    }
    None
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}

fn read_utf16_string(data: &[u8], offset: usize, char_count: usize) -> Option<String> {
    let byte_len = char_count * 2;
    if offset + byte_len > data.len() {
        return None;
    }
    let chars: Vec<u16> = (0..char_count)
        .map(|i| read_u16_le(data, offset + i * 2))
        .collect();
    Some(String::from_utf16_lossy(&chars))
}

fn read_utf16_string_until_null(data: &[u8], offset: usize) -> Option<String> {
    let mut chars = Vec::new();
    let max_chars = 512;
    let mut pos = offset;
    for _ in 0..max_chars {
        if pos + 2 > data.len() {
            break;
        }
        let ch = read_u16_le(data, pos);
        if ch == 0 {
            break;
        }
        chars.push(ch);
        pos += 2;
    }
    if chars.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&chars))
}

fn read_resource_name_string(data: &[u8], base_offset: usize, name_offset: usize) -> Option<String> {
    let pos = base_offset + name_offset;
    if pos + 2 > data.len() {
        return None;
    }
    let length = read_u16_le(data, pos) as usize;
    if length == 0 || length > 256 {
        return None;
    }
    read_utf16_string(data, pos + 2, length)
}

fn align_up(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return value;
    }
    (value + alignment - 1) & !(alignment - 1)
}

fn resource_type_name(type_id: u32) -> String {
    match type_id {
        1 => "RT_CURSOR".into(),
        2 => "RT_BITMAP".into(),
        3 => "RT_ICON".into(),
        4 => "RT_MENU".into(),
        5 => "RT_DIALOG".into(),
        6 => "RT_STRING".into(),
        7 => "RT_FONTDIR".into(),
        8 => "RT_FONT".into(),
        9 => "RT_ACCELERATOR".into(),
        10 => "RT_RCDATA".into(),
        11 => "RT_MESSAGETABLE".into(),
        12 => "RT_GROUP_CURSOR".into(),
        14 => "RT_GROUP_ICON".into(),
        16 => "RT_VERSION".into(),
        17 => "RT_DLGINCLUDE".into(),
        19 => "RT_PLUGPLAY".into(),
        20 => "RT_VXD".into(),
        21 => "RT_ANICURSOR".into(),
        22 => "RT_ANIICON".into(),
        23 => "RT_HTML".into(),
        24 => "RT_MANIFEST".into(),
        _ => format!("#{}", type_id),
    }
}

fn language_id_to_string(lang_id: u32) -> String {
    let primary = lang_id & 0x3FF;
    let sub = (lang_id >> 10) & 0x3F;
    match (primary, sub) {
        (0, 0) => "Neutral".into(),
        (0, 1) => "Default".into(),
        (0x09, 0x01) => "en-US".into(),
        (0x09, 0x02) => "en-GB".into(),
        (0x09, 0x03) => "en-AU".into(),
        (0x09, 0x04) => "en-CA".into(),
        (0x09, _) => "en".into(),
        (0x04, 0x01) => "zh-Hans".into(),
        (0x04, 0x02) => "zh-Hant".into(),
        (0x04, _) => "zh".into(),
        (0x11, _) => "ja".into(),
        (0x12, _) => "ko".into(),
        (0x07, _) => "de".into(),
        (0x0C, _) => "fr".into(),
        (0x0A, _) => "es".into(),
        (0x10, _) => "it".into(),
        (0x16, _) => "pt".into(),
        (0x19, _) => "ru".into(),
        (0x1D, _) => "sv".into(),
        (0x13, _) => "nl".into(),
        (0x15, _) => "pl".into(),
        (0x1F, _) => "tr".into(),
        (0x01, _) => "ar".into(),
        (0x0D, _) => "he".into(),
        (0x1E, _) => "th".into(),
        (0x2A, _) => "vi".into(),
        (0x21, _) => "id".into(),
        (0x39, _) => "hi".into(),
        _ => format!("{:#06x}", lang_id),
    }
}

fn file_type_str(file_type: u32) -> String {
    match file_type {
        0 => "Unknown".into(),
        1 => "Application".into(),
        2 => "DLL".into(),
        3 => "Driver".into(),
        4 => "Font".into(),
        5 => "VXD".into(),
        7 => "Static Library".into(),
        _ => format!("{:#x}", file_type),
    }
}

fn parse_resources(data: &[u8], pe: &PE) -> Option<ResourceInfo> {
    // Get Data Directory index 2 (Resource Table)
    let opt = pe.header.optional_header.as_ref()?;
    let (rsrc_rva, rsrc_size) = match opt.data_directories.data_directories.get(2) {
        Some(Some((_, dd))) => (dd.virtual_address, dd.size),
        _ => (0, 0),
    };
    if rsrc_rva == 0 || rsrc_size == 0 {
        return None;
    }

    let base_offset = rva_to_offset(rsrc_rva, pe, data.len())?;
    if base_offset >= data.len() {
        return None;
    }

    let mut entries = Vec::new();
    parse_resource_directory(
        data, pe, base_offset, base_offset,
        0, 0, String::new(), String::new(), &mut entries,
    );

    let version_info = extract_version_info(data, pe, &entries);
    let manifest = extract_manifest(data, &entries);
    let icon_data = extract_icons(data, &entries);

    Some(ResourceInfo {
        total_entries: entries.len(),
        entries,
        version_info,
        manifest,
        icon_data,
    })
}

fn parse_resource_directory(
    data: &[u8],
    pe: &PE,
    base_offset: usize,
    dir_offset: usize,
    level: usize,
    type_id: u32,
    type_name: String,
    name: String,
    entries: &mut Vec<ResourceEntry>,
) {
    if level > 3 || entries.len() >= 4096 {
        return;
    }

    // IMAGE_RESOURCE_DIRECTORY: 16 bytes
    if dir_offset + 16 > data.len() {
        return;
    }
    let num_named = read_u16_le(data, dir_offset + 12) as usize;
    let num_id = read_u16_le(data, dir_offset + 14) as usize;
    let total = num_named + num_id;

    if total > 1024 {
        return;
    }

    let entries_offset = dir_offset + 16;

    for i in 0..total {
        if entries.len() >= 4096 {
            return;
        }
        let entry_offset = entries_offset + i * 8;
        if entry_offset + 8 > data.len() {
            return;
        }

        let name_or_id = read_u32_le(data, entry_offset);
        let offset_to_data = read_u32_le(data, entry_offset + 4);

        // Determine name for this level
        let (current_type_id, current_type_name, current_name) = match level {
            0 => {
                // Type level
                let tid = name_or_id & 0x7FFFFFFF;
                let tname = if name_or_id & 0x80000000 != 0 {
                    read_resource_name_string(data, base_offset, (name_or_id & 0x7FFFFFFF) as usize)
                        .unwrap_or_else(|| resource_type_name(tid))
                } else {
                    resource_type_name(tid)
                };
                (tid, tname, name.clone())
            }
            1 => {
                // Name/ID level
                let n = if name_or_id & 0x80000000 != 0 {
                    read_resource_name_string(data, base_offset, (name_or_id & 0x7FFFFFFF) as usize)
                        .unwrap_or_else(|| format!("#{}", name_or_id & 0x7FFFFFFF))
                } else {
                    format!("#{}", name_or_id)
                };
                (type_id, type_name.clone(), n)
            }
            _ => {
                (type_id, type_name.clone(), name.clone())
            }
        };

        let is_directory = offset_to_data & 0x80000000 != 0;

        if is_directory {
            let sub_offset = base_offset + (offset_to_data & 0x7FFFFFFF) as usize;
            parse_resource_directory(
                data, pe, base_offset, sub_offset,
                level + 1, current_type_id, current_type_name, current_name, entries,
            );
        } else {
            // Leaf: IMAGE_RESOURCE_DATA_ENTRY (16 bytes)
            let data_entry_offset = base_offset + (offset_to_data & 0x7FFFFFFF) as usize;
            if data_entry_offset + 16 > data.len() {
                continue;
            }
            let data_rva = read_u32_le(data, data_entry_offset);
            let data_size = read_u32_le(data, data_entry_offset + 4);

            let language = if level == 2 {
                name_or_id & 0x7FFFFFFF
            } else {
                0
            };

            let file_offset = rva_to_offset(data_rva, pe, data.len()).unwrap_or(0);

            entries.push(ResourceEntry {
                resource_type: current_type_name.clone(),
                type_id: current_type_id,
                name: current_name.clone(),
                language,
                language_str: language_id_to_string(language),
                size: data_size,
                rva: data_rva,
                file_offset,
            });
        }
    }
}

fn extract_version_info(data: &[u8], pe: &PE, entries: &[ResourceEntry]) -> Option<VersionInfo> {
    // Find first RT_VERSION entry (type 16)
    let entry = entries.iter().find(|e| e.type_id == 16)?;
    let offset = rva_to_offset(entry.rva, pe, data.len())?;
    let size = entry.size as usize;
    if offset + size > data.len() || size < 6 {
        return None;
    }
    let version_data = &data[offset..offset + size];
    parse_vs_versioninfo(version_data)
}

fn parse_vs_versioninfo(data: &[u8]) -> Option<VersionInfo> {
    if data.len() < 6 {
        return None;
    }

    // VS_VERSIONINFO header
    let _length = read_u16_le(data, 0) as usize;
    let value_length = read_u16_le(data, 2) as usize;
    let _type = read_u16_le(data, 4);

    // Key: "VS_VERSION_INFO" (null-terminated UTF-16LE)
    // Verify signature
    let key_offset = 6;
    let expected_key = "VS_VERSION_INFO";
    if let Some(key) = read_utf16_string_until_null(data, key_offset) {
        if key != expected_key {
            return None;
        }
    } else {
        return None;
    }

    // Skip past key + null terminator
    let after_key = key_offset + (expected_key.len() + 1) * 2;
    let after_key_aligned = align_up(after_key, 4);

    // Parse VS_FIXEDFILEINFO if value_length > 0
    let fixed = if value_length >= 52 && after_key_aligned + 52 <= data.len() {
        let ffi_offset = after_key_aligned;
        let signature = read_u32_le(data, ffi_offset);
        if signature == 0xFEEF04BD {
            let file_ver_ms = read_u32_le(data, ffi_offset + 8);
            let file_ver_ls = read_u32_le(data, ffi_offset + 12);
            let prod_ver_ms = read_u32_le(data, ffi_offset + 16);
            let prod_ver_ls = read_u32_le(data, ffi_offset + 20);
            let file_flags = read_u32_le(data, ffi_offset + 28);
            let file_os = read_u32_le(data, ffi_offset + 32);
            let file_type = read_u32_le(data, ffi_offset + 36);

            Some(FixedFileInfo {
                file_version: format!("{}.{}.{}.{}",
                    file_ver_ms >> 16, file_ver_ms & 0xFFFF,
                    file_ver_ls >> 16, file_ver_ls & 0xFFFF),
                product_version: format!("{}.{}.{}.{}",
                    prod_ver_ms >> 16, prod_ver_ms & 0xFFFF,
                    prod_ver_ls >> 16, prod_ver_ls & 0xFFFF),
                file_flags,
                file_os,
                file_type,
                file_type_str: file_type_str(file_type),
            })
        } else {
            None
        }
    } else {
        None
    };

    // Move past VS_FIXEDFILEINFO
    let children_offset = if value_length > 0 {
        align_up(after_key_aligned + value_length, 4)
    } else {
        after_key_aligned
    };

    // Parse children (StringFileInfo / VarFileInfo)
    let mut string_info = Vec::new();
    let mut pos = children_offset;

    while pos + 6 < data.len() {
        let child_length = read_u16_le(data, pos) as usize;
        if child_length == 0 || pos + child_length > data.len() {
            break;
        }

        let _child_value_length = read_u16_le(data, pos + 2);
        let _child_type = read_u16_le(data, pos + 4);

        if let Some(child_key) = read_utf16_string_until_null(data, pos + 6) {
            if child_key == "StringFileInfo" {
                let si_strings = parse_string_file_info(data, pos);
                string_info.extend(si_strings);
            }
        }

        pos = align_up(pos + child_length, 4);
    }

    Some(VersionInfo {
        fixed,
        string_info,
    })
}

fn parse_string_file_info(data: &[u8], sfi_offset: usize) -> Vec<VersionString> {
    let mut result = Vec::new();
    if sfi_offset + 6 > data.len() {
        return result;
    }

    let sfi_length = read_u16_le(data, sfi_offset) as usize;
    if sfi_length == 0 || sfi_offset + sfi_length > data.len() {
        return result;
    }

    // Skip StringFileInfo header: length(2) + value_length(2) + type(2) + key("StringFileInfo"\0 in UTF-16)
    let key_str = "StringFileInfo";
    let after_sfi_key = sfi_offset + 6 + (key_str.len() + 1) * 2;
    let mut table_pos = align_up(after_sfi_key, 4);

    let sfi_end = sfi_offset + sfi_length;

    // Iterate StringTable entries
    while table_pos + 6 < sfi_end && table_pos + 6 < data.len() {
        let table_length = read_u16_le(data, table_pos) as usize;
        if table_length == 0 || table_pos + table_length > data.len() {
            break;
        }

        // Skip StringTable header: length(2) + value_length(2) + type(2) + key(8 chars + null in UTF-16)
        let table_key_offset = table_pos + 6;
        // Read the table key (e.g., "040904b0") - 8 chars
        let _table_key = read_utf16_string_until_null(data, table_key_offset);
        // Find end of table key: skip past it
        let mut str_pos = table_key_offset;
        // Skip UTF-16 chars until null
        let mut key_chars = 0;
        while str_pos + 2 <= data.len() && key_chars < 64 {
            let ch = read_u16_le(data, str_pos);
            str_pos += 2;
            if ch == 0 {
                break;
            }
            key_chars += 1;
        }
        str_pos = align_up(str_pos, 4);

        let table_end = table_pos + table_length;

        // Iterate String entries within this StringTable
        while str_pos + 6 < table_end && str_pos + 6 < data.len() && result.len() < 64 {
            let string_length = read_u16_le(data, str_pos) as usize;
            let string_value_length = read_u16_le(data, str_pos + 2) as usize;
            let _string_type = read_u16_le(data, str_pos + 4);

            if string_length == 0 || str_pos + string_length > data.len() {
                break;
            }

            // Read key
            if let Some(key) = read_utf16_string_until_null(data, str_pos + 6) {
                // Skip past key + null
                let after_string_key = str_pos + 6 + (key.len() + 1) * 2;
                let value_offset = align_up(after_string_key, 4);

                let value = if string_value_length > 0 && value_offset < data.len() {
                    // value_length is in WCHARs (including null terminator)
                    let char_count = string_value_length.saturating_sub(1).min(512);
                    read_utf16_string(data, value_offset, char_count)
                        .unwrap_or_default()
                } else {
                    String::new()
                };

                result.push(VersionString { key, value });
            }

            str_pos = align_up(str_pos + string_length, 4);
        }

        table_pos = align_up(table_pos + table_length, 4);
    }

    result
}

fn extract_manifest(data: &[u8], entries: &[ResourceEntry]) -> Option<String> {
    // Find first RT_MANIFEST entry (type 24)
    let entry = entries.iter().find(|e| e.type_id == 24)?;
    let offset = entry.file_offset;
    let size = entry.size as usize;
    if offset == 0 || offset + size > data.len() || size == 0 {
        return None;
    }
    let manifest_data = &data[offset..offset + size];
    // Manifest is typically UTF-8 XML
    let text = String::from_utf8_lossy(manifest_data).to_string();
    if text.is_empty() {
        return None;
    }
    Some(text)
}

fn extract_icons(data: &[u8], entries: &[ResourceEntry]) -> Vec<IconGroup> {
    let mut groups = Vec::new();
    for entry in entries.iter().filter(|e| e.type_id == 14) {
        if let Some(group) = reconstruct_ico(data, entries, entry) {
            groups.push(group);
        }
    }
    groups
}

fn reconstruct_ico(
    data: &[u8],
    entries: &[ResourceEntry],
    group_entry: &ResourceEntry,
) -> Option<IconGroup> {
    let offset = group_entry.file_offset;
    let size = group_entry.size as usize;
    if offset == 0 || size < 6 || offset + size > data.len() {
        return None;
    }
    let grp = &data[offset..offset + size];

    // GRPICONDIR: reserved(2) + type(2) + count(2)
    let _reserved = read_u16_le(grp, 0);
    let img_type = read_u16_le(grp, 2);
    if img_type != 1 {
        return None; // not an icon
    }
    let count = read_u16_le(grp, 4) as usize;
    if count == 0 || 6 + count * 14 > size {
        return None;
    }

    // Collect RT_ICON data for each entry
    let mut icon_images = Vec::new();
    let mut blobs: Vec<Vec<u8>> = Vec::new();

    for i in 0..count {
        let ge_offset = 6 + i * 14;
        // GRPICONDIRENTRY: bWidth(1) bHeight(1) bColorCount(1) bReserved(1)
        //   wPlanes(2) wBitCount(2) dwBytesInRes(4) nID(2)
        let b_width = grp[ge_offset];
        let b_height = grp[ge_offset + 1];
        let bit_count = read_u16_le(grp, ge_offset + 6);
        let bytes_in_res = read_u32_le(grp, ge_offset + 8);
        let n_id = read_u16_le(grp, ge_offset + 12);

        let width = if b_width == 0 { 256u32 } else { b_width as u32 };
        let height = if b_height == 0 { 256u32 } else { b_height as u32 };

        // Find corresponding RT_ICON entry (type 3) with name == "#N"
        let icon_name = format!("#{}", n_id);
        let icon_entry = entries.iter().find(|e| e.type_id == 3 && e.name == icon_name);
        let blob = match icon_entry {
            Some(ie) => {
                let ie_off = ie.file_offset;
                let ie_size = ie.size as usize;
                if ie_off == 0 || ie_off + ie_size > data.len() {
                    return None;
                }
                data[ie_off..ie_off + ie_size].to_vec()
            }
            None => {
                // Try using bytes_in_res as fallback size hint; skip this entry
                let _ = bytes_in_res;
                return None;
            }
        };

        icon_images.push(IconImage { width, height, bit_count });
        blobs.push(blob);
    }

    // Build ICO file:
    // ICONDIR (6 bytes) + ICONDIRENTRY[count] (16 each) + image data
    let header_size = 6 + count * 16;
    let total_size: usize = header_size + blobs.iter().map(|b| b.len()).sum::<usize>();
    let mut ico = Vec::with_capacity(total_size);

    // ICONDIR
    ico.extend_from_slice(&0u16.to_le_bytes()); // reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // type = icon
    ico.extend_from_slice(&(count as u16).to_le_bytes());

    // Compute offsets for each image blob
    let mut current_offset = header_size as u32;
    for (i, blob) in blobs.iter().enumerate() {
        let ge_offset = 6 + i * 14;
        // Copy first 12 bytes from GRPICONDIRENTRY (bWidth..dwBytesInRes)
        ico.extend_from_slice(&grp[ge_offset..ge_offset + 12]);
        // Replace nID(u16) with dwImageOffset(u32)
        ico.extend_from_slice(&current_offset.to_le_bytes());
        current_offset += blob.len() as u32;
    }

    // Append image data blobs
    for blob in &blobs {
        ico.extend_from_slice(blob);
    }

    Some(IconGroup {
        name: group_entry.name.clone(),
        ico_bytes: ico,
        images: icon_images,
    })
}

// --- Authenticode / Code Signing ---

fn parse_authenticode(data: &[u8], pe: &PE) -> AuthenticodeInfo {
    let not_signed = AuthenticodeInfo {
        signed: false,
        parse_ok: false,
        trust_verified: false,
        warnings: Vec::new(),
        win_certificate: None,
        signer: None,
        certificates: Vec::new(),
    };

    // Get Data Directory index 4 (Certificate Table)
    // Certificate Table is special: the "RVA" field is actually a file offset, not an RVA.
    let opt = match pe.header.optional_header.as_ref() {
        Some(o) => o,
        None => return not_signed,
    };

    let (cert_offset, cert_size) = match opt.data_directories.data_directories.get(4) {
        Some(Some((_, dd))) => (dd.virtual_address, dd.size),
        _ => (0, 0),
    };

    if cert_offset == 0 && cert_size == 0 {
        return not_signed;
    }

    let mut warnings = Vec::new();

    // Boundary check
    let offset = cert_offset as usize;
    let size = cert_size as usize;
    if offset.checked_add(size).is_none() || offset + size > data.len() || size < 8 {
        warnings.push("Certificate Table points outside file bounds".into());
        return AuthenticodeInfo {
            signed: true,
            parse_ok: false,
            trust_verified: false,
            warnings,
            win_certificate: None,
            signer: None,
            certificates: Vec::new(),
        };
    }

    // WIN_CERTIFICATE header: dwLength(4) + wRevision(2) + wCertificateType(2)
    let dw_length = read_u32_le(data, offset);
    let w_revision = read_u16_le(data, offset + 4);
    let w_certificate_type = read_u16_le(data, offset + 6);

    let revision_str = match w_revision {
        0x0100 => "WIN_CERT_REVISION_1_0".into(),
        0x0200 => "WIN_CERT_REVISION_2_0".into(),
        _ => format!("Unknown ({:#06x})", w_revision),
    };

    let cert_type_str = match w_certificate_type {
        0x0001 => "WIN_CERT_TYPE_X509".into(),
        0x0002 => "WIN_CERT_TYPE_PKCS_SIGNED_DATA".into(),
        0x0003 => "WIN_CERT_TYPE_RESERVED_1".into(),
        0x0004 => "WIN_CERT_TYPE_TS_STACK_SIGNED".into(),
        _ => format!("Unknown ({:#06x})", w_certificate_type),
    };

    let win_cert = WinCertificateInfo {
        length: dw_length,
        revision: revision_str,
        revision_raw: w_revision,
        certificate_type: cert_type_str,
        certificate_type_raw: w_certificate_type,
    };

    if w_certificate_type != 0x0002 {
        warnings.push(format!(
            "Certificate type is {:#06x}, expected PKCS_SIGNED_DATA (0x0002)",
            w_certificate_type
        ));
        return AuthenticodeInfo {
            signed: true,
            parse_ok: false,
            trust_verified: false,
            warnings,
            win_certificate: Some(win_cert),
            signer: None,
            certificates: Vec::new(),
        };
    }

    // bCertificate starts at offset+8, length = dwLength-8
    // dwLength must not exceed the Certificate Table directory size
    if dw_length as usize > size {
        warnings.push(format!(
            "WIN_CERTIFICATE dwLength ({}) exceeds Certificate Table size ({})",
            dw_length, size
        ));
        return AuthenticodeInfo {
            signed: true,
            parse_ok: false,
            trust_verified: false,
            warnings,
            win_certificate: Some(win_cert),
            signer: None,
            certificates: Vec::new(),
        };
    }
    let blob_len = dw_length.saturating_sub(8) as usize;
    let blob_start = offset + 8;
    if blob_start + blob_len > data.len() || blob_len == 0 {
        warnings.push("PKCS#7 blob extends beyond file".into());
        return AuthenticodeInfo {
            signed: true,
            parse_ok: false,
            trust_verified: false,
            warnings,
            win_certificate: Some(win_cert),
            signer: None,
            certificates: Vec::new(),
        };
    }

    let pkcs7_blob = &data[blob_start..blob_start + blob_len];

    // Parse PKCS#7 ContentInfo
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::Decode;

    let content_info = match ContentInfo::from_der(pkcs7_blob) {
        Ok(ci) => ci,
        Err(_) => {
            warnings.push("Failed to parse PKCS#7 ContentInfo (DER)".into());
            return AuthenticodeInfo {
                signed: true,
                parse_ok: false,
                trust_verified: false,
                warnings,
                win_certificate: Some(win_cert),
                signer: None,
                certificates: Vec::new(),
            };
        }
    };

    // Verify content_type is signedData (1.2.840.113549.1.7.2)
    let signed_data_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    if content_info.content_type != signed_data_oid {
        warnings.push(format!(
            "ContentInfo content_type is {}, expected signedData (1.2.840.113549.1.7.2)",
            content_info.content_type
        ));
        return AuthenticodeInfo {
            signed: true,
            parse_ok: false,
            trust_verified: false,
            warnings,
            win_certificate: Some(win_cert),
            signer: None,
            certificates: Vec::new(),
        };
    }

    let signed_data = match content_info.content.decode_as::<SignedData>() {
        Ok(sd) => sd,
        Err(_) => {
            warnings.push("Failed to decode SignedData from ContentInfo".into());
            return AuthenticodeInfo {
                signed: true,
                parse_ok: false,
                trust_verified: false,
                warnings,
                win_certificate: Some(win_cert),
                signer: None,
                certificates: Vec::new(),
            };
        }
    };

    // Extract raw X.509 certificates and converted entries
    let mut raw_certs: Vec<&x509_cert::Certificate> = Vec::new();
    let mut certificates = Vec::new();
    if let Some(cert_set) = &signed_data.certificates {
        for cert_choice in cert_set.0.iter() {
            use cms::cert::CertificateChoices;
            if let CertificateChoices::Certificate(cert) = cert_choice {
                raw_certs.push(cert);
                certificates.push(extract_cert_entry(cert));
            }
        }
    }

    // Identify signer from SignerInfos[0].sid (IssuerAndSerialNumber)
    // Compare using full issuer DN (DER bytes) + serial, not just CN string
    let mut signer_idx: Option<usize> = None;
    if let Some(signer_info) = signed_data.signer_infos.0.iter().next() {
        use cms::signed_data::SignerIdentifier;
        use der::Encode;
        if let SignerIdentifier::IssuerAndSerialNumber(ias) = &signer_info.sid {
            let signer_issuer_der = ias.issuer.to_der().ok();
            let signer_serial_bytes = ias.serial_number.as_bytes();
            for (i, raw_cert) in raw_certs.iter().enumerate() {
                let tbs = &raw_cert.tbs_certificate;
                let issuer_match = match (&signer_issuer_der, tbs.issuer.to_der().ok()) {
                    (Some(a), Some(b)) => a == &b,
                    _ => false,
                };
                if issuer_match && tbs.serial_number.as_bytes() == signer_serial_bytes {
                    signer_idx = Some(i);
                    break;
                }
            }
            if signer_idx.is_none() {
                warnings.push("Signer certificate not found in certificate chain".into());
            }
        }
    }

    // Mark signer cert
    if let Some(idx) = signer_idx {
        certificates[idx].is_signer = true;
    }

    let signer = signer_idx.map(|i| certificates[i].clone());

    // Generate warnings
    // Check for expired certificates
    let now_str = format_current_utc();
    for cert in &certificates {
        if cert.not_after < now_str {
            warnings.push(format!("Certificate expired: {} (expired {})", cert.subject, cert.not_after));
        }
    }
    // Check for self-signed (subject == issuer)
    for cert in &certificates {
        if cert.subject == cert.issuer {
            warnings.push(format!("Self-signed certificate: {}", cert.subject));
        }
    }
    // Check chain completeness
    if certificates.len() == 1 {
        warnings.push("Certificate chain contains only one certificate".into());
    }

    AuthenticodeInfo {
        signed: true,
        parse_ok: true,
        trust_verified: false,
        warnings,
        win_certificate: Some(win_cert),
        signer,
        certificates,
    }
}

fn extract_cert_entry(cert: &x509_cert::Certificate) -> CertificateEntry {
    let tbs = &cert.tbs_certificate;
    let subject = extract_common_name(&tbs.subject);
    let issuer = extract_common_name(&tbs.issuer);
    let serial = hex_encode(tbs.serial_number.as_bytes());
    let not_before = format_x509_time(&tbs.validity.not_before);
    let not_after = format_x509_time(&tbs.validity.not_after);

    // Compute SHA-1 thumbprint of the entire DER-encoded certificate
    let thumbprint_sha1 = {
        use der::Encode;
        match cert.to_der() {
            Ok(der_bytes) => {
                let mut hasher = Sha1::new();
                Digest::update(&mut hasher, &der_bytes);
                let hash = hasher.finalize();
                hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
            }
            Err(_) => "N/A".into(),
        }
    };

    CertificateEntry {
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        thumbprint_sha1,
        is_signer: false,
    }
}

fn extract_common_name(name: &x509_cert::name::Name) -> String {
    // OID 2.5.4.3 = CN (Common Name)
    let cn_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.4.3");
    for rdn in name.0.iter() {
        for atav in rdn.0.iter() {
            if atav.oid == cn_oid {
                // Try to extract the string value from the ANY
                if let Ok(s) = atav.value.decode_as::<der::asn1::Utf8StringRef<'_>>() {
                    return s.as_str().to_string();
                }
                if let Ok(s) = atav.value.decode_as::<der::asn1::PrintableStringRef<'_>>() {
                    return s.as_str().to_string();
                }
                if let Ok(s) = atav.value.decode_as::<der::asn1::Ia5StringRef<'_>>() {
                    return s.as_str().to_string();
                }
                // BMPString (UTF-16BE) — decode manually
                if let Ok(bytes) = atav.value.decode_as::<der::asn1::OctetStringRef<'_>>() {
                    let b = bytes.as_bytes();
                    if b.len() >= 2 && b.len() % 2 == 0 {
                        let chars: Vec<u16> = b.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                        return String::from_utf16_lossy(&chars);
                    }
                }
            }
        }
    }
    // Fallback: serialize the whole name
    format!("{}", name)
}

fn format_x509_time(time: &x509_cert::time::Time) -> String {
    use x509_cert::time::Time;
    let dt = match time {
        Time::UtcTime(ut) => ut.to_date_time(),
        Time::GeneralTime(gt) => gt.to_date_time(),
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        dt.year(), dt.month(), dt.day(),
        dt.hour(), dt.minutes(), dt.seconds()
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

fn format_current_utc() -> String {
    // Approximate current UTC time from SystemTime for certificate expiry comparison
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if secs == 0 {
        return String::new();
    }
    // Reuse existing format_timestamp logic for the date portion
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds_val = time_of_day % 60;

    let mut y = 1970i64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }
    let days_in_months: [i64; 12] = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    for (i, &dm) in days_in_months.iter().enumerate() {
        if remaining_days < dm {
            m = i + 1;
            break;
        }
        remaining_days -= dm;
    }
    let d = remaining_days + 1;
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, m, d, hours, minutes, seconds_val)
}

// --- Rich Header parsing ---

fn parse_rich_header(data: &[u8]) -> Option<RichHeaderInfo> {
    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = read_u32_le(data, 0x3C) as usize;
    if e_lfanew < 0x80 || e_lfanew > data.len() {
        return None;
    }

    // Scan for "Rich" marker (0x68636952) in the region between 0x80 and e_lfanew
    let scan_start = 0x80;
    let scan_end = e_lfanew;
    if scan_end <= scan_start || scan_end > data.len() {
        return None;
    }

    let mut rich_offset = None;
    let mut pos = scan_start;
    while pos + 4 <= scan_end {
        if read_u32_le(data, pos) == 0x68636952 {
            rich_offset = Some(pos);
            break;
        }
        pos += 4;
    }
    let rich_offset = rich_offset?;

    // XOR key is the 4 bytes right after "Rich"
    if rich_offset + 8 > data.len() {
        return None;
    }
    let xor_key = read_u32_le(data, rich_offset + 4);

    // Decode backwards from Rich to find DanS (0x536E6144)
    // The decoded region starts at scan_start (0x80)
    let encoded_start = scan_start;
    let encoded_end = rich_offset;
    if encoded_end <= encoded_start {
        return None;
    }

    // Verify DanS signature
    let first_dword = read_u32_le(data, encoded_start) ^ xor_key;
    if first_dword != 0x536E6144 {
        return None;
    }

    // Skip DanS + 3 padding dwords (16 bytes total)
    let entries_start = encoded_start + 16;
    if entries_start >= encoded_end {
        return Some(RichHeaderInfo {
            xor_key: format!("{:#010x}", xor_key),
            xor_key_raw: xor_key,
            entries: Vec::new(),
        });
    }

    let mut entries = Vec::new();
    let mut off = entries_start;
    while off + 8 <= encoded_end {
        let comp_id = read_u32_le(data, off) ^ xor_key;
        let count = read_u32_le(data, off + 4) ^ xor_key;
        let build_id = (comp_id & 0xFFFF) as u16;
        let prod_id = ((comp_id >> 16) & 0xFFFF) as u16;
        entries.push(RichEntry { build_id, prod_id, count });
        off += 8;
    }

    Some(RichHeaderInfo {
        xor_key: format!("{:#010x}", xor_key),
        xor_key_raw: xor_key,
        entries,
    })
}

// --- TLS Directory parsing ---

fn parse_tls(data: &[u8], pe: &PE) -> Option<TlsInfo> {
    let opt = pe.header.optional_header.as_ref()?;
    let (rva, size) = match opt.data_directories.data_directories.get(9) {
        Some(Some((_, dd))) => (dd.virtual_address, dd.size),
        _ => (0, 0),
    };
    if rva == 0 || size == 0 {
        return None;
    }

    let tls_offset = rva_to_offset(rva, pe, data.len())?;
    let image_base = opt.windows_fields.image_base;

    if pe.is_64 {
        // PE32+: pointers are 8 bytes, struct is 40 bytes
        if tls_offset + 40 > data.len() {
            return None;
        }
        let raw_data_start = read_u64_le(data, tls_offset);
        let raw_data_end = read_u64_le(data, tls_offset + 8);
        let address_of_index = read_u64_le(data, tls_offset + 16);
        let address_of_callbacks = read_u64_le(data, tls_offset + 24);
        let size_of_zero_fill = read_u32_le(data, tls_offset + 32);
        let characteristics = read_u32_le(data, tls_offset + 36);

        let callbacks = read_tls_callbacks_64(data, pe, address_of_callbacks, image_base);
        let callback_count = callbacks.len();

        Some(TlsInfo {
            raw_data_start: format!("{:#x}", raw_data_start),
            raw_data_end: format!("{:#x}", raw_data_end),
            address_of_index: format!("{:#x}", address_of_index),
            address_of_callbacks: format!("{:#x}", address_of_callbacks),
            size_of_zero_fill,
            characteristics,
            callbacks,
            callback_count,
        })
    } else {
        // PE32: pointers are 4 bytes, struct is 24 bytes
        if tls_offset + 24 > data.len() {
            return None;
        }
        let raw_data_start = read_u32_le(data, tls_offset) as u64;
        let raw_data_end = read_u32_le(data, tls_offset + 4) as u64;
        let address_of_index = read_u32_le(data, tls_offset + 8) as u64;
        let address_of_callbacks = read_u32_le(data, tls_offset + 12) as u64;
        let size_of_zero_fill = read_u32_le(data, tls_offset + 16);
        let characteristics = read_u32_le(data, tls_offset + 20);

        let callbacks = read_tls_callbacks_32(data, pe, address_of_callbacks as u32, image_base as u32);
        let callback_count = callbacks.len();

        Some(TlsInfo {
            raw_data_start: format!("{:#x}", raw_data_start),
            raw_data_end: format!("{:#x}", raw_data_end),
            address_of_index: format!("{:#x}", address_of_index),
            address_of_callbacks: format!("{:#x}", address_of_callbacks),
            size_of_zero_fill,
            characteristics,
            callbacks,
            callback_count,
        })
    }
}

fn read_tls_callbacks_64(data: &[u8], pe: &PE, callbacks_va: u64, image_base: u64) -> Vec<String> {
    let mut result = Vec::new();
    if callbacks_va == 0 || callbacks_va < image_base {
        return result;
    }
    let callbacks_rva = (callbacks_va - image_base) as u32;
    let Some(offset) = rva_to_offset(callbacks_rva, pe, data.len()) else {
        return result;
    };
    let mut pos = offset;
    for _ in 0..256 {
        if pos + 8 > data.len() {
            break;
        }
        let cb = read_u64_le(data, pos);
        if cb == 0 {
            break;
        }
        result.push(format!("{:#x}", cb));
        pos += 8;
    }
    result
}

fn read_tls_callbacks_32(data: &[u8], pe: &PE, callbacks_va: u32, image_base: u32) -> Vec<String> {
    let mut result = Vec::new();
    if callbacks_va == 0 || callbacks_va < image_base {
        return result;
    }
    let callbacks_rva = callbacks_va - image_base;
    let Some(offset) = rva_to_offset(callbacks_rva, pe, data.len()) else {
        return result;
    };
    let mut pos = offset;
    for _ in 0..256 {
        if pos + 4 > data.len() {
            break;
        }
        let cb = read_u32_le(data, pos);
        if cb == 0 {
            break;
        }
        result.push(format!("{:#x}", cb));
        pos += 4;
    }
    result
}

// --- Debug Directory parsing ---

fn parse_debug(data: &[u8], pe: &PE) -> Option<DebugInfo> {
    let opt = pe.header.optional_header.as_ref()?;
    let (rva, size) = match opt.data_directories.data_directories.get(6) {
        Some(Some((_, dd))) => (dd.virtual_address, dd.size),
        _ => (0, 0),
    };
    if rva == 0 || size == 0 {
        return None;
    }

    let debug_offset = rva_to_offset(rva, pe, data.len())?;
    let entry_count = (size as usize / 28).min(32);
    if entry_count == 0 {
        return None;
    }

    let mut entries = Vec::new();
    for i in 0..entry_count {
        let base = debug_offset + i * 28;
        if base + 28 > data.len() {
            break;
        }

        let timestamp = read_u32_le(data, base + 4);
        let major_version = read_u16_le(data, base + 8);
        let minor_version = read_u16_le(data, base + 10);
        let debug_type_raw = read_u32_le(data, base + 12);
        let size_of_data = read_u32_le(data, base + 16);
        let _address_of_raw_data = read_u32_le(data, base + 20);
        let pointer_to_raw_data = read_u32_le(data, base + 24);

        let debug_type = match debug_type_raw {
            0 => "Unknown",
            1 => "COFF",
            2 => "CodeView",
            3 => "FPO",
            4 => "Misc",
            5 => "Exception",
            6 => "Fixup",
            9 => "Borland",
            12 => "VC_FEATURE",
            13 => "POGO",
            14 => "ILTCG",
            16 => "Repro",
            20 => "Ex DLL Characteristics",
            _ => "Unknown",
        }.to_string();

        let mut pdb_path = None;
        let mut guid = None;
        let mut age = None;

        // Parse CodeView (RSDS) data
        if debug_type_raw == 2 && pointer_to_raw_data > 0 && size_of_data >= 24 {
            let cv_offset = pointer_to_raw_data as usize;
            if cv_offset + 24 <= data.len() {
                let sig = read_u32_le(data, cv_offset);
                if sig == 0x53445352 {
                    // RSDS signature confirmed
                    // GUID: 16 bytes at cv_offset+4
                    let data1 = read_u32_le(data, cv_offset + 4);
                    let data2 = read_u16_le(data, cv_offset + 8);
                    let data3 = read_u16_le(data, cv_offset + 10);
                    let mut data4 = [0u8; 8];
                    if cv_offset + 20 <= data.len() {
                        data4.copy_from_slice(&data[cv_offset + 12..cv_offset + 20]);
                    }
                    guid = Some(format!(
                        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                        data1, data2, data3,
                        data4[0], data4[1],
                        data4[2], data4[3], data4[4], data4[5], data4[6], data4[7]
                    ));

                    // Age: u32 at cv_offset+20
                    age = Some(read_u32_le(data, cv_offset + 20));

                    // PDB path: null-terminated UTF-8 starting at cv_offset+24
                    let pdb_start = cv_offset + 24;
                    let pdb_end = (cv_offset + size_of_data as usize).min(data.len());
                    if pdb_start < pdb_end {
                        let pdb_bytes = &data[pdb_start..pdb_end];
                        let null_pos = pdb_bytes.iter().position(|&b| b == 0).unwrap_or(pdb_bytes.len());
                        pdb_path = Some(String::from_utf8_lossy(&pdb_bytes[..null_pos]).to_string());
                    }
                }
            }
        }

        entries.push(DebugEntry {
            debug_type,
            debug_type_raw,
            timestamp,
            major_version,
            minor_version,
            size_of_data,
            pointer_to_raw_data,
            pdb_path,
            guid,
            age,
        });
    }

    if entries.is_empty() {
        return None;
    }

    Some(DebugInfo { entries })
}
