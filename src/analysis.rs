use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;
use std::time::SystemTime;

use goblin::pe::PE;
use md5::Digest;
use regex::Regex;
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
    pub opsec_strict: bool,
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
    pub opsec: Option<OpsecInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_fingerprint: Option<BuildFingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dotnet: Option<DotNetInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go: Option<GoInfo>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<Vec<OverlayClassification>>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct IconGroup {
    pub name: String,
    pub ico_bytes: Vec<u8>,
    pub images: Vec<IconImage>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_hash: Option<String>,
    pub checksum_valid: bool,
    pub entries: Vec<RichEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RichEntry {
    pub comp_id: String,
    pub prod_id: u16,
    pub build_id: u16,
    pub count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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

#[derive(Clone, Debug, Serialize)]
pub struct OpsecInfo {
    pub summary: OpsecSummary,
    pub findings: Vec<OpsecFinding>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpsecSummary {
    pub finding_count: usize,
    pub max_severity: String,
    pub types: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpsecFinding {
    pub id: String,
    #[serde(rename = "type")]
    pub finding_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub evidence: BTreeMap<String, String>,
    pub confidence: f32,
}

#[derive(Clone, Debug, Serialize)]
pub struct BuildFingerprint {
    pub compiler: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_version: Option<String>,
    pub is_managed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packer: Option<PackerInfo>,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackerInfo {
    pub name: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DotNetInfo {
    pub runtime_version: String,
    pub flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assembly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assembly_version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GoInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    pub confidence: f32,
    pub markers: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OverlayClassification {
    pub format: String,
    pub confidence: f32,
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

    let display_strings = if opts.show_strings {
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

    // Always detect overlay for anomaly detection (STRUCT-002)
    let mut overlay_info = detect_overlay(data, pe);
    if overlay_info.present {
        overlay_info.classification = classify_overlay(data, overlay_info.offset, overlay_info.size);
    }
    let overlay_for_anomalies = Some(overlay_info);

    // Always parse resources for OPSEC-004 version mismatch detection,
    // but only include in output when show_resources.
    let resources_parsed = parse_resources(data, pe);

    let authenticode = if opts.show_authenticode {
        Some(parse_authenticode(data, pe))
    } else {
        None
    };

    // Always parse rich header for anomaly detection (RICH-001/002),
    // but only include in output when show_all so that "only" flags
    // like --hashes don't get an unexpected section.
    let rich_header_parsed = parse_rich_header(data);
    let tls = if opts.show_all { parse_tls(data, pe) } else { None };
    // Always parse debug for anomaly detection (OPSEC-001),
    // but only include in output when show_all so that "only" flags
    // like --hashes don't get an unexpected OPSEC section.
    let debug = parse_debug(data, pe);

    // .NET and Go detection
    let dotnet = parse_dotnet(data, pe);
    let go = detect_go(data, pe);

    let suspicious_summary = imports.as_ref().map(|imp| build_suspicious_summary(imp));

    let mut anomalies_vec = detect_anomalies(
        &sections, &coff_header, &optional_header, &overlay_for_anomalies, &suspicious_summary, &debug,
        &rich_header_parsed, &imports,
    );

    // OPSEC detection (OPSEC-002 through OPSEC-008)
    // When opsec_strict, always extract with min_len=6 for credential/endpoint scanning
    // regardless of display_strings (which may use a higher min_str_len).
    let opsec_strings = if opts.opsec_strict {
        Some(extract_strings(data, 6))
    } else {
        None
    };
    let strings_for_opsec = opsec_strings.as_ref().or(display_strings.as_ref());
    let (opsec_info, opsec_anomalies) = detect_opsec(
        &file_info, &debug, &resources_parsed, &rich_header_parsed,
        &authenticode, strings_for_opsec, data,
    );
    anomalies_vec.extend(opsec_anomalies);

    // Packer detection + Build fingerprint
    let overlay_off = overlay_for_anomalies.as_ref().and_then(|o| if o.present { Some(o.offset) } else { None });
    let packer = detect_packer(pe, data, overlay_off, &anomalies_vec);
    let fp = build_fingerprint(&dotnet, &go, &debug, &rich_header_parsed, &optional_header, &imports, packer);

    let rich_header = if opts.show_all { rich_header_parsed } else { None };
    let debug_output = if opts.show_all { debug } else { None };
    let resources = if opts.show_resources { resources_parsed } else { None };
    // Gate opsec output like debug/rich_header: only show in full output modes
    // or when --opsec-strict explicitly requests OPSEC analysis.
    // OPSEC anomalies are always in anomalies[] regardless.
    let include_opsec = opts.show_all || opts.opsec_strict;
    let opsec = if include_opsec && !opsec_info.findings.is_empty() {
        Some(opsec_info)
    } else {
        None
    };

    // Gate overlay, dotnet, go, and build_fingerprint for output
    let overlay = if opts.show_overlay { overlay_for_anomalies } else { None };
    let fp_output = if opts.show_all { fp } else { None };
    let dotnet_output = if opts.show_all { dotnet } else { None };
    let go_output = if opts.show_all { go } else { None };

    AnalysisResult {
        file_info,
        dos_header,
        coff_header,
        optional_header,
        sections,
        imports,
        exports,
        strings: display_strings,
        hashes,
        overlay,
        resources,
        authenticode,
        rich_header,
        tls,
        debug: debug_output,
        suspicious_summary,
        opsec,
        build_fingerprint: fp_output,
        dotnet: dotnet_output,
        go: go_output,
        anomalies: Some(anomalies_vec),
    }
}

fn detect_anomalies(
    sections: &Option<Vec<SectionInfo>>,
    coff_header: &Option<CoffHeader>,
    optional_header: &Option<OptionalHeader>,
    overlay: &Option<OverlayInfo>,
    suspicious_summary: &Option<SuspiciousSummary>,
    debug: &Option<DebugInfo>,
    rich_header: &Option<RichHeaderInfo>,
    imports: &Option<Vec<ImportEntry>>,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    let standard_names: &[&str] = &[
        ".text", ".data", ".rdata", ".rsrc", ".reloc",
        ".bss", ".idata", ".edata", ".tls", ".pdata",
        // COFF long section names (numeric references to string table)
        ".CRT", ".symtab",
        // Go-specific sections
        ".gopclntab", ".go.buildinfo",
    ];
    // COFF string table references (/4, /19, etc.) are also standard
    let is_coff_strtab_ref = |name: &str| -> bool {
        name.starts_with('/') && name[1..].chars().all(|c| c.is_ascii_digit())
    };

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
            if !standard_names.contains(&sec.name.as_str()) && !is_coff_strtab_ref(&sec.name) {
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
                if let Some(sec) = ep_section
                    && sec.name != ".text" {
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
                description: "NO_SEH is set — binary does not use Structured Exception Handling".into(),
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
            // Suppress future-timestamp warning when REPRO debug type is present:
            // reproducible builds use a content hash as the timestamp, not a real date.
            let has_repro = debug.as_ref().is_some_and(|d| {
                d.entries.iter().any(|e| e.debug_type_raw == 16) // 16 = IMAGE_DEBUG_TYPE_REPRO
            });
            if now > 0 && ts > now && !has_repro {
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

    // TIME-004: COFF timestamp vs Debug timestamp mismatch
    if let Some(coff) = coff_header {
        if let Some(dbg) = debug {
            for entry in &dbg.entries {
                if entry.debug_type_raw == 2 && entry.timestamp != 0 && coff.time_date_stamp != 0 {
                    let delta = (coff.time_date_stamp as i64 - entry.timestamp as i64).unsigned_abs();
                    if delta > 86400 { // more than 24 hours apart
                        anomalies.push(Anomaly {
                            rule_id: "TIME-004".into(),
                            category: "Timestamp".into(),
                            severity: "warning".into(),
                            description: format!(
                                "COFF timestamp and debug timestamp differ by {} hours",
                                delta / 3600
                            ),
                            evidence: Some(format!("coff={:#x}, debug={:#x}, delta={}s",
                                coff.time_date_stamp, entry.timestamp, delta)),
                            threshold: Some("86400".into()),
                        });
                        break;
                    }
                }
            }
        }
    }

    // Rule 14: Overlay detected
    if let Some(overlay) = overlay
        && overlay.present {
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

    // Suspicious combo rules (Rules 17-18)
    if let Some(summary) = suspicious_summary {
        let has_category = |name: &str| {
            summary.categories.iter().any(|c| c.category == name)
        };

        // Rule 17: Process Injection + Evasion
        // Require at least one strong injection API (CreateRemoteThread, WriteProcessMemory, etc.)
        // to avoid false positives on benign software that imports OpenProcess + SetFileAttributes.
        let has_strong_injection = imports.as_ref().is_some_and(|imps| {
            let strong_apis = [
                "CreateRemoteThread", "CreateRemoteThreadEx",
                "WriteProcessMemory", "NtWriteVirtualMemory",
                "VirtualAllocEx", "VirtualAllocExNuma",
                "NtMapViewOfSection", "QueueUserAPC", "NtQueueApcThread",
                "SetThreadContext", "NtSetContextThread", "RtlCreateUserThread",
            ];
            imps.iter().any(|dll| dll.functions.iter().any(|f| strong_apis.contains(&f.name.as_str())))
        });
        if has_strong_injection && has_category("Evasion") {
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

    // OPSEC-001: PDB debug path found (skip empty/nulled paths — handled by OPSEC-003)
    if let Some(dbg) = debug {
        for entry in &dbg.entries {
            if let Some(ref pdb) = entry.pdb_path {
                if !pdb.is_empty() {
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
    }

    // RICH-001: Rich Header checksum mismatch (tampering / false flag, e.g. Olympic Destroyer)
    if let Some(rich) = rich_header
        && !rich.checksum_valid {
            anomalies.push(Anomaly {
                rule_id: "RICH-001".into(),
                category: "Rich Header".into(),
                severity: "warning".into(),
                description: "Rich Header checksum is invalid — possible tampering or false flag".into(),
                evidence: Some(format!("xor_key={}", rich.xor_key)),
                threshold: None,
            });
        }

    // RICH-002: No Rich Header but has executable code section > 0x1000 bytes
    if rich_header.is_none()
        && let Some(secs) = sections {
            let has_code = secs.iter().any(|s| {
                s.characteristics & 0x20000000 != 0 && s.raw_size > 0x1000
            });
            if has_code {
                anomalies.push(Anomaly {
                    rule_id: "RICH-002".into(),
                    category: "Rich Header".into(),
                    severity: "info".into(),
                    description: "No Rich Header found — PE may not have been built with MSVC toolchain".into(),
                    evidence: None,
                    threshold: None,
                });
            }
        }

    anomalies
}

// --- OPSEC detection subsystem (OPSEC-002 through OPSEC-007) ---

static AWS_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").unwrap()
});
static SLACK_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(xoxb|xoxp|xoxo|xapp|xwfp)-[A-Za-z0-9\-]{10,}").unwrap()
});
static GOOGLE_API_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap()
});
static GITHUB_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b").unwrap()
});
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(https?|wss?)://[^\s<>"']+"#).unwrap()
});
static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap()
});

const MAX_CREDENTIAL_FINDINGS: usize = 50;
const MAX_ENDPOINT_FINDINGS: usize = 100;

#[derive(Debug, Clone, Copy)]
enum PdbPathClass {
    WindowsUserProfile,
    WindowsUncShare,
    PosixHome,
    Relative,
    WindowsSystem,
    CiAzureDevOps,
    CiGitHubActions,
    CiBuildServer,
    Other,
}

impl PdbPathClass {
    fn as_str(&self) -> &'static str {
        match self {
            PdbPathClass::WindowsUserProfile => "windows_user_profile",
            PdbPathClass::WindowsUncShare => "windows_unc_share",
            PdbPathClass::PosixHome => "posix_home",
            PdbPathClass::Relative => "relative",
            PdbPathClass::WindowsSystem => "windows_system",
            PdbPathClass::CiAzureDevOps => "ci_azure_devops",
            PdbPathClass::CiGitHubActions => "ci_github_actions",
            PdbPathClass::CiBuildServer => "ci_build_server",
            PdbPathClass::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum IpClass {
    Private,
    Loopback,
    LinkLocal,
    Public,
}

impl IpClass {
    fn as_str(&self) -> &'static str {
        match self {
            IpClass::Private => "private",
            IpClass::Loopback => "loopback",
            IpClass::LinkLocal => "link_local",
            IpClass::Public => "public",
        }
    }
}

fn detect_opsec(
    file_info: &Option<FileInfo>,
    debug: &Option<DebugInfo>,
    resources: &Option<ResourceInfo>,
    rich_header: &Option<RichHeaderInfo>,
    authenticode: &Option<AuthenticodeInfo>,
    strings: Option<&Vec<StringEntry>>,
    data: &[u8],
) -> (OpsecInfo, Vec<Anomaly>) {
    let mut findings = Vec::new();
    let mut anomalies = Vec::new();

    detect_pdb_opsec(debug, &mut findings);
    detect_version_mismatch(file_info, resources, authenticode, &mut findings, &mut anomalies);
    if let Some(strings) = strings {
        detect_credentials(strings, &mut findings, &mut anomalies);
        detect_endpoints(strings, &mut findings, &mut anomalies);
        detect_source_path_leaks(strings, &mut findings);
    }
    // Always scan raw bytes for source path leaks (works without -a/--opsec-strict)
    detect_source_path_leaks_raw(data, &mut findings);
    detect_rich_opsec(rich_header, &mut findings);

    let summary = build_opsec_summary(&findings);
    (OpsecInfo { summary, findings }, anomalies)
}

fn classify_pdb_path(path: &str) -> (PdbPathClass, Option<String>) {
    let normalized = path.replace('/', "\\");

    // CI/CD patterns checked FIRST — more specific than user profile patterns.
    // Self-hosted runners often use C:\Users\runneradmin\... or /home/jenkins/...
    // which would otherwise match the generic user profile patterns.
    let p_lower = normalized.to_ascii_lowercase();
    if p_lower.contains("\\agent\\_work\\") || p_lower.contains("\\a\\_work\\") {
        return (PdbPathClass::CiAzureDevOps, None);
    }
    if p_lower.contains("\\actions-runner\\") || p_lower.contains("\\runner\\work\\")
        || p_lower.contains("\\actions\\runner\\") || path.contains("/home/runner/work/") {
        return (PdbPathClass::CiGitHubActions, None);
    }
    if p_lower.contains("\\jenkins\\workspace\\") || p_lower.contains("/jenkins/")
        || path.contains("/workspace/") && path.contains("jenkins") {
        return (PdbPathClass::CiBuildServer, None);
    }
    if p_lower.contains("\\buildagent\\work\\") || p_lower.contains("\\teamcity\\") {
        return (PdbPathClass::CiBuildServer, None);
    }

    // Windows user profile: C:\Users\<name>\...
    let user_prefix = ["C:\\Users\\", "D:\\Users\\", "E:\\Users\\"];
    for prefix in &user_prefix {
        if let Some(rest) = normalized.strip_prefix(prefix) {
            let user = rest.split('\\').next().unwrap_or("").to_string();
            if !user.is_empty() {
                return (PdbPathClass::WindowsUserProfile, Some(user));
            }
        }
    }

    if normalized.starts_with("\\\\") {
        return (PdbPathClass::WindowsUncShare, None);
    }

    if path.starts_with("/home/") {
        let user = path.trim_start_matches("/home/")
            .split('/').next().unwrap_or("").to_string();
        if !user.is_empty() {
            return (PdbPathClass::PosixHome, Some(user));
        }
    }

    if path.starts_with(".\\") || path.starts_with("./")
        || path.starts_with("..\\") || path.starts_with("../") {
        return (PdbPathClass::Relative, None);
    }

    if normalized.starts_with("C:\\Windows\\") || normalized.starts_with("C:\\Program Files") {
        return (PdbPathClass::WindowsSystem, None);
    }

    (PdbPathClass::Other, None)
}

fn detect_pdb_opsec(
    debug: &Option<DebugInfo>,
    findings: &mut Vec<OpsecFinding>,
) {
    let dbg = match debug {
        Some(d) => d,
        None => return,
    };

    for entry in &dbg.entries {
        // Only consider CodeView entries (type 2) with confirmed RSDS (guid present)
        if entry.debug_type_raw == 2 && entry.guid.is_some() {
            match entry.pdb_path.as_deref() {
                None | Some("") => {
                    // OPSEC-003: Nulled/empty CodeView PDB path
                    let mut evidence = BTreeMap::new();
                    if let Some(ref guid) = entry.guid {
                        evidence.insert("guid".into(), guid.clone());
                    }
                    if let Some(age) = entry.age {
                        evidence.insert("age".into(), age.to_string());
                    }
                    findings.push(OpsecFinding {
                        id: "OPSEC-003".into(),
                        finding_type: "nulled_pdb".into(),
                        severity: "warning".into(),
                        source: "debug_directory".into(),
                        description: "CodeView RSDS structure present but PDB path is empty/nulled — possible deliberate OPSEC countermeasure".into(),
                        evidence,
                        confidence: 0.8,
                    });
                }
                Some(pdb) => {
                    // OPSEC-002: PDB path classification
                    let (path_class, username) = classify_pdb_path(pdb);
                    let mut evidence = BTreeMap::new();
                    evidence.insert("pdb_path".into(), pdb.to_string());
                    evidence.insert("path_class".into(), path_class.as_str().into());
                    if let Some(ref user) = username {
                        evidence.insert("username_hint".into(), user.clone());
                    }
                    findings.push(OpsecFinding {
                        id: "OPSEC-002".into(),
                        finding_type: "pdb_path".into(),
                        severity: "info".into(),
                        source: "debug_directory".into(),
                        description: format!("PDB path classified as {}: {}", path_class.as_str(), pdb),
                        evidence,
                        confidence: 0.9,
                    });
                    // OPSEC-008: CI/CD path trace
                    match path_class {
                        PdbPathClass::CiAzureDevOps | PdbPathClass::CiGitHubActions | PdbPathClass::CiBuildServer => {
                            let mut ci_ev = BTreeMap::new();
                            ci_ev.insert("pdb_path".into(), pdb.to_string());
                            ci_ev.insert("ci_system".into(), path_class.as_str().into());
                            findings.push(OpsecFinding {
                                id: "OPSEC-008".into(),
                                finding_type: "ci_cd_trace".into(),
                                severity: "info".into(),
                                source: "debug_directory".into(),
                                description: format!("PDB path indicates CI/CD build environment ({}): {}", path_class.as_str(), pdb),
                                evidence: ci_ev,
                                confidence: 0.85,
                            });
                        }
                        _ => {}
                    }
                    // Note: OPSEC-001 anomaly is already emitted by detect_anomalies
                }
            }
        }
    }
}

fn strip_pe_ext(s: &str) -> &str {
    s.strip_suffix(".exe")
        .or_else(|| s.strip_suffix(".dll"))
        .or_else(|| s.strip_suffix(".sys"))
        .or_else(|| s.strip_suffix(".ocx"))
        .or_else(|| s.strip_suffix(".scr"))
        .unwrap_or(s)
}

fn mismatch_score(on_disk: &str, meta: &str) -> u8 {
    if on_disk == meta { return 0; }
    if strip_pe_ext(on_disk) == strip_pe_ext(meta) { return 1; }
    2
}

fn detect_version_mismatch(
    file_info: &Option<FileInfo>,
    resources: &Option<ResourceInfo>,
    authenticode: &Option<AuthenticodeInfo>,
    findings: &mut Vec<OpsecFinding>,
    anomalies: &mut Vec<Anomaly>,
) {
    let info = match file_info {
        Some(i) => i,
        None => return,
    };
    let res = match resources {
        Some(r) => r,
        None => return,
    };
    let ver = match &res.version_info {
        Some(v) => v,
        None => return,
    };

    let on_disk = std::path::Path::new(&info.name)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    if on_disk.is_empty() {
        return;
    }
    let on_disk_lower = on_disk.to_ascii_lowercase();

    // Check OriginalFilename
    let original_filename = ver.string_info.iter()
        .find(|kv| kv.key.eq_ignore_ascii_case("OriginalFilename"))
        .map(|kv| kv.value.trim().to_string());

    if let Some(ref orig) = original_filename {
        if !orig.is_empty() {
            let orig_lower = orig.to_ascii_lowercase();
            let score = mismatch_score(&on_disk_lower, &orig_lower);
            if score >= 2 {
                let mut evidence = BTreeMap::new();
                evidence.insert("on_disk_name".into(), on_disk.clone());
                evidence.insert("original_filename".into(), orig.clone());
                evidence.insert("mismatch_level".into(), "strong".into());
                findings.push(OpsecFinding {
                    id: "OPSEC-004".into(),
                    finding_type: "version_mismatch".into(),
                    severity: "warning".into(),
                    source: "version_info".into(),
                    description: format!(
                        "Filename mismatch: on-disk '{}' vs OriginalFilename '{}' — possible masquerading",
                        on_disk, orig
                    ),
                    evidence,
                    confidence: 0.85,
                });
                anomalies.push(Anomaly {
                    rule_id: "OPSEC-004".into(),
                    category: "OPSEC".into(),
                    severity: "warning".into(),
                    description: format!(
                        "Filename mismatch: on-disk '{}' vs OriginalFilename '{}' — possible masquerading",
                        on_disk, orig
                    ),
                    evidence: Some(format!("on_disk={}, original_filename={}", on_disk, orig)),
                    threshold: None,
                });
            } else if score == 1 {
                let mut evidence = BTreeMap::new();
                evidence.insert("on_disk_name".into(), on_disk.clone());
                evidence.insert("original_filename".into(), orig.clone());
                evidence.insert("mismatch_level".into(), "weak".into());
                findings.push(OpsecFinding {
                    id: "OPSEC-004".into(),
                    finding_type: "version_mismatch".into(),
                    severity: "info".into(),
                    source: "version_info".into(),
                    description: format!(
                        "Minor filename difference: on-disk '{}' vs OriginalFilename '{}'",
                        on_disk, orig
                    ),
                    evidence,
                    confidence: 0.5,
                });
            }
        }
    }

    // Check InternalName — but downgrade if OriginalFilename already matches on-disk name,
    // since InternalName is often a product description (e.g., "Client Application") rather
    // than a filename, and a mismatch alone is not suspicious in that case.
    let orig_matches = original_filename.as_ref()
        .is_some_and(|orig| mismatch_score(&on_disk_lower, &orig.to_ascii_lowercase()) == 0);
    let internal_name = ver.string_info.iter()
        .find(|kv| kv.key.eq_ignore_ascii_case("InternalName"))
        .map(|kv| kv.value.trim().to_string());

    if let Some(ref iname) = internal_name {
        if !iname.is_empty() {
            let iname_lower = iname.to_ascii_lowercase();
            let score = mismatch_score(&on_disk_lower, &iname_lower);
            // When OriginalFilename matches, InternalName mismatch is just info
            let effective_severity = if orig_matches && score >= 2 { "info" } else if score >= 2 { "warning" } else { "info" };
            if score >= 2 {
                let mut evidence = BTreeMap::new();
                evidence.insert("on_disk_name".into(), on_disk.clone());
                evidence.insert("internal_name".into(), iname.clone());
                evidence.insert("mismatch_level".into(), if orig_matches { "weak_internal_only" } else { "strong" }.into());
                findings.push(OpsecFinding {
                    id: "OPSEC-004".into(),
                    finding_type: "version_mismatch".into(),
                    severity: effective_severity.into(),
                    source: "version_info".into(),
                    description: format!(
                        "Filename mismatch: on-disk '{}' vs InternalName '{}'{}",
                        on_disk, iname,
                        if orig_matches { "" } else { " — possible masquerading" }
                    ),
                    evidence,
                    confidence: if orig_matches { 0.3 } else { 0.85 },
                });
                if !orig_matches {
                    anomalies.push(Anomaly {
                        rule_id: "OPSEC-004".into(),
                        category: "OPSEC".into(),
                        severity: "warning".into(),
                        description: format!(
                            "Filename mismatch: on-disk '{}' vs InternalName '{}' — possible masquerading",
                            on_disk, iname
                        ),
                        evidence: Some(format!("on_disk={}, internal_name={}", on_disk, iname)),
                        threshold: None,
                    });
                }
            } else if score == 1 {
                let mut evidence = BTreeMap::new();
                evidence.insert("on_disk_name".into(), on_disk.clone());
                evidence.insert("internal_name".into(), iname.clone());
                evidence.insert("mismatch_level".into(), "weak".into());
                findings.push(OpsecFinding {
                    id: "OPSEC-004".into(),
                    finding_type: "version_mismatch".into(),
                    severity: "info".into(),
                    source: "version_info".into(),
                    description: format!(
                        "Minor filename difference: on-disk '{}' vs InternalName '{}'",
                        on_disk, iname
                    ),
                    evidence,
                    confidence: 0.5,
                });
            }
        }
    }

    // Vendor masquerading: claims known vendor but not properly signed.
    // Only check when authenticode was actually evaluated (not None) to avoid
    // false positives in limited display modes where authenticode is not parsed.
    // Distinguish three states:
    //   signed=false             → unsigned (high confidence masquerading)
    //   signed=true, parse_ok=false → signature present but unparseable (lower confidence)
    //   signed=true, parse_ok=true  → properly signed (no finding)
    if let Some(auth) = authenticode {
        let company_name = ver.string_info.iter()
            .find(|kv| kv.key.eq_ignore_ascii_case("CompanyName"))
            .map(|kv| kv.value.trim().to_string());

        if let Some(ref company) = company_name {
            let known_vendors = ["Microsoft", "Google", "Adobe", "Apple", "Mozilla", "Oracle"];
            let claims_vendor = known_vendors.iter().any(|v| {
                company.to_ascii_lowercase().contains(&v.to_ascii_lowercase())
            });
            if claims_vendor && !auth.signed {
                let mut evidence = BTreeMap::new();
                evidence.insert("company_name".into(), company.clone());
                evidence.insert("signed".into(), "false".into());
                findings.push(OpsecFinding {
                    id: "OPSEC-004".into(),
                    finding_type: "vendor_mismatch".into(),
                    severity: "warning".into(),
                    source: "version_info".into(),
                    description: format!(
                        "Claims vendor '{}' but binary is not signed — possible masquerading",
                        company
                    ),
                    evidence,
                    confidence: 0.8,
                });
                anomalies.push(Anomaly {
                    rule_id: "OPSEC-004".into(),
                    category: "OPSEC".into(),
                    severity: "warning".into(),
                    description: format!("Claims vendor '{}' but binary is not signed", company),
                    evidence: Some(format!("company_name={}", company)),
                    threshold: None,
                });
            } else if claims_vendor && auth.signed && !auth.parse_ok {
                let mut evidence = BTreeMap::new();
                evidence.insert("company_name".into(), company.clone());
                evidence.insert("signed".into(), "true".into());
                evidence.insert("parse_ok".into(), "false".into());
                findings.push(OpsecFinding {
                    id: "OPSEC-004".into(),
                    finding_type: "vendor_mismatch".into(),
                    severity: "info".into(),
                    source: "version_info".into(),
                    description: format!(
                        "Claims vendor '{}' — signature present but could not be verified",
                        company
                    ),
                    evidence,
                    confidence: 0.4,
                });
            }
        }
    }
}

fn detect_credentials(
    strings: &[StringEntry],
    findings: &mut Vec<OpsecFinding>,
    anomalies: &mut Vec<Anomaly>,
) {
    let mut count = 0;

    for s in strings {
        if count >= MAX_CREDENTIAL_FINDINGS { break; }

        // AWS Access Key ID
        if let Some(m) = AWS_KEY_RE.find(&s.value) {
            let prefix = &m.as_str()[..4];
            let mut evidence = BTreeMap::new();
            evidence.insert("pattern".into(), "aws_access_key_id".into());
            evidence.insert("offset".into(), format!("{:#x}", s.offset));
            evidence.insert("prefix".into(), prefix.to_string());
            findings.push(OpsecFinding {
                id: "OPSEC-005".into(),
                finding_type: "credential".into(),
                severity: "critical".into(),
                source: "strings".into(),
                description: format!("Possible AWS access key ID at offset {:#x}", s.offset),
                evidence,
                confidence: 0.95,
            });
            anomalies.push(Anomaly {
                rule_id: "OPSEC-005".into(),
                category: "OPSEC".into(),
                severity: "critical".into(),
                description: format!("Possible AWS access key ID at offset {:#x}", s.offset),
                evidence: Some(format!("prefix={}", prefix)),
                threshold: None,
            });
            count += 1;
            continue;
        }

        // Slack token
        if let Some(m) = SLACK_TOKEN_RE.find(&s.value) {
            let prefix = m.as_str().split('-').next().unwrap_or("");
            let mut evidence = BTreeMap::new();
            evidence.insert("pattern".into(), "slack_token".into());
            evidence.insert("offset".into(), format!("{:#x}", s.offset));
            evidence.insert("prefix".into(), prefix.to_string());
            findings.push(OpsecFinding {
                id: "OPSEC-005".into(),
                finding_type: "credential".into(),
                severity: "critical".into(),
                source: "strings".into(),
                description: format!("Possible Slack token ({}) at offset {:#x}", prefix, s.offset),
                evidence,
                confidence: 0.9,
            });
            anomalies.push(Anomaly {
                rule_id: "OPSEC-005".into(),
                category: "OPSEC".into(),
                severity: "critical".into(),
                description: format!("Possible Slack token ({}) at offset {:#x}", prefix, s.offset),
                evidence: Some(format!("prefix={}", prefix)),
                threshold: None,
            });
            count += 1;
            continue;
        }

        // Google API key
        if GOOGLE_API_KEY_RE.is_match(&s.value) {
            let mut evidence = BTreeMap::new();
            evidence.insert("pattern".into(), "google_api_key".into());
            evidence.insert("offset".into(), format!("{:#x}", s.offset));
            findings.push(OpsecFinding {
                id: "OPSEC-005".into(),
                finding_type: "credential".into(),
                severity: "critical".into(),
                source: "strings".into(),
                description: format!("Possible Google API key at offset {:#x}", s.offset),
                evidence,
                confidence: 0.85,
            });
            anomalies.push(Anomaly {
                rule_id: "OPSEC-005".into(),
                category: "OPSEC".into(),
                severity: "critical".into(),
                description: format!("Possible Google API key at offset {:#x}", s.offset),
                evidence: Some("prefix=AIza".into()),
                threshold: None,
            });
            count += 1;
            continue;
        }

        // GitHub token
        if let Some(m) = GITHUB_TOKEN_RE.find(&s.value) {
            let prefix = m.as_str().split('_').next().unwrap_or("");
            let mut evidence = BTreeMap::new();
            evidence.insert("pattern".into(), "github_token".into());
            evidence.insert("offset".into(), format!("{:#x}", s.offset));
            evidence.insert("prefix".into(), prefix.to_string());
            findings.push(OpsecFinding {
                id: "OPSEC-005".into(),
                finding_type: "credential".into(),
                severity: "critical".into(),
                source: "strings".into(),
                description: format!("Possible GitHub token ({}) at offset {:#x}", prefix, s.offset),
                evidence,
                confidence: 0.9,
            });
            anomalies.push(Anomaly {
                rule_id: "OPSEC-005".into(),
                category: "OPSEC".into(),
                severity: "critical".into(),
                description: format!("Possible GitHub token ({}) at offset {:#x}", prefix, s.offset),
                evidence: Some(format!("prefix={}", prefix)),
                threshold: None,
            });
            count += 1;
        }
    }
}

fn classify_ipv4(octets: &[u8; 4]) -> IpClass {
    match octets {
        [10, ..] => IpClass::Private,
        [172, b, ..] if (16..=31).contains(b) => IpClass::Private,
        [192, 168, ..] => IpClass::Private,
        [127, ..] => IpClass::Loopback,
        [169, 254, ..] => IpClass::LinkLocal,
        _ => IpClass::Public,
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part.parse().ok()?;
    }
    if octets[0] == 0 { return None; }
    Some(octets)
}

fn detect_endpoints(
    strings: &[StringEntry],
    findings: &mut Vec<OpsecFinding>,
    anomalies: &mut Vec<Anomaly>,
) {
    let mut count = 0;
    let mut seen_urls: HashSet<String> = HashSet::new();
    let mut seen_ips: HashSet<String> = HashSet::new();

    for s in strings {
        if count >= MAX_ENDPOINT_FINDINGS { break; }

        // URL detection
        for m in URL_RE.find_iter(&s.value) {
            if count >= MAX_ENDPOINT_FINDINGS { break; }
            let url = m.as_str();
            if !seen_urls.insert(url.to_string()) { continue; }
            // Skip regex patterns embedded in binaries (contain metacharacters)
            if url.contains("(.") || url.contains("(?") || url.contains("[^")
                || url.contains("\\d") || url.contains("\\w") || url.ends_with('$') {
                continue;
            }

            let is_internal = url.contains("localhost")
                || url.contains("127.0.0.1")
                || url.contains(".local")
                || url.contains(".internal")
                || url.contains(".lan");

            let severity = if is_internal { "warning" } else { "info" };
            let mut evidence = BTreeMap::new();
            evidence.insert("url".into(), url.to_string());
            evidence.insert("offset".into(), format!("{:#x}", s.offset));
            evidence.insert("class".into(), if is_internal { "internal" } else { "external" }.into());

            findings.push(OpsecFinding {
                id: "OPSEC-006".into(),
                finding_type: "endpoint".into(),
                severity: severity.into(),
                source: "strings".into(),
                description: format!("Hardcoded {} URL: {}", if is_internal { "internal" } else { "external" }, url),
                evidence,
                confidence: 0.8,
            });

            if is_internal {
                anomalies.push(Anomaly {
                    rule_id: "OPSEC-006".into(),
                    category: "OPSEC".into(),
                    severity: "warning".into(),
                    description: format!("Internal/local URL found: {}", url),
                    evidence: Some(url.to_string()),
                    threshold: None,
                });
            }
            count += 1;
        }

        // Private/reserved IP detection
        for cap in IPV4_RE.captures_iter(&s.value) {
            if count >= MAX_ENDPOINT_FINDINGS { break; }
            let ip_str = cap.get(1).unwrap().as_str();
            if !seen_ips.insert(ip_str.to_string()) { continue; }

            if let Some(octets) = parse_ipv4(ip_str) {
                let class = classify_ipv4(&octets);
                if class == IpClass::Public { continue; }

                let severity = if class == IpClass::Private { "warning" } else { "info" };
                let mut evidence = BTreeMap::new();
                evidence.insert("ip".into(), ip_str.to_string());
                evidence.insert("offset".into(), format!("{:#x}", s.offset));
                evidence.insert("class".into(), class.as_str().into());

                findings.push(OpsecFinding {
                    id: "OPSEC-006".into(),
                    finding_type: "endpoint".into(),
                    severity: severity.into(),
                    source: "strings".into(),
                    description: format!("Hardcoded {} IP address: {}", class.as_str(), ip_str),
                    evidence,
                    confidence: 0.7,
                });

                if class == IpClass::Private {
                    anomalies.push(Anomaly {
                        rule_id: "OPSEC-006".into(),
                        category: "OPSEC".into(),
                        severity: "warning".into(),
                        description: format!("Private IP address found: {}", ip_str),
                        evidence: Some(ip_str.to_string()),
                        threshold: None,
                    });
                }
                count += 1;
            }
        }
    }
}

fn detect_source_path_leaks(
    strings: &[StringEntry],
    findings: &mut Vec<OpsecFinding>,
) {
    let mut seen_users: HashSet<String> = HashSet::new();

    // Patterns for source/build paths that leak usernames.
    // Common in Go (embeds full source paths), Rust, and debug builds.
    let user_path_prefixes: &[(&str, &str)] = &[
        ("c:/users/", "windows"),
        ("c:\\users\\", "windows"),
        ("d:/users/", "windows"),
        ("d:\\users\\", "windows"),
        ("/home/", "posix"),
        ("/users/", "macos"),
    ];

    for s in strings {
        let lower = s.value.to_ascii_lowercase();
        for &(prefix, os_hint) in user_path_prefixes {
            if let Some(rest) = lower.strip_prefix(prefix) {
                let user = rest.split(['/', '\\']).next().unwrap_or("");
                if user.is_empty() || seen_users.contains(user) { continue; }
                // Skip generic/system users
                if matches!(user, "public" | "default" | "all users" | "administrator") {
                    continue;
                }
                seen_users.insert(user.to_string());

                let mut evidence = BTreeMap::new();
                evidence.insert("username".into(), user.to_string());
                evidence.insert("os_hint".into(), os_hint.into());
                evidence.insert("sample_path".into(), s.value.clone());
                evidence.insert("offset".into(), format!("{:#x}", s.offset));

                findings.push(OpsecFinding {
                    id: "OPSEC-009".into(),
                    finding_type: "source_path_leak".into(),
                    severity: "warning".into(),
                    source: "strings".into(),
                    description: format!(
                        "Source/build path leaks username '{}' ({})",
                        user, os_hint
                    ),
                    evidence,
                    confidence: 0.85,
                });
            }
        }
    }
}

/// Scan raw PE bytes for source path leaks without requiring string extraction.
/// Detects patterns like C:/Users/<name>/ and /home/<name>/ directly in binary data.
fn detect_source_path_leaks_raw(
    data: &[u8],
    findings: &mut Vec<OpsecFinding>,
) {
    let mut seen_users: HashSet<String> = HashSet::new();
    // Collect users already found by string-based detection to avoid duplicates
    for f in findings.iter() {
        if f.finding_type == "source_path_leak" {
            if let Some(user) = f.evidence.get("username") {
                seen_users.insert(user.to_ascii_lowercase());
            }
        }
    }

    let markers: &[&[u8]] = &[
        b"C:/Users/", b"C:\\Users\\",
        b"D:/Users/", b"D:\\Users\\",
        b"/home/",
    ];

    let scan_limit = data.len().min(16 * 1024 * 1024);
    let scan_data = &data[..scan_limit];

    for marker in markers {
        let mut pos = 0;
        while pos + marker.len() < scan_data.len() {
            let haystack = &scan_data[pos..];
            let found = match find_bytes(haystack, marker) {
                Some(off) => off,
                None => break,
            };
            let match_start = pos + found;
            let abs_pos = match_start + marker.len();
            pos = abs_pos;

            // Skip if this /home/ is part of a URL or domain path.
            // Look back for URL indicators: "://", "www.", or ".com", ".net" etc.
            if match_start >= 3 {
                let lookback_start = match_start.saturating_sub(32);
                let lookback = &scan_data[lookback_start..match_start];
                let is_url = lookback.windows(3).any(|w| w == b"://")
                    || lookback.windows(4).any(|w| w == b"www.")
                    || lookback.windows(4).any(|w| w == b".com" || w == b".net" || w == b".org" || w == b".io/");
                if is_url { continue; }
                // Also skip if preceded by a dot (domain component like api.example.local/home/)
                if match_start > 0 && scan_data[match_start - 1] != b'\0'
                    && scan_data[match_start - 1] != b'\n'
                    && scan_data[match_start - 1] != b'\r'
                    && scan_data[match_start - 1] > 0x20
                    && scan_data[match_start - 1] != b'"'
                    && *marker == b"/home/" as &[u8] {
                    // /home/ mid-string (not at string boundary) — likely a URL path
                    continue;
                }
            }

            // Extract username: read printable ASCII until / or \ or non-printable
            let user_start = abs_pos;
            let mut user_end = user_start;
            while user_end < scan_data.len() && user_end - user_start < 64 {
                let b = scan_data[user_end];
                if b == b'/' || b == b'\\' || b < 0x20 || b > 0x7e {
                    break;
                }
                user_end += 1;
            }
            if user_end == user_start { continue; }

            let user = String::from_utf8_lossy(&scan_data[user_start..user_end]).to_string();
            let user_lower = user.to_ascii_lowercase();
            if matches!(user_lower.as_str(), "public" | "default" | "all users" | "administrator") {
                continue;
            }
            if seen_users.contains(&user_lower) { continue; }
            seen_users.insert(user_lower);

            // Extract a sample path (up to 200 chars of printable ASCII)
            let path_start = abs_pos - marker.len();
            let mut path_end = path_start;
            while path_end < scan_data.len() && path_end - path_start < 200 {
                let b = scan_data[path_end];
                if b < 0x20 || b > 0x7e { break; }
                path_end += 1;
            }
            let sample_path = String::from_utf8_lossy(&scan_data[path_start..path_end]).to_string();

            let os_hint = if marker.starts_with(b"/") { "posix" } else { "windows" };
            let mut evidence = BTreeMap::new();
            evidence.insert("username".into(), user.clone());
            evidence.insert("os_hint".into(), os_hint.into());
            evidence.insert("sample_path".into(), sample_path);
            evidence.insert("offset".into(), format!("{:#x}", path_start));

            findings.push(OpsecFinding {
                id: "OPSEC-009".into(),
                finding_type: "source_path_leak".into(),
                severity: "warning".into(),
                source: "raw_bytes".into(),
                description: format!(
                    "Source/build path leaks username '{}' ({})",
                    user, os_hint
                ),
                evidence,
                confidence: 0.85,
            });
        }
    }
}

fn detect_rich_opsec(
    rich_header: &Option<RichHeaderInfo>,
    findings: &mut Vec<OpsecFinding>,
) {
    let rich = match rich_header {
        Some(r) => r,
        None => return,
    };

    // OPSEC-007: Rich Header checksum invalid as OPSEC surface
    if !rich.checksum_valid {
        let mut evidence = BTreeMap::new();
        evidence.insert("xor_key".into(), rich.xor_key.clone());
        evidence.insert("checksum_valid".into(), "false".into());
        findings.push(OpsecFinding {
            id: "OPSEC-007".into(),
            finding_type: "rich_header".into(),
            severity: "warning".into(),
            source: "rich_header".into(),
            description: "Rich Header checksum invalid — build fingerprint may be tampered for OPSEC/attribution purposes".into(),
            evidence,
            confidence: 0.8,
        });
        // Note: RICH-001 anomaly is already emitted by detect_anomalies
    }

    // Wide toolset version range check
    if !rich.entries.is_empty() {
        let active: Vec<_> = rich.entries.iter().filter(|e| e.count > 0).collect();
        if let (Some(oldest), Some(newest)) = (
            active.iter().min_by_key(|e| e.build_id),
            active.iter().max_by_key(|e| e.build_id),
        ) {
            if oldest.build_id < 7000 && newest.build_id > 25000 {
                let mut evidence = BTreeMap::new();
                evidence.insert("oldest_build_id".into(), oldest.build_id.to_string());
                evidence.insert("newest_build_id".into(), newest.build_id.to_string());
                if let Some(ref desc) = oldest.description {
                    evidence.insert("oldest_tool".into(), desc.clone());
                }
                if let Some(ref desc) = newest.description {
                    evidence.insert("newest_tool".into(), desc.clone());
                }
                findings.push(OpsecFinding {
                    id: "OPSEC-007".into(),
                    finding_type: "rich_header".into(),
                    severity: "info".into(),
                    source: "rich_header".into(),
                    description: "Rich Header shows very wide toolset version range — may indicate build environment mixing or tampering".into(),
                    evidence,
                    confidence: 0.5,
                });
            }
        }
    }
}

fn build_opsec_summary(findings: &[OpsecFinding]) -> OpsecSummary {
    let mut types = BTreeMap::new();
    let mut max_rank = 0u8;

    for f in findings {
        *types.entry(f.finding_type.clone()).or_insert(0) += 1;
        let rank = match f.severity.as_str() {
            "critical" => 3,
            "warning" => 2,
            "info" => 1,
            _ => 0,
        };
        if rank > max_rank { max_rank = rank; }
    }

    OpsecSummary {
        finding_count: findings.len(),
        max_severity: match max_rank {
            3 => "critical",
            2 => "warning",
            1 => "info",
            _ => "none",
        }.into(),
        types,
    }
}

// --- .NET metadata parsing ---

fn parse_dotnet(data: &[u8], pe: &PE) -> Option<DotNetInfo> {
    let opt = pe.header.optional_header.as_ref()?;
    let (dd14_rva, dd14_size) = match opt.data_directories.data_directories.get(14) {
        Some(Some((_, dd))) => (dd.virtual_address, dd.size),
        _ => (0, 0),
    };
    if dd14_rva == 0 || dd14_size == 0 {
        return None;
    }

    let cor20_offset = rva_to_offset(dd14_rva, pe, data.len())?;
    if cor20_offset + 72 > data.len() {
        return None;
    }

    // Parse IMAGE_COR20_HEADER
    let _cb = read_u32_le(data, cor20_offset);
    let major_rt = read_u16_le(data, cor20_offset + 4);
    let minor_rt = read_u16_le(data, cor20_offset + 6);
    let meta_rva = read_u32_le(data, cor20_offset + 8);
    let _meta_size = read_u32_le(data, cor20_offset + 12);
    let cor_flags = read_u32_le(data, cor20_offset + 16);

    if meta_rva == 0 {
        return None;
    }

    let runtime_version = format!("v{}.{}", major_rt, minor_rt);

    let mut flags = Vec::new();
    if cor_flags & 0x01 != 0 { flags.push("IL_ONLY".into()); }
    if cor_flags & 0x02 != 0 { flags.push("32BIT_REQUIRED".into()); }
    if cor_flags & 0x04 != 0 { flags.push("STRONG_NAME_SIGNED".into()); }
    if cor_flags & 0x10 != 0 { flags.push("NATIVE_ENTRYPOINT".into()); }
    if cor_flags & 0x10000 != 0 { flags.push("32BIT_PREFERRED".into()); }

    let meta_offset = rva_to_offset(meta_rva, pe, data.len())?;
    if meta_offset + 16 > data.len() {
        return None;
    }

    // Verify BSJB signature
    let sig = read_u32_le(data, meta_offset);
    if sig != 0x424A5342 {
        return None;
    }

    // Skip MajorVersion(2) + MinorVersion(2) + Reserved(4)
    let ver_len = read_u32_le(data, meta_offset + 12) as usize;
    if meta_offset + 16 + ver_len > data.len() {
        return None;
    }

    // Read version string (overrides runtime_version)
    let ver_bytes = &data[meta_offset + 16..meta_offset + 16 + ver_len];
    let ver_string = String::from_utf8_lossy(ver_bytes)
        .trim_end_matches('\0')
        .to_string();
    let runtime_version = if !ver_string.is_empty() { ver_string } else { runtime_version };

    // After version string: Flags(2) + NumberOfStreams(2)
    let padded_ver_len = (ver_len + 3) & !3;
    let streams_offset = meta_offset + 16 + padded_ver_len;
    if streams_offset + 4 > data.len() {
        return Some(DotNetInfo {
            runtime_version,
            flags,
            assembly_name: None,
            assembly_version: None,
            references: Vec::new(),
        });
    }

    let _stream_flags = read_u16_le(data, streams_offset);
    let num_streams = read_u16_le(data, streams_offset + 2) as usize;

    // Parse stream headers
    struct StreamInfo {
        offset: u32,
        #[allow(dead_code)]
        size: u32,
        name: String,
    }
    let mut streams = Vec::new();
    let mut pos = streams_offset + 4;
    for _ in 0..num_streams {
        if pos + 8 > data.len() { break; }
        let s_offset = read_u32_le(data, pos);
        let s_size = read_u32_le(data, pos + 4);
        pos += 8;
        // Read null-terminated name, padded to 4-byte boundary
        let name_start = pos;
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        let name = String::from_utf8_lossy(&data[name_start..pos]).to_string();
        pos += 1; // skip null
        pos = (pos + 3) & !3; // pad to 4-byte boundary
        streams.push(StreamInfo { offset: s_offset, size: s_size, name });
    }

    // Find #Strings, #~ (or #-) streams
    let strings_stream = streams.iter().find(|s| s.name == "#Strings");
    let tilde_stream = streams.iter().find(|s| s.name == "#~" || s.name == "#-");

    let mut assembly_name = None;
    let mut assembly_version = None;
    let mut references = Vec::new();

    // Parse #~ stream for Assembly and AssemblyRef tables
    if let Some(tilde) = tilde_stream {
        let tilde_abs = meta_offset + tilde.offset as usize;
        if tilde_abs + 24 <= data.len() {
            // #~ header: Reserved(4) + MajorVer(1) + MinorVer(1) + HeapSizes(1) + Reserved(1) + Valid(8) + Sorted(8)
            let heap_sizes = data.get(tilde_abs + 6).copied().unwrap_or(0);
            let valid_lo = read_u32_le(data, tilde_abs + 8);
            let valid_hi = read_u32_le(data, tilde_abs + 12);
            let valid: u64 = (valid_hi as u64) << 32 | valid_lo as u64;

            // Read row counts for each table bit set in Valid
            let mut row_counts: HashMap<u8, u32> = HashMap::new();
            let mut rc_pos = tilde_abs + 24;
            for bit in 0u8..64 {
                if valid & (1u64 << bit) != 0 {
                    if rc_pos + 4 > data.len() { break; }
                    let count = read_u32_le(data, rc_pos);
                    row_counts.insert(bit, count);
                    rc_pos += 4;
                }
            }

            // Calculate data start (after row counts)
            let data_start = rc_pos;

            // Calculate row sizes and find offset of Assembly (0x20) and AssemblyRef (0x23)
            let s_size: usize = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
            let g_size: usize = if heap_sizes & 0x02 != 0 { 4 } else { 2 };
            let b_size: usize = if heap_sizes & 0x04 != 0 { 4 } else { 2 };

            let t_size = |table_id: u8| -> usize {
                if *row_counts.get(&table_id).unwrap_or(&0) > 65535 { 4 } else { 2 }
            };
            let c_size = |tag_bits: u32, tables: &[u8]| -> usize {
                let max_rows = tables.iter()
                    .map(|t| *row_counts.get(t).unwrap_or(&0))
                    .max()
                    .unwrap_or(0);
                if max_rows < (1u32 << (16 - tag_bits)) { 2 } else { 4 }
            };

            let calc_row_size = |table_id: u8| -> usize {
                match table_id {
                    0x00 => 2 + s_size + g_size + g_size + g_size, // Module
                    0x01 => c_size(2, &[0x02, 0x01, 0x1B]) + s_size + s_size, // TypeRef
                    0x02 => 4 + s_size + s_size + c_size(2, &[0x02, 0x01, 0x1B]) + t_size(0x04) + t_size(0x06), // TypeDef
                    0x03 => t_size(0x04), // FieldPtr
                    0x04 => 2 + s_size + b_size, // Field
                    0x05 => t_size(0x06), // MethodPtr
                    0x06 => 4 + 2 + 2 + s_size + b_size + t_size(0x08), // MethodDef
                    0x07 => t_size(0x08), // ParamPtr
                    0x08 => 2 + 2 + s_size, // Param
                    0x09 => t_size(0x02) + c_size(2, &[0x02, 0x01, 0x1B]), // InterfaceImpl
                    0x0A => c_size(3, &[0x02, 0x01, 0x1A, 0x06, 0x1B]) + s_size + b_size, // MemberRef
                    0x0B => 2 + c_size(2, &[0x04, 0x08, 0x17]) + b_size, // Constant
                    0x0C => c_size(5, &[0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B]) + c_size(3, &[0x06, 0x0A]) + b_size, // CustomAttribute
                    0x0D => c_size(1, &[0x04, 0x08]) + b_size, // FieldMarshal
                    0x0E => 2 + c_size(2, &[0x02, 0x06, 0x20]) + b_size, // DeclSecurity
                    0x0F => 2 + 4 + t_size(0x02), // ClassLayout
                    0x10 => 4 + t_size(0x04), // FieldLayout
                    0x11 => b_size, // StandAloneSig
                    0x12 => t_size(0x02) + t_size(0x14), // EventMap
                    0x13 => t_size(0x14), // EventPtr
                    0x14 => 2 + s_size + c_size(2, &[0x02, 0x01, 0x1B]), // Event
                    0x15 => t_size(0x02) + t_size(0x17), // PropertyMap
                    0x16 => t_size(0x17), // PropertyPtr
                    0x17 => 2 + s_size + b_size, // Property
                    0x18 => 2 + t_size(0x06) + c_size(1, &[0x14, 0x17]), // MethodSemantics
                    0x19 => t_size(0x02) + c_size(1, &[0x06, 0x0A]) + c_size(1, &[0x06, 0x0A]), // MethodImpl
                    0x1A => s_size, // ModuleRef
                    0x1B => b_size, // TypeSpec
                    0x1C => 2 + c_size(1, &[0x04, 0x06]) + s_size + t_size(0x1A), // ImplMap
                    0x1D => 4 + t_size(0x04), // FieldRVA
                    0x20 => 4 + 2 + 2 + 2 + 2 + 4 + b_size + s_size + s_size, // Assembly
                    0x21 => 4, // AssemblyProcessor
                    0x22 => 4 + 4 + 4, // AssemblyOS
                    0x23 => 2 + 2 + 2 + 2 + 4 + b_size + s_size + s_size + b_size, // AssemblyRef
                    _ => 0,
                }
            };

            // Calculate offset to each table in order
            let table_order: &[u8] = &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23,
            ];

            let mut table_offsets: HashMap<u8, usize> = HashMap::new();
            let mut current_offset = data_start;
            for &tid in table_order {
                if valid & (1u64 << tid) != 0 {
                    table_offsets.insert(tid, current_offset);
                    let rows = *row_counts.get(&tid).unwrap_or(&0) as usize;
                    let row_size = calc_row_size(tid);
                    current_offset += rows * row_size;
                }
            }

            // Helper: read a string index from #Strings stream
            let read_strings_idx = |offset: usize| -> Option<String> {
                let idx = if s_size == 4 {
                    read_u32_le(data, offset) as usize
                } else {
                    read_u16_le(data, offset) as usize
                };
                if let Some(ss) = strings_stream {
                    let abs = meta_offset + ss.offset as usize + idx;
                    if abs < data.len() {
                        let end = data[abs..].iter().position(|&b| b == 0).unwrap_or(0);
                        let s = String::from_utf8_lossy(&data[abs..abs + end]).to_string();
                        if !s.is_empty() { return Some(s); }
                    }
                }
                None
            };

            // Parse Assembly table (0x20)
            if let Some(&asm_off) = table_offsets.get(&0x20) {
                if valid & (1u64 << 0x20) != 0 {
                    // Assembly row: HashAlgId(4) + Major(2) + Minor(2) + Build(2) + Rev(2) + Flags(4) + PublicKey(B) + Name(S) + Culture(S)
                    let name_offset = asm_off + 4 + 2 + 2 + 2 + 2 + 4 + b_size;
                    let major = read_u16_le(data, asm_off + 4);
                    let minor = read_u16_le(data, asm_off + 6);
                    let build = read_u16_le(data, asm_off + 8);
                    let rev = read_u16_le(data, asm_off + 10);
                    assembly_version = Some(format!("{}.{}.{}.{}", major, minor, build, rev));
                    assembly_name = read_strings_idx(name_offset);
                }
            }

            // Parse AssemblyRef table (0x23)
            if let Some(&aref_off) = table_offsets.get(&0x23) {
                let aref_rows = *row_counts.get(&0x23).unwrap_or(&0) as usize;
                let aref_row_size = calc_row_size(0x23);
                let limit = aref_rows.min(20);
                for i in 0..limit {
                    let row_off = aref_off + i * aref_row_size;
                    // AssemblyRef: Major(2)+Minor(2)+Build(2)+Rev(2)+Flags(4)+PublicKeyOrToken(B)+Name(S)+Culture(S)+HashValue(B)
                    let ref_major = read_u16_le(data, row_off);
                    let ref_minor = read_u16_le(data, row_off + 2);
                    let ref_build = read_u16_le(data, row_off + 4);
                    let ref_rev = read_u16_le(data, row_off + 6);
                    let name_offset = row_off + 2 + 2 + 2 + 2 + 4 + b_size;
                    if let Some(name) = read_strings_idx(name_offset) {
                        references.push(format!("{} ({}.{}.{}.{})", name, ref_major, ref_minor, ref_build, ref_rev));
                    }
                }
            }
        }
    }

    Some(DotNetInfo {
        runtime_version,
        flags,
        assembly_name,
        assembly_version,
        references,
    })
}

// --- Go detection ---

fn detect_go(data: &[u8], pe: &PE) -> Option<GoInfo> {
    let mut markers = Vec::new();
    let mut build_id = None;

    // Check section names for Go-specific sections
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_string();
        if name == ".gopclntab" || name == ".go.buildinfo" {
            markers.push(name);
        }
    }

    // Scan for Go build ID marker in raw bytes (limit scan to 8MB)
    let scan_limit = data.len().min(8 * 1024 * 1024);
    let scan_data = &data[..scan_limit];

    // Look for "\xff Go build ID: \"" marker
    let marker_prefix = b"\xff Go build ID: \"";
    if let Some(pos) = find_bytes(scan_data, marker_prefix) {
        let start = pos + marker_prefix.len();
        if let Some(end_off) = scan_data[start..].iter().position(|&b| b == b'"') {
            let id = String::from_utf8_lossy(&scan_data[start..start + end_off]).to_string();
            if !id.is_empty() && id.len() < 200 {
                build_id = Some(id);
                markers.push("Go build ID".into());
            }
        }
    }

    // Look for other Go runtime markers
    for marker_str in &[b"runtime.go" as &[u8], b"runtime.cgo", b"GOMAXPROCS"] {
        if find_bytes(scan_data, marker_str).is_some() {
            markers.push(String::from_utf8_lossy(marker_str).to_string());
        }
    }

    // Require at least 2 markers AND at least 1 structural marker
    // (section name or build ID) to avoid false positives from string-only matches.
    let has_structural = markers.iter().any(|m| {
        m == ".gopclntab" || m == ".go.buildinfo" || m == "Go build ID"
    });
    if markers.len() < 2 || !has_structural { return None; }

    let confidence = if markers.len() >= 3 { 0.95 } else { 0.8 };
    Some(GoInfo { build_id, confidence, markers })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// --- Overlay classification ---

fn classify_overlay(data: &[u8], overlay_offset: usize, overlay_size: usize) -> Option<Vec<OverlayClassification>> {
    if overlay_size == 0 || overlay_offset >= data.len() { return None; }
    let overlay = &data[overlay_offset..data.len().min(overlay_offset + overlay_size)];
    if overlay.len() < 4 { return None; }

    let mut results = Vec::new();

    struct Sig { name: &'static str, magic: &'static [u8], confidence: f32 }
    let sigs: &[Sig] = &[
        Sig { name: "ZIP", magic: b"PK\x03\x04", confidence: 0.95 },
        Sig { name: "RAR", magic: b"Rar!\x1a\x07", confidence: 0.95 },
        Sig { name: "7z", magic: b"7z\xbc\xaf\x27\x1c", confidence: 0.95 },
        Sig { name: "CAB", magic: b"MSCF", confidence: 0.90 },
        Sig { name: "PE", magic: b"MZ", confidence: 0.80 },
        Sig { name: "PDF", magic: b"%PDF", confidence: 0.90 },
        Sig { name: "GZIP", magic: b"\x1f\x8b", confidence: 0.85 },
        Sig { name: "XZ", magic: b"\xfd7zXZ\x00", confidence: 0.95 },
        Sig { name: "NSIS", magic: b"\xef\xbe\xad\xde", confidence: 0.75 },
    ];

    for sig in sigs {
        if overlay.len() >= sig.magic.len() && &overlay[..sig.magic.len()] == sig.magic {
            results.push(OverlayClassification {
                format: sig.name.to_string(),
                confidence: sig.confidence,
            });
        }
    }

    if results.is_empty() { None } else { Some(results) }
}

// --- Build fingerprint ---

fn detect_packer(pe: &PE, data: &[u8], overlay_offset: Option<usize>,
                 anomalies: &[Anomaly]) -> Option<PackerInfo> {
    let section_names: Vec<String> = pe.sections.iter()
        .map(|s| String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string())
        .collect();
    let has_section = |pat: &str| -> bool {
        section_names.iter().any(|s| s.eq_ignore_ascii_case(pat))
    };

    // Corroboration signals from existing anomalies
    let has_anomaly = |rule: &str| anomalies.iter().any(|a| a.rule_id == rule);
    let has_pack_001 = has_anomaly("PACK-001"); // entropy > 7.0
    let has_pack_003 = has_anomaly("PACK-003"); // raw_size=0
    let has_pack_004 = has_anomaly("PACK-004"); // expansion ratio > 10x
    let has_code_002 = has_anomaly("CODE-002"); // EP not in .text
    let corroboration_bonus = |score: &mut f32| {
        if has_pack_001 { *score += 0.15; }
        if has_pack_003 { *score += 0.15; }
        if has_pack_004 { *score += 0.10; }
        if has_code_002 { *score += 0.05; }
    };

    // --- Overlay-based detections (Tier A: high precision) ---
    if let Some(ov_off) = overlay_offset {
        if ov_off < data.len() {
            let ov = &data[ov_off..];
            let scan_len = ov.len().min(256 * 1024); // scan up to 256KB of overlay

            // NSIS: magic 0xEFBEADDE or "NullsoftInst" string
            if ov.len() >= 4 && &ov[..4] == b"\xef\xbe\xad\xde" {
                return Some(PackerInfo {
                    name: "NSIS Installer".into(),
                    confidence: 0.90,
                    evidence: vec!["NSIS magic (0xEFBEADDE) in overlay".into()],
                });
            }
            if find_bytes(&ov[..scan_len], b"NullsoftInst").is_some() {
                return Some(PackerInfo {
                    name: "NSIS Installer".into(),
                    confidence: 0.90,
                    evidence: vec!["NullsoftInst string in overlay".into()],
                });
            }

            // Inno Setup: "Inno Setup Setup Data" in overlay
            if find_bytes(&ov[..scan_len], b"Inno Setup Setup Data").is_some() {
                return Some(PackerInfo {
                    name: "Inno Setup".into(),
                    confidence: 0.90,
                    evidence: vec!["Inno Setup Setup Data in overlay".into()],
                });
            }
            // Inno Setup fallback: "Inno Setup" in first 1KB
            if find_bytes(&ov[..ov.len().min(1024)], b"Inno Setup").is_some() {
                return Some(PackerInfo {
                    name: "Inno Setup".into(),
                    confidence: 0.80,
                    evidence: vec!["Inno Setup signature in overlay".into()],
                });
            }
        }
    }

    // --- UPX (Tier A: section constellation + near-start marker scan) ---
    {
        let mut score = 0.0f32;
        let mut evidence = Vec::new();

        let has_upx0 = has_section("UPX0") || has_section(".UPX0");
        let has_upx1 = has_section("UPX1") || has_section(".UPX1");
        let has_upx2 = has_section("UPX2") || has_section(".UPX2") || has_section("UPX!");

        if has_upx0 && has_upx1 {
            score += 0.60;
            evidence.push("section constellation: UPX0 + UPX1".into());
        } else if has_upx0 || has_upx1 || has_upx2 {
            score += 0.35;
            evidence.push("single UPX section name".into());
        }

        // Near-start marker scan (0..1024) — common UPX YARA approach
        let window = &data[..data.len().min(1024)];
        if find_bytes(window, b"UPX!").is_some() {
            score += 0.30;
            evidence.push("UPX! marker in header (0..1024)".into());
        }

        corroboration_bonus(&mut score);
        if score >= 0.60 {
            return Some(PackerInfo {
                name: "UPX".into(),
                confidence: score.min(1.0),
                evidence,
            });
        }
    }

    // --- MPRESS (Tier A: 2-name constellation) ---
    {
        let has_m1 = has_section(".MPRESS1");
        let has_m2 = has_section(".MPRESS2");
        if has_m1 && has_m2 {
            let mut score = 0.70f32;
            corroboration_bonus(&mut score);
            return Some(PackerInfo {
                name: "MPRESS".into(),
                confidence: score.min(1.0),
                evidence: vec!["section constellation: .MPRESS1 + .MPRESS2".into()],
            });
        } else if has_m1 || has_m2 {
            let mut score = 0.45f32;
            corroboration_bonus(&mut score);
            if score >= 0.60 {
                return Some(PackerInfo {
                    name: "MPRESS".into(),
                    confidence: score.min(1.0),
                    evidence: vec!["single MPRESS section name".into()],
                });
            }
        }
    }

    // --- ASPack (needs .aspack; .adata alone is ambiguous) ---
    {
        let has_aspack = has_section(".aspack") || has_section("ASPack") || has_section(".ASPack");
        let has_adata = has_section(".adata");
        if has_aspack {
            let mut score = if has_adata { 0.70f32 } else { 0.50 };
            corroboration_bonus(&mut score);
            if score >= 0.50 {
                let mut ev = vec![];
                if has_aspack { ev.push("section: .aspack".into()); }
                if has_adata { ev.push("section: .adata (corroborating)".into()); }
                return Some(PackerInfo {
                    name: "ASPack".into(),
                    confidence: score.min(1.0),
                    evidence: ev,
                });
            }
        }
    }

    // Helper: match patterns against sections, dedup by actual section name matched
    // (avoids case-variant patterns inflating matched count)
    let match_sections = |patterns: &[&str]| -> Vec<String> {
        let mut matched_names: Vec<String> = Vec::new();
        for sec in &section_names {
            let sec_lower = sec.to_ascii_lowercase();
            if patterns.iter().any(|pat| pat.to_ascii_lowercase() == sec_lower)
                && !matched_names.iter().any(|m: &String| m.to_ascii_lowercase() == sec_lower) {
                matched_names.push(sec.clone());
            }
        }
        matched_names
    };

    // --- Spoofable protectors (Tier B: medium confidence, require corroboration for high) ---
    struct ProtectorSig { name: &'static str, patterns: &'static [&'static str] }
    let protectors = [
        ProtectorSig { name: "Themida/WinLicense", patterns: &["Themida", ".Themida", "WinLicen", ".winlice"] },
        ProtectorSig { name: "VMProtect", patterns: &[".vmp0", ".vmp1", ".vmp2"] },
        ProtectorSig { name: "Enigma Protector", patterns: &[".enigma1", ".enigma2"] },
    ];
    for p in &protectors {
        let matched = match_sections(p.patterns);
        if !matched.is_empty() {
            let mut score = if matched.len() >= 2 { 0.55f32 } else { 0.45 };
            corroboration_bonus(&mut score);
            return Some(PackerInfo {
                name: p.name.into(),
                confidence: score.min(1.0),
                evidence: matched.iter().map(|s| format!("section: {}", s)).collect(),
            });
        }
    }

    // --- Other packers (section-name based, non-spoofable names) ---
    struct SimpleSig { name: &'static str, patterns: &'static [&'static str] }
    let simple_packers = [
        SimpleSig { name: "PECompact", patterns: &["pec1", "pec2", "PEC2MO", "PEC2TO", "PECompact2"] },
        SimpleSig { name: "NSPack", patterns: &[".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1", "nsp2"] },
        SimpleSig { name: "Petite", patterns: &[".petite"] },
        SimpleSig { name: "Upack", patterns: &[".Upack", ".ByDwing"] },
        SimpleSig { name: "RLPack", patterns: &[".RLPack"] },
    ];
    for p in &simple_packers {
        let matched = match_sections(p.patterns);
        if !matched.is_empty() {
            let mut score = if matched.len() >= 2 { 0.65f32 } else { 0.50 };
            corroboration_bonus(&mut score);
            return Some(PackerInfo {
                name: p.name.into(),
                confidence: score.min(1.0),
                evidence: matched.iter().map(|s| format!("section: {}", s)).collect(),
            });
        }
    }

    // .packed alone is ambiguous — only report with strong corroboration
    if has_section(".packed") {
        let mut score = 0.25f32;
        corroboration_bonus(&mut score);
        if score >= 0.50 {
            return Some(PackerInfo {
                name: "Unknown Packer".into(),
                confidence: score.min(1.0),
                evidence: vec!["section: .packed (generic)".into()],
            });
        }
    }

    None
}

fn build_fingerprint(
    dotnet: &Option<DotNetInfo>,
    go: &Option<GoInfo>,
    debug: &Option<DebugInfo>,
    rich_header: &Option<RichHeaderInfo>,
    optional_header: &Option<OptionalHeader>,
    imports: &Option<Vec<ImportEntry>>,
    packer: Option<PackerInfo>,
) -> Option<BuildFingerprint> {
    // Determine compiler
    let mut fp = if let Some(dn) = dotnet {
        BuildFingerprint {
            compiler: ".NET".into(),
            compiler_version: Some(dn.runtime_version.clone()),
            is_managed: true,
            packer: None,
            confidence: 0.99,
            evidence: vec!["CLR header present".into()],
        }
    } else if let Some(go) = go {
        BuildFingerprint {
            compiler: "Go".into(),
            compiler_version: None,
            is_managed: false,
            packer: None,
            confidence: go.confidence,
            evidence: go.markers.clone(),
        }
    } else if let Some(pdb) = debug.as_ref().and_then(|dbg| {
        dbg.entries.iter().find_map(|e| {
            let p = e.pdb_path.as_ref()?;
            let lower = p.to_ascii_lowercase();
            if lower.contains("\\target\\debug\\") || lower.contains("\\target\\release\\")
                || lower.contains("/target/debug/") || lower.contains("/target/release/") {
                Some(p.clone())
            } else {
                None
            }
        })
    }) {
        BuildFingerprint {
            compiler: "Rust".into(),
            compiler_version: None,
            is_managed: false,
            packer: None,
            confidence: 0.75,
            evidence: vec![format!("Cargo build path in PDB: {}", pdb)],
        }
    } else if let Some(rich) = rich_header {
        if !rich.entries.is_empty() {
            let detail = rich.entries.iter()
                .filter(|e| e.count > 0)
                .filter_map(|e| e.description.as_deref())
                .find(|d| d.contains("[LNK]"))
                .map(|d| d.to_string());
            BuildFingerprint {
                compiler: "MSVC".into(),
                compiler_version: detail,
                is_managed: false,
                packer: None,
                confidence: 0.85,
                evidence: vec!["Rich Header present".into()],
            }
        } else {
            return packer.map(|pk| BuildFingerprint {
                compiler: "Unknown".into(), compiler_version: None,
                is_managed: false, packer: Some(pk), confidence: 0.3,
                evidence: vec!["Packer detected".into()],
            });
        }
    } else if rich_header.is_none() && imports.as_ref().is_some_and(|imps| {
        imps.iter().any(|i| {
            let dll = i.dll.to_ascii_lowercase();
            dll.contains("libgcc") || dll.contains("libstdc++") || dll == "msvcrt.dll"
        })
    }) {
        BuildFingerprint {
            compiler: "MinGW".into(),
            compiler_version: None,
            is_managed: false,
            packer: None,
            confidence: 0.6,
            evidence: vec!["No Rich Header + MinGW-style imports".into()],
        }
    } else if let Some(opt) = optional_header {
        if opt.major_linker_version > 0 {
            BuildFingerprint {
                compiler: "Unknown".into(),
                compiler_version: Some(format!("Linker {}.{}", opt.major_linker_version, opt.minor_linker_version)),
                is_managed: false,
                packer: None,
                confidence: 0.3,
                evidence: vec![format!("Linker version {}.{}", opt.major_linker_version, opt.minor_linker_version)],
            }
        } else {
            return packer.map(|pk| BuildFingerprint {
                compiler: "Unknown".into(), compiler_version: None,
                is_managed: false, packer: Some(pk), confidence: 0.3,
                evidence: vec!["Packer detected".into()],
            });
        }
    } else {
        return packer.map(|pk| BuildFingerprint {
            compiler: "Unknown".into(), compiler_version: None,
            is_managed: false, packer: Some(pk), confidence: 0.3,
            evidence: vec!["Packer detected".into()],
        });
    };

    // Attach packer info to whatever compiler was detected
    fp.packer = packer;
    Some(fp)
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
        if (0x20..0x7f).contains(&byte) {
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

    // Build a set of (offset, value) from ASCII strings for O(1) dedup lookup
    let ascii_set: HashSet<(usize, String)> = strings.iter()
        .map(|e| (e.offset, e.value.clone()))
        .collect();

    // UTF-16LE strings
    if data.len() >= 2 {
        let mut current_u16 = Vec::new();
        let mut start_u16 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            let wchar = u16::from_le_bytes([data[i], data[i + 1]]);
            if (0x20..0x7f).contains(&wchar) {
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
                    if !ascii_set.contains(&(start_u16, s.clone())) {
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
            if !ascii_set.contains(&(start_u16, s.clone())) {
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
    let no_overlay = OverlayInfo { offset: 0, size: 0, present: false, classification: None };

    // The overlay starts after the last section's raw data
    let end_of_pe = pe.sections.iter()
        .filter_map(|s| s.pointer_to_raw_data.checked_add(s.size_of_raw_data))
        .map(|v| v as usize)
        .max()
        .unwrap_or(0);

    if end_of_pe >= data.len() || end_of_pe == 0 {
        return no_overlay;
    }

    // Exclude known post-section data from overlay:
    // 1. Certificate table (Data Directory 4) sits after sections but is not overlay
    // 2. COFF symbol table (PointerToSymbolTable) is legitimate PE data
    // Only trust these if they actually fall in the post-section region AND within file bounds.
    let mut known_tail_end = end_of_pe;

    // Certificate table (uses file offsets, not RVA)
    if let Some(opt) = pe.header.optional_header.as_ref() {
        if let Some(Some((_, dd))) = opt.data_directories.data_directories.get(4) {
            let cert_start = dd.virtual_address as usize;
            let cert_end = cert_start.saturating_add(dd.size as usize);
            // Only trust if cert starts at or after end_of_pe and ends within file
            if dd.virtual_address > 0 && dd.size > 0
                && cert_start >= end_of_pe && cert_end <= data.len() {
                if cert_end > known_tail_end {
                    known_tail_end = cert_end;
                }
            }
        }
    }

    // COFF symbol table + string table
    let sym_ptr = pe.header.coff_header.pointer_to_symbol_table as usize;
    let sym_count = pe.header.coff_header.number_of_symbol_table as usize;
    if sym_ptr > 0 && sym_count > 0 {
        let sym_end = sym_ptr.saturating_add(sym_count.saturating_mul(18));
        // Only trust if symbol table starts at or after end_of_pe and within file
        if sym_ptr >= end_of_pe && sym_end <= data.len() {
            let strtab_end = if sym_end + 4 <= data.len() {
                let strtab_size = read_u32_le(data, sym_end) as usize;
                sym_end.saturating_add(strtab_size).min(data.len())
            } else {
                sym_end
            };
            if strtab_end > known_tail_end {
                known_tail_end = strtab_end;
            }
        }
    }

    if known_tail_end >= data.len() {
        return no_overlay;
    }

    // Real overlay starts after all known PE structures
    let overlay_start = known_tail_end.max(end_of_pe);
    if overlay_start >= data.len() {
        return no_overlay;
    }

    OverlayInfo {
        offset: overlay_start,
        size: data.len() - overlay_start,
        present: true,
        classification: None,
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

#[allow(clippy::too_many_arguments)]
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

        if let Some(child_key) = read_utf16_string_until_null(data, pos + 6)
            && child_key == "StringFileInfo" {
                let si_strings = parse_string_file_info(data, pos);
                string_info.extend(si_strings);
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

    // Rich Hash: MD5 of the XOR-decoded data from DanS to Rich marker (YARA/VT compatible)
    let rich_hash = {
        let mut clear = Vec::with_capacity(encoded_end - encoded_start);
        let mut i = encoded_start;
        while i + 4 <= encoded_end {
            let dword = read_u32_le(data, i) ^ xor_key;
            clear.extend_from_slice(&dword.to_le_bytes());
            i += 4;
        }
        let digest = Md5::digest(&clear);
        Some(format!("{:x}", digest))
    };

    // Checksum verification: recompute XOR key from DOS header + Rich entries
    let checksum_valid = {
        let mut checksum = encoded_start as u32; // DanS offset
        // Sum rotated bytes of DOS header (0..encoded_start), skipping e_lfanew (0x3C..0x40)
        for i in 0..encoded_start {
            if (0x3C..0x40).contains(&i) {
                continue;
            }
            if i < data.len() {
                checksum = checksum.wrapping_add((data[i] as u32).rotate_left(i as u32));
            }
        }
        // Sum rotated comp_ids from Rich entries
        let entries_start_ck = encoded_start + 16;
        let mut off = entries_start_ck;
        while off + 8 <= encoded_end {
            let comp_id = read_u32_le(data, off) ^ xor_key;
            let count = read_u32_le(data, off + 4) ^ xor_key;
            checksum = checksum.wrapping_add(comp_id.rotate_left(count & 0x1F));
            off += 8;
        }
        checksum == xor_key
    };

    // Skip DanS + 3 padding dwords (16 bytes total)
    let entries_start = encoded_start + 16;
    if entries_start >= encoded_end {
        return Some(RichHeaderInfo {
            xor_key: format!("{:#010x}", xor_key),
            xor_key_raw: xor_key,
            rich_hash,
            checksum_valid,
            entries: Vec::new(),
        });
    }

    let mut entries = Vec::new();
    let mut off = entries_start;
    while off + 8 <= encoded_end {
        let comp_id_raw = read_u32_le(data, off) ^ xor_key;
        let count = read_u32_le(data, off + 4) ^ xor_key;
        let build_id = (comp_id_raw & 0xFFFF) as u16;
        let prod_id = ((comp_id_raw >> 16) & 0xFFFF) as u16;
        let description = Some(crate::rich_db::lookup_rich_entry(prod_id, build_id));
        entries.push(RichEntry {
            comp_id: format!("{:#010x}", comp_id_raw),
            prod_id,
            build_id,
            count,
            description,
        });
        off += 8;
    }

    Some(RichHeaderInfo {
        xor_key: format!("{:#010x}", xor_key),
        xor_key_raw: xor_key,
        rich_hash,
        checksum_valid,
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
