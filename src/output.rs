use colored::Colorize;

use crate::analysis::AnalysisResult;

pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let art = format!(
        r#"
  {}
  {}
  {}  {}
  {}
"#,
        "╔═╗╔═╗╔╦╗╦═╗╦╔═╗╔═╗╔═╗".cyan().bold(),
        "╠═╝║╣  ║ ╠╦╝║╠═╣║ ╦║╣ ".cyan().bold(),
        "╩  ╚═╝ ╩ ╩╚═╩╩ ╩╚═╝╚═╝".cyan().bold(),
        format!("v{version}").white().dimmed(),
        "PE file surface analysis".white().dimmed(),
    );
    eprint!("{art}");
}

pub fn format_json(result: &AnalysisResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|e| format!("JSON error: {}", e))
}

pub fn format_ndjson(result: &AnalysisResult) -> String {
    let mut s = serde_json::to_string(result).unwrap_or_else(|e| format!("{{\"error\":\"JSON error: {}\"}}", e));
    s.push('\n');
    s
}

pub fn format_text(result: &AnalysisResult) -> String {
    let mut out = String::new();

    if let Some(ref info) = result.file_info {
        out.push_str("=== File Info ===\n");
        out.push_str(&format!("  File:    {}\n", info.name));
        out.push_str(&format!("  Size:    {} bytes ({:.2} KB)\n", info.size, info.size as f64 / 1024.0));
        out.push_str(&format!("  Type:    {}\n", info.pe_type));
        out.push('\n');
    }

    if let Some(ref fp) = result.build_fingerprint {
        out.push_str("=== Build Fingerprint ===\n");
        out.push_str(&format!("  Compiler:    {} (confidence: {:.0}%)\n", fp.compiler, fp.confidence * 100.0));
        if let Some(ref ver) = fp.compiler_version {
            out.push_str(&format!("  Version:     {}\n", ver));
        }
        if fp.is_managed {
            out.push_str("  Managed:     Yes\n");
        }
        if let Some(ref pk) = fp.packer {
            out.push_str(&format!("  Packer:      {} (confidence: {:.0}%)\n", pk.name, pk.confidence * 100.0));
            for ev in &pk.evidence {
                out.push_str(&format!("               {}\n", ev));
            }
        }
        for ev in &fp.evidence {
            out.push_str(&format!("  Evidence:    {}\n", ev));
        }
        out.push('\n');
    }

    // OPSEC Analysis section (structured findings)
    if let Some(ref opsec) = result.opsec {
        out.push_str(&format!("{}\n", "=== OPSEC Analysis ===".yellow().bold()));
        let sev_str = match opsec.summary.max_severity.as_str() {
            "critical" => format!("{}", "CRITICAL".red().bold()),
            "warning" => format!("{}", "WARNING".yellow()),
            "info" => format!("{}", "INFO".cyan()),
            _ => "NONE".to_string(),
        };
        out.push_str(&format!("  Findings: {}  Max Severity: {}\n",
            opsec.summary.finding_count, sev_str));
        if !opsec.summary.types.is_empty() {
            out.push_str("  Types:");
            for (t, c) in &opsec.summary.types {
                out.push_str(&format!(" {}={}", t, c));
            }
            out.push('\n');
        }
        out.push('\n');
        for finding in &opsec.findings {
            let tag = match finding.severity.as_str() {
                "critical" => format!("{}", "[CRITICAL]".red().bold()),
                "warning" => format!("{}", "[WARNING]".yellow()),
                "info" => format!("{}", "[INFO]".cyan()),
                _ => String::new(),
            };
            out.push_str(&format!("  {} {} {}: {}\n",
                tag,
                format!("[{}]", finding.id).dimmed(),
                finding.finding_type,
                finding.description));
        }
        out.push('\n');
    } else if let Some(ref debug) = result.debug {
        // Fallback: show PDB paths even without full OPSEC findings
        let pdb_paths: Vec<&str> = debug.entries.iter()
            .filter_map(|e| e.pdb_path.as_deref())
            .collect();
        if !pdb_paths.is_empty() {
            out.push_str(&format!("{}\n", "=== OPSEC: PDB Path ===".yellow().bold()));
            for pdb in &pdb_paths {
                out.push_str(&format!("  {}\n", pdb.yellow()));
            }
            out.push('\n');
        }
    }

    if let Some(ref hashes) = result.hashes {
        out.push_str("=== Hashes ===\n");
        out.push_str(&format!("  MD5:     {}\n", hashes.md5));
        out.push_str(&format!("  SHA1:    {}\n", hashes.sha1));
        out.push_str(&format!("  SHA256:  {}\n", hashes.sha256));
        if let Some(ref imphash) = hashes.imphash {
            out.push_str(&format!("  Imphash: {}\n", imphash));
        }
        out.push('\n');
    }

    if let Some(ref dos) = result.dos_header {
        out.push_str("=== DOS Header ===\n");
        out.push_str(&format!("  e_magic:   {}\n", dos.e_magic));
        out.push_str(&format!("  e_lfanew:  {:#x}\n", dos.e_lfanew));
        out.push('\n');
    }

    if let Some(ref coff) = result.coff_header {
        out.push_str("=== COFF Header ===\n");
        out.push_str(&format!("  Machine:              {} ({:#06x})\n", coff.machine, coff.machine_raw));
        out.push_str(&format!("  NumberOfSections:     {}\n", coff.number_of_sections));
        out.push_str(&format!("  TimeDateStamp:        {:#010x} ({})\n", coff.time_date_stamp, coff.time_date_stamp_str));
        out.push_str(&format!("  PointerToSymbolTable: {:#x}\n", coff.pointer_to_symbol_table));
        out.push_str(&format!("  NumberOfSymbols:      {}\n", coff.number_of_symbols));
        out.push_str(&format!("  SizeOfOptionalHeader: {:#x}\n", coff.size_of_optional_header));
        out.push_str(&format!("  Characteristics:      {:#06x}\n", coff.characteristics));
        for c in &coff.characteristics_str {
            out.push_str(&format!("                        - {}\n", c));
        }
        out.push('\n');
    }

    if let Some(ref opt) = result.optional_header {
        out.push_str("=== Optional Header ===\n");
        out.push_str(&format!("  Magic:                 {}\n", opt.magic));
        out.push_str(&format!("  LinkerVersion:         {}.{}\n", opt.major_linker_version, opt.minor_linker_version));
        out.push_str(&format!("  SizeOfCode:            {:#x}\n", opt.size_of_code));
        out.push_str(&format!("  AddressOfEntryPoint:   {:#x}\n", opt.address_of_entry_point));
        out.push_str(&format!("  ImageBase:             {:#x}\n", opt.image_base));
        out.push_str(&format!("  SectionAlignment:      {:#x}\n", opt.section_alignment));
        out.push_str(&format!("  FileAlignment:         {:#x}\n", opt.file_alignment));
        out.push_str(&format!("  OSVersion:             {}.{}\n", opt.major_os_version, opt.minor_os_version));
        out.push_str(&format!("  SizeOfImage:           {:#x}\n", opt.size_of_image));
        out.push_str(&format!("  SizeOfHeaders:         {:#x}\n", opt.size_of_headers));
        out.push_str(&format!("  CheckSum:              {:#x}\n", opt.checksum));
        out.push_str(&format!("  Subsystem:             {}\n", opt.subsystem));
        out.push_str(&format!("  DllCharacteristics:    {:#06x}\n", opt.dll_characteristics));
        for c in &opt.dll_characteristics_str {
            out.push_str(&format!("                         - {}\n", c));
        }
        out.push_str(&format!("  NumberOfRvaAndSizes:   {}\n", opt.number_of_rva_and_sizes));

        if !opt.data_directories.is_empty() {
            out.push_str("\n  Data Directories:\n");
            out.push_str(&format!("  {:<28} {:>12} {:>12}\n", "Name", "RVA", "Size"));
            out.push_str(&format!("  {:-<28} {:-<12} {:-<12}\n", "", "", ""));
            for dd in &opt.data_directories {
                out.push_str(&format!("  {:<28} {:#012x} {:#012x}\n", dd.name, dd.virtual_address, dd.size));
            }
        }
        out.push('\n');
    }

    if let Some(ref sections) = result.sections {
        out.push_str(&format!("=== Sections ({}) ===\n", sections.len()));
        out.push_str(&format!("  {:<10} {:>10} {:>12} {:>10} {:>12} {:>8} {}\n",
            "Name", "VirtSize", "VirtAddr", "RawSize", "RawAddr", "Entropy", "Characteristics"));
        out.push_str(&format!("  {:-<10} {:-<10} {:-<12} {:-<10} {:-<12} {:-<8} {:-<30}\n",
            "", "", "", "", "", "", ""));
        for sec in sections {
            out.push_str(&format!("  {:<10} {:#010x} {:#012x} {:#010x} {:#012x} {:>7.4} {}\n",
                sec.name,
                sec.virtual_size,
                sec.virtual_address,
                sec.raw_size,
                sec.raw_address,
                sec.entropy,
                sec.characteristics_str.join(" | ")));
        }
        out.push('\n');
    }

    if let Some(ref imports) = result.imports {
        let total_funcs: usize = imports.iter().map(|i| i.functions.len()).sum();
        out.push_str(&format!("=== Imports ({} DLLs, {} functions) ===\n", imports.len(), total_funcs));
        for imp in imports {
            out.push_str(&format!("  {} ({} functions)\n", imp.dll, imp.functions.len()));
            for func in &imp.functions {
                if let Some(ref risk) = func.risk {
                    let tag = match risk.severity.as_str() {
                        "high" => format!("{}", "[HIGH]".red().bold()),
                        "medium" => format!("{}", "[MED]".yellow()),
                        "low" => format!("{}", "[LOW]".cyan()),
                        _ => String::new(),
                    };
                    out.push_str(&format!("    - {} {} {}\n", func.name, tag, risk.category.dimmed()));
                } else {
                    out.push_str(&format!("    - {}\n", func.name));
                }
            }
        }
        out.push('\n');
    }

    if let Some(ref summary) = result.suspicious_summary
        && summary.total_suspicious > 0 {
            out.push_str("=== Suspicious API Summary ===\n");
            out.push_str(&format!("  Total suspicious APIs: {}\n", summary.total_suspicious));
            out.push_str(&format!("  {} {} {}\n",
                format!("HIGH: {}", summary.high_count).red().bold(),
                format!("MEDIUM: {}", summary.medium_count).yellow(),
                format!("LOW: {}", summary.low_count).cyan(),
            ));
            out.push_str(&format!("\n  {:<24} {:>5}\n", "Category", "Count"));
            out.push_str(&format!("  {:-<24} {:-<5}\n", "", ""));
            for cat in &summary.categories {
                out.push_str(&format!("  {:<24} {:>5}\n", cat.category, cat.count));
            }
            out.push('\n');
        }

    if let Some(ref anomalies) = result.anomalies
        && !anomalies.is_empty() {
            out.push_str("=== Anomaly Detection ===\n");
            let critical = anomalies.iter().filter(|a| a.severity == "critical").count();
            let warning = anomalies.iter().filter(|a| a.severity == "warning").count();
            let info_count = anomalies.iter().filter(|a| a.severity == "info").count();
            out.push_str(&format!("  {} {} {}\n",
                format!("CRITICAL: {}", critical).red().bold(),
                format!("WARNING: {}", warning).yellow(),
                format!("INFO: {}", info_count).cyan(),
            ));
            out.push('\n');
            for anomaly in anomalies {
                let tag = match anomaly.severity.as_str() {
                    "critical" => format!("{}", "[CRITICAL]".red().bold()),
                    "warning" => format!("{}", "[WARNING]".yellow()),
                    "info" => format!("{}", "[INFO]".cyan()),
                    _ => String::new(),
                };
                out.push_str(&format!("  {} {} {}: {}\n", tag, format!("[{}]", anomaly.rule_id).dimmed(), anomaly.category, anomaly.description));
            }
            out.push('\n');
        }

    if let Some(ref exports) = result.exports
        && !exports.is_empty() {
            out.push_str(&format!("=== Exports ({}) ===\n", exports.len()));
            out.push_str(&format!("  {:<6} {:<12} {}\n", "Ord", "RVA", "Name"));
            out.push_str(&format!("  {:-<6} {:-<12} {:-<30}\n", "", "", ""));
            for exp in exports {
                out.push_str(&format!("  {:<6} {:#012x} {}\n", exp.ordinal, exp.rva, exp.name));
            }
            out.push('\n');
        }

    if let Some(ref overlay) = result.overlay {
        out.push_str("=== Overlay ===\n");
        if overlay.present {
            out.push_str("  Present:  Yes\n");
            out.push_str(&format!("  Offset:   {:#x}\n", overlay.offset));
            out.push_str(&format!("  Size:     {} bytes ({:.2} KB)\n", overlay.size, overlay.size as f64 / 1024.0));
            if let Some(ref classes) = overlay.classification {
                for c in classes {
                    out.push_str(&format!("  Format:   {} (confidence: {:.0}%)\n", c.format, c.confidence * 100.0));
                }
            }
        } else {
            out.push_str("  Present:  No\n");
        }
        out.push('\n');
    }

    if let Some(ref rich) = result.rich_header {
        out.push_str("=== Rich Header ===\n");
        out.push_str(&format!("  XOR Key:    {}\n", rich.xor_key));
        if let Some(ref hash) = rich.rich_hash {
            out.push_str(&format!("  Rich Hash:  {}\n", hash));
        }
        out.push_str(&format!("  Checksum:   {}\n",
            if rich.checksum_valid { "Valid" } else { "Invalid" }));
        if !rich.entries.is_empty() {
            out.push_str(&format!("\n  {:<12} {:>6}  {:>7}  {:>7}  {}\n",
                "CompID", "ProdID", "BuildID", "Count", "Description"));
            out.push_str(&format!("  {:-<12} {:-<6}  {:-<7}  {:-<7}  {:-<30}\n",
                "", "", "", "", ""));
            for e in &rich.entries {
                out.push_str(&format!("  {:<12} {:>6}  {:>7}  {:>7}  {}\n",
                    e.comp_id, e.prod_id, e.build_id, e.count,
                    e.description.as_deref().unwrap_or("")));
            }
        }
        out.push('\n');
    }

    if let Some(ref tls) = result.tls {
        out.push_str("=== TLS Directory ===\n");
        out.push_str(&format!("  RawDataStart:       {}\n", tls.raw_data_start));
        out.push_str(&format!("  RawDataEnd:         {}\n", tls.raw_data_end));
        out.push_str(&format!("  AddressOfIndex:     {}\n", tls.address_of_index));
        out.push_str(&format!("  AddressOfCallBacks: {}\n", tls.address_of_callbacks));
        out.push_str(&format!("  SizeOfZeroFill:     {:#x}\n", tls.size_of_zero_fill));
        out.push_str(&format!("  Characteristics:    {:#x}\n", tls.characteristics));
        out.push_str(&format!("  Callbacks:          {}\n", tls.callback_count));
        for (i, cb) in tls.callbacks.iter().enumerate() {
            out.push_str(&format!("    [{}] {}\n", i, cb));
        }
        out.push('\n');
    }

    if let Some(ref debug) = result.debug {
        out.push_str(&format!("=== Debug Directory ({} entries) ===\n", debug.entries.len()));
        for (i, entry) in debug.entries.iter().enumerate() {
            out.push_str(&format!("  [{}] Type: {} ({})\n", i, entry.debug_type, entry.debug_type_raw));
            out.push_str(&format!("      Timestamp:       {:#010x}\n", entry.timestamp));
            out.push_str(&format!("      Version:         {}.{}\n", entry.major_version, entry.minor_version));
            out.push_str(&format!("      SizeOfData:      {:#x}\n", entry.size_of_data));
            out.push_str(&format!("      PointerToRawData:{:#x}\n", entry.pointer_to_raw_data));
            if let Some(ref guid) = entry.guid {
                out.push_str(&format!("      GUID:            {}\n", guid));
            }
            if let Some(age) = entry.age {
                out.push_str(&format!("      Age:             {}\n", age));
            }
            if let Some(ref pdb) = entry.pdb_path {
                out.push_str(&format!("      PDB:             {}\n", pdb.yellow().bold()));
            }
        }
        out.push('\n');
    }

    if let Some(ref dn) = result.dotnet {
        out.push_str("=== .NET Metadata ===\n");
        out.push_str(&format!("  Runtime:     {}\n", dn.runtime_version));
        if let Some(ref name) = dn.assembly_name {
            out.push_str(&format!("  Assembly:    {}\n", name));
        }
        if let Some(ref ver) = dn.assembly_version {
            out.push_str(&format!("  Version:     {}\n", ver));
        }
        if !dn.flags.is_empty() {
            out.push_str(&format!("  Flags:       {}\n", dn.flags.join(", ")));
        }
        if !dn.references.is_empty() {
            out.push_str(&format!("  References ({}):\n", dn.references.len()));
            for r in &dn.references {
                out.push_str(&format!("    - {}\n", r));
            }
        }
        out.push('\n');
    }

    if let Some(ref go) = result.go {
        out.push_str("=== Go Build Info ===\n");
        if let Some(ref bid) = go.build_id {
            out.push_str(&format!("  Build ID:    {}\n", bid));
        }
        out.push_str(&format!("  Confidence:  {:.0}%\n", go.confidence * 100.0));
        out.push_str(&format!("  Markers:     {}\n", go.markers.join(", ")));
        out.push('\n');
    }

    if let Some(ref resources) = result.resources {
        out.push_str(&format!("=== Resources ({} entries) ===\n", resources.total_entries));

        if let Some(ref ver) = resources.version_info {
            out.push_str("  Version Info:\n");
            if let Some(ref fixed) = ver.fixed {
                out.push_str(&format!("    FileVersion:    {}\n", fixed.file_version));
                out.push_str(&format!("    ProductVersion: {}\n", fixed.product_version));
                out.push_str(&format!("    FileType:       {} ({})\n", fixed.file_type_str, fixed.file_type));
                out.push_str(&format!("    FileOS:         {:#x}\n", fixed.file_os));
                out.push_str(&format!("    FileFlags:      {:#x}\n", fixed.file_flags));
            }
            if !ver.string_info.is_empty() {
                out.push_str("    String Info:\n");
                for s in &ver.string_info {
                    out.push_str(&format!("      {:<24} {}\n", format!("{}:", s.key), s.value));
                }
            }
            out.push('\n');
        }

        if let Some(ref manifest) = resources.manifest {
            out.push_str("  Manifest:\n");
            for line in manifest.lines() {
                out.push_str(&format!("    {}\n", line));
            }
            out.push('\n');
        }

        if !resources.entries.is_empty() {
            out.push_str(&format!("  {:<20} {:<16} {:<10} {:>8} {:>12}\n",
                "Type", "Name", "Language", "Size", "RVA"));
            out.push_str(&format!("  {:-<20} {:-<16} {:-<10} {:-<8} {:-<12}\n",
                "", "", "", "", ""));
            for e in &resources.entries {
                out.push_str(&format!("  {:<20} {:<16} {:<10} {:>8} {:#012x}\n",
                    e.resource_type, e.name, e.language_str, e.size, e.rva));
            }
        }
        out.push('\n');
    }

    if let Some(ref auth) = result.authenticode {
        out.push_str("=== Authenticode / Code Signing ===\n");
        out.push_str(&format!("  Signed:          {}\n", if auth.signed { "Yes" } else { "No" }));
        out.push_str(&format!("  Parse OK:        {}\n", if auth.parse_ok { "Yes" } else { "No" }));
        out.push_str(&format!("  Trust Verified:  {}\n", if auth.trust_verified { "Yes" } else { "No (not implemented)" }));

        if let Some(ref wc) = auth.win_certificate {
            out.push_str("\n  WIN_CERTIFICATE:\n");
            out.push_str(&format!("    Length:   {} bytes\n", wc.length));
            out.push_str(&format!("    Revision: {} ({:#06x})\n", wc.revision, wc.revision_raw));
            out.push_str(&format!("    Type:     {} ({:#06x})\n", wc.certificate_type, wc.certificate_type_raw));
        }

        if let Some(ref signer) = auth.signer {
            out.push_str("\n  Signer:\n");
            out.push_str(&format!("    Subject:    {}\n", signer.subject));
            out.push_str(&format!("    Issuer:     {}\n", signer.issuer));
            out.push_str(&format!("    Serial:     {}\n", signer.serial));
            out.push_str(&format!("    Not Before: {}\n", signer.not_before));
            out.push_str(&format!("    Not After:  {}\n", signer.not_after));
            out.push_str(&format!("    Thumbprint: {}\n", signer.thumbprint_sha1));
        }

        if !auth.certificates.is_empty() {
            out.push_str(&format!("\n  Certificate Chain ({} certificates):\n", auth.certificates.len()));
            for (i, cert) in auth.certificates.iter().enumerate() {
                let signer_tag = if cert.is_signer { " (signer)" } else { "" };
                out.push_str(&format!("    [{}]{}\n", i, signer_tag));
                out.push_str(&format!("      Subject:    {}\n", cert.subject));
                out.push_str(&format!("      Issuer:     {}\n", cert.issuer));
                out.push_str(&format!("      Serial:     {}\n", cert.serial));
                out.push_str(&format!("      Not Before: {}\n", cert.not_before));
                out.push_str(&format!("      Not After:  {}\n", cert.not_after));
                out.push_str(&format!("      Thumbprint: {}\n", cert.thumbprint_sha1));
            }
        }

        if !auth.warnings.is_empty() {
            out.push_str("\n  Warnings:\n");
            for w in &auth.warnings {
                out.push_str(&format!("    ! {}\n", w));
            }
        }
        out.push('\n');
    }

    if let Some(ref strings) = result.strings {
        out.push_str(&format!("=== Strings ({}) ===\n", strings.len()));
        for s in strings {
            out.push_str(&format!("  {:#010x} [{}] {}\n", s.offset, s.encoding, s.value));
        }
        out.push('\n');
    }

    out
}
