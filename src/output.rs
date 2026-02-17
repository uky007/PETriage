use crate::analysis::AnalysisResult;

pub fn format_json(result: &AnalysisResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|e| format!("JSON error: {}", e))
}

pub fn format_text(result: &AnalysisResult) -> String {
    let mut out = String::new();

    if let Some(ref info) = result.file_info {
        out.push_str(&format!("=== File Info ===\n"));
        out.push_str(&format!("  File:    {}\n", info.name));
        out.push_str(&format!("  Size:    {} bytes ({:.2} KB)\n", info.size, info.size as f64 / 1024.0));
        out.push_str(&format!("  Type:    {}\n", info.pe_type));
        out.push('\n');
    }

    if let Some(ref hashes) = result.hashes {
        out.push_str(&format!("=== Hashes ===\n"));
        out.push_str(&format!("  MD5:     {}\n", hashes.md5));
        out.push_str(&format!("  SHA1:    {}\n", hashes.sha1));
        out.push_str(&format!("  SHA256:  {}\n", hashes.sha256));
        out.push('\n');
    }

    if let Some(ref dos) = result.dos_header {
        out.push_str(&format!("=== DOS Header ===\n"));
        out.push_str(&format!("  e_magic:   {}\n", dos.e_magic));
        out.push_str(&format!("  e_lfanew:  {:#x}\n", dos.e_lfanew));
        out.push('\n');
    }

    if let Some(ref coff) = result.coff_header {
        out.push_str(&format!("=== COFF Header ===\n"));
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
        out.push_str(&format!("=== Optional Header ===\n"));
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
            out.push_str(&format!("\n  Data Directories:\n"));
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
                out.push_str(&format!("    - {}\n", func));
            }
        }
        out.push('\n');
    }

    if let Some(ref exports) = result.exports {
        if !exports.is_empty() {
            out.push_str(&format!("=== Exports ({}) ===\n", exports.len()));
            out.push_str(&format!("  {:<6} {:<12} {}\n", "Ord", "RVA", "Name"));
            out.push_str(&format!("  {:-<6} {:-<12} {:-<30}\n", "", "", ""));
            for exp in exports {
                out.push_str(&format!("  {:<6} {:#012x} {}\n", exp.ordinal, exp.rva, exp.name));
            }
            out.push('\n');
        }
    }

    if let Some(ref overlay) = result.overlay {
        out.push_str(&format!("=== Overlay ===\n"));
        if overlay.present {
            out.push_str(&format!("  Present:  Yes\n"));
            out.push_str(&format!("  Offset:   {:#x}\n", overlay.offset));
            out.push_str(&format!("  Size:     {} bytes ({:.2} KB)\n", overlay.size, overlay.size as f64 / 1024.0));
        } else {
            out.push_str(&format!("  Present:  No\n"));
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
