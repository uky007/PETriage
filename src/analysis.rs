use std::collections::HashMap;

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
    pub suspicious_summary: Option<SuspiciousSummary>,
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
}

#[derive(Clone, Debug, Serialize)]
pub struct OverlayInfo {
    pub offset: usize,
    pub size: usize,
    pub present: bool,
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

    let hashes = if opts.show_hashes {
        Some(compute_hashes(data))
    } else {
        None
    };

    let overlay = if opts.show_overlay {
        Some(detect_overlay(data, pe))
    } else {
        None
    };

    let suspicious_summary = imports.as_ref().map(|imp| build_suspicious_summary(imp));

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
        suspicious_summary,
    }
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
    pe.exports.iter().enumerate().map(|(i, exp)| {
        ExportEntry {
            name: exp.name.unwrap_or("(ordinal only)").to_string(),
            ordinal: i,
            rva: exp.rva,
        }
    }).collect()
}

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
                    }
                }
                current_u16.clear();
            }
            i += 2;
        }
        if current_u16.len() >= min_len {
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
    }
}

fn detect_overlay(data: &[u8], pe: &PE) -> OverlayInfo {
    // The overlay starts after the last section's raw data
    let end_of_pe = pe.sections.iter()
        .map(|s| (s.pointer_to_raw_data + s.size_of_raw_data) as usize)
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
