use egui::{Color32, Ui};

use crate::analysis::{self, AnalysisResult};
use super::editor::EditorState;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const ACCENT_DIM: Color32 = Color32::from_rgb(0, 120, 150);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const FLAG_COLOR: Color32 = Color32::from_rgb(180, 160, 90);
const MODIFIED_BG: Color32 = Color32::from_rgb(80, 60, 0);

pub fn show(ui: &mut Ui, result: &AnalysisResult, data: &[u8], editor: &mut EditorState) {
    let layout = pe_layout(data);

    // Save / Reset bar (show at top when dirty)
    if editor.dirty {
        ui.horizontal(|ui| {
            ui.colored_label(Color32::from_rgb(255, 200, 50), egui::RichText::new(
                format!("{} pending edit(s)", editor.edits.len())
            ).strong());
            ui.add_space(16.0);
            let save_btn = egui::Button::new(
                egui::RichText::new("Save As...").color(Color32::WHITE).strong(),
            )
            .fill(Color32::from_rgb(0, 100, 140))
            .stroke(egui::Stroke::new(1.0, ACCENT))
            .corner_radius(egui::CornerRadius::same(4));
            if ui.add(save_btn).clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("PE files", &["exe", "dll", "sys", "ocx", "scr"])
                    .add_filter("All files", &["*"])
                    .save_file()
                {
                    let mut patched = data.to_vec();
                    editor.apply_to(&mut patched);
                    match std::fs::write(&path, &patched) {
                        Ok(()) => {
                            editor.save_message = Some(format!("Saved to {}", path.display()));
                            editor.edits.clear();
                            editor.dirty = false;
                        }
                        Err(e) => {
                            editor.save_message = Some(format!("Save failed: {}", e));
                        }
                    }
                }
            let reset_btn = egui::Button::new(
                egui::RichText::new("Reset").color(Color32::WHITE),
            )
            .fill(Color32::from_rgb(80, 30, 30))
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(160, 60, 60)))
            .corner_radius(egui::CornerRadius::same(4));
            if ui.add(reset_btn).clicked() {
                editor.reset();
            }
        });
        ui.add_space(4.0);
    }
    if let Some(ref msg) = editor.save_message.clone() {
        ui.colored_label(Color32::from_rgb(80, 200, 120), msg);
        ui.add_space(4.0);
    }

    // --- DOS Header (read-only) ---
    if let Some(ref dos) = result.dos_header {
        egui::CollapsingHeader::new(
            egui::RichText::new("DOS Header").color(ACCENT).size(14.0),
        )
        .default_open(true)
        .show(ui, |ui| {
            egui::Grid::new("dos_header_grid")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.colored_label(LABEL, "e_magic:");
                    ui.monospace(&dos.e_magic);
                    ui.end_row();

                    ui.colored_label(LABEL, "e_lfanew:");
                    ui.monospace(format!("{:#x}", dos.e_lfanew));
                    ui.end_row();
                });
        });
    }

    // --- COFF Header (editable fields) ---
    if let Some(ref coff) = result.coff_header {
        ui.add_space(4.0);
        egui::CollapsingHeader::new(
            egui::RichText::new("COFF Header").color(ACCENT).size(14.0),
        )
        .default_open(true)
        .show(ui, |ui| {
            if let Some((_, _, _, _, coff_offset)) = layout {
                egui::Grid::new("coff_header_grid")
                    .num_columns(3)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        // Machine — editable dropdown
                        let machine_offset = coff_offset;
                        let machine_original = read_u16_le(data, machine_offset) as u64;
                        let machine_current = editor.get_current_u16(data, machine_offset);
                        let machine_modified = editor.find_edit(machine_offset).is_some();
                        ui.colored_label(if machine_modified { Color32::from_rgb(255, 200, 50) } else { LABEL }, "Machine:");
                        let machine_items: &[(&str, u16)] = &[
                            ("IMAGE_FILE_MACHINE_I386 (x86)", 0x014C),
                            ("IMAGE_FILE_MACHINE_AMD64 (x64)", 0x8664),
                            ("IMAGE_FILE_MACHINE_ARM", 0x01C0),
                            ("IMAGE_FILE_MACHINE_ARMNT (ARMv7)", 0x01C4),
                            ("IMAGE_FILE_MACHINE_ARM64 (AArch64)", 0xAA64),
                            ("IMAGE_FILE_MACHINE_IA64 (Itanium)", 0x0200),
                        ];
                        let current_label = machine_items.iter()
                            .find(|(_, v)| *v == machine_current)
                            .map(|(l, _)| *l)
                            .unwrap_or("Unknown");
                        let combo_frame = if machine_modified {
                            egui::Frame::new().fill(MODIFIED_BG).corner_radius(egui::CornerRadius::same(2)).inner_margin(egui::Margin::symmetric(2, 0))
                        } else {
                            egui::Frame::NONE
                        };
                        combo_frame.show(ui, |ui| {
                            egui::ComboBox::from_id_salt("machine_combo")
                                .selected_text(format!("{} ({:#06x})", current_label, machine_current))
                                .show_ui(ui, |ui| {
                                    for (label, val) in machine_items {
                                        if ui.selectable_label(machine_current == *val, format!("{} ({:#06x})", label, val)).clicked() {
                                            editor.set_value(machine_offset, 2, machine_original, *val as u64, "Machine");
                                        }
                                    }
                                });
                        });
                        if machine_modified { ui.colored_label(FLAG_COLOR, "*"); } else { ui.label(""); }
                        ui.end_row();

                        ui.colored_label(LABEL, "NumberOfSections:");
                        ui.monospace(coff.number_of_sections.to_string());
                        ui.label("");
                        ui.end_row();

                        // TimeDateStamp — hex editor + human-readable date
                        {
                            let ts_offset = coff_offset + 4;
                            let ts_original = read_u32_le(data, ts_offset) as u64;
                            let ts_current = editor.get_current_u32(data, ts_offset);
                            let is_modified = editor.find_edit(ts_offset).is_some();
                            ui.colored_label(if is_modified { Color32::from_rgb(255, 200, 50) } else { LABEL }, "TimeDateStamp:");
                            let frame = if is_modified {
                                egui::Frame::new().fill(MODIFIED_BG).corner_radius(egui::CornerRadius::same(2)).inner_margin(egui::Margin::symmetric(2, 0))
                            } else {
                                egui::Frame::NONE
                            };
                            frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let mut val = ts_current;
                                    if ui.add(egui::DragValue::new(&mut val).range(0..=u32::MAX).hexadecimal(8, false, true)).changed() {
                                        editor.set_value(ts_offset, 4, ts_original, val as u64, "TimeDateStamp");
                                    }
                                    let ts_str = analysis::format_timestamp(ts_current);
                                    ui.colored_label(Color32::from_rgb(160, 170, 190), format!("({})", ts_str));
                                });
                            });
                            if is_modified { ui.colored_label(FLAG_COLOR, "*"); } else { ui.label(""); }
                        }
                        ui.end_row();

                        ui.colored_label(LABEL, "PointerToSymbolTable:");
                        ui.monospace(format!("{:#x}", coff.pointer_to_symbol_table));
                        ui.label("");
                        ui.end_row();

                        ui.colored_label(LABEL, "NumberOfSymbols:");
                        ui.monospace(coff.number_of_symbols.to_string());
                        ui.label("");
                        ui.end_row();

                        ui.colored_label(LABEL, "SizeOfOptionalHeader:");
                        ui.monospace(format!("{:#x}", coff.size_of_optional_header));
                        ui.label("");
                        ui.end_row();

                        edit_u16_hex(ui, data, editor, coff_offset + 18, "Characteristics");
                        ui.end_row();
                    });

                // COFF Characteristics flags
                ui.add_space(4.0);
                ui.colored_label(LABEL, "Flags:");
                let chars_offset = coff_offset + 18;
                let current_chars = editor.get_current_u16(data, chars_offset);
                let coff_flags: &[(&str, u16)] = &[
                    ("RELOCS_STRIPPED", 0x0001),
                    ("EXECUTABLE_IMAGE", 0x0002),
                    ("LARGE_ADDRESS_AWARE", 0x0020),
                    ("32BIT_MACHINE", 0x0100),
                    ("DLL", 0x2000),
                ];
                show_flag_checkboxes_u16(ui, data, editor, chars_offset, current_chars, coff_flags, "CoffChar");
            } else {
                // Fallback read-only if layout can't be parsed
                show_coff_readonly(ui, coff);
            }
        });
    }

    // --- Optional Header (editable fields) ---
    if let Some(ref opt) = result.optional_header {
        ui.add_space(4.0);
        egui::CollapsingHeader::new(
            egui::RichText::new("Optional Header").color(ACCENT).size(14.0),
        )
        .default_open(true)
        .show(ui, |ui| {
            if let Some((is_pe32plus, opt_offset, _, size_of_opt, _)) = layout {
                let opt_end = opt_offset + (size_of_opt as usize);
                let opt_valid = opt_end <= data.len() && size_of_opt >= 72;

                egui::Grid::new("opt_header_grid")
                    .num_columns(3)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        ui.colored_label(LABEL, "Magic:");
                        ui.monospace(&opt.magic);
                        ui.label("");
                        ui.end_row();

                        ui.colored_label(LABEL, "LinkerVersion:");
                        ui.monospace(format!("{}.{}", opt.major_linker_version, opt.minor_linker_version));
                        ui.label("");
                        ui.end_row();

                        ui.colored_label(LABEL, "SizeOfCode:");
                        ui.monospace(format!("{:#x}", opt.size_of_code));
                        ui.label("");
                        ui.end_row();

                        if opt_valid {
                            edit_u32_hex(ui, data, editor, opt_offset + 16, "AddressOfEntryPoint");
                            ui.end_row();

                            if is_pe32plus {
                                edit_u64_hex(ui, data, editor, opt_offset + 24, "ImageBase");
                            } else {
                                edit_u32_hex(ui, data, editor, opt_offset + 28, "ImageBase");
                            }
                            ui.end_row();

                            edit_u32_hex(ui, data, editor, opt_offset + 32, "SectionAlignment");
                            ui.end_row();

                            edit_u32_hex(ui, data, editor, opt_offset + 36, "FileAlignment");
                            ui.end_row();

                            ui.colored_label(LABEL, "OSVersion:");
                            ui.monospace(format!("{}.{}", opt.major_os_version, opt.minor_os_version));
                            ui.label("");
                            ui.end_row();

                            edit_u32_hex(ui, data, editor, opt_offset + 56, "SizeOfImage");
                            ui.end_row();

                            edit_u32_hex(ui, data, editor, opt_offset + 60, "SizeOfHeaders");
                            ui.end_row();

                            edit_u32_hex(ui, data, editor, opt_offset + 64, "CheckSum");
                            ui.end_row();

                            // Subsystem — editable dropdown
                            {
                                let subsys_offset = opt_offset + 68;
                                let subsys_original = read_u16_le(data, subsys_offset) as u64;
                                let subsys_current = editor.get_current_u16(data, subsys_offset);
                                let subsys_modified = editor.find_edit(subsys_offset).is_some();
                                let subsys_items: &[(&str, u16)] = &[
                                    ("UNKNOWN", 0),
                                    ("NATIVE", 1),
                                    ("WINDOWS_GUI", 2),
                                    ("WINDOWS_CUI", 3),
                                    ("OS2_CUI", 5),
                                    ("POSIX_CUI", 7),
                                    ("WINDOWS_CE_GUI", 9),
                                    ("EFI_APPLICATION", 10),
                                    ("EFI_BOOT_SERVICE_DRIVER", 11),
                                    ("EFI_RUNTIME_DRIVER", 12),
                                    ("EFI_ROM", 13),
                                    ("XBOX", 14),
                                    ("WINDOWS_BOOT_APPLICATION", 16),
                                ];
                                let subsys_label = subsys_items.iter()
                                    .find(|(_, v)| *v == subsys_current)
                                    .map(|(l, _)| *l)
                                    .unwrap_or("Unknown");
                                ui.colored_label(if subsys_modified { Color32::from_rgb(255, 200, 50) } else { LABEL }, "Subsystem:");
                                let frame = if subsys_modified {
                                    egui::Frame::new().fill(MODIFIED_BG).corner_radius(egui::CornerRadius::same(2)).inner_margin(egui::Margin::symmetric(2, 0))
                                } else {
                                    egui::Frame::NONE
                                };
                                frame.show(ui, |ui| {
                                    egui::ComboBox::from_id_salt("subsystem_combo")
                                        .selected_text(format!("{} ({})", subsys_label, subsys_current))
                                        .show_ui(ui, |ui| {
                                            for (label, val) in subsys_items {
                                                if ui.selectable_label(subsys_current == *val, format!("{} ({})", label, val)).clicked() {
                                                    editor.set_value(subsys_offset, 2, subsys_original, *val as u64, "Subsystem");
                                                }
                                            }
                                        });
                                });
                                if subsys_modified { ui.colored_label(FLAG_COLOR, "*"); } else { ui.label(""); }
                            }
                            ui.end_row();

                            edit_u16_hex(ui, data, editor, opt_offset + 70, "DllCharacteristics");
                            ui.end_row();
                        } else {
                            // Read-only fallback for remaining fields
                            ui.colored_label(LABEL, "AddressOfEntryPoint:");
                            ui.monospace(format!("{:#x}", opt.address_of_entry_point));
                            ui.label("");
                            ui.end_row();
                        }

                        ui.colored_label(LABEL, "NumberOfRvaAndSizes:");
                        ui.monospace(opt.number_of_rva_and_sizes.to_string());
                        ui.label("");
                        ui.end_row();
                    });

                // DllCharacteristics flags
                if opt_valid {
                    ui.add_space(4.0);
                    ui.colored_label(LABEL, "DllCharacteristics Flags:");
                    let dll_chars_offset = opt_offset + 70;
                    let current_dll_chars = editor.get_current_u16(data, dll_chars_offset);
                    let dll_flags: &[(&str, u16)] = &[
                        ("HIGH_ENTROPY_VA", 0x0020),
                        ("DYNAMIC_BASE (ASLR)", 0x0040),
                        ("FORCE_INTEGRITY", 0x0080),
                        ("NX_COMPAT (DEP)", 0x0100),
                        ("NO_SEH", 0x0400),
                        ("GUARD_CF", 0x4000),
                        ("TERMINAL_SERVER_AWARE", 0x8000),
                    ];
                    show_flag_checkboxes_u16(ui, data, editor, dll_chars_offset, current_dll_chars, dll_flags, "DllChar");
                }
            } else {
                show_opt_readonly(ui, opt);
            }

            // Data Directories (always read-only)
            if !opt.data_directories.is_empty() {
                ui.add_space(8.0);
                egui::CollapsingHeader::new(
                    egui::RichText::new("Data Directories").color(ACCENT_DIM),
                )
                .default_open(false)
                .show(ui, |ui| {
                    egui::Grid::new("data_dir_grid")
                        .num_columns(3)
                        .spacing([16.0, 2.0])
                        .striped(true)
                        .show(ui, |ui| {
                            ui.colored_label(LABEL, "Name");
                            ui.colored_label(LABEL, "RVA");
                            ui.colored_label(LABEL, "Size");
                            ui.end_row();

                            for dd in &opt.data_directories {
                                ui.label(&dd.name);
                                ui.monospace(format!("{:#010x}", dd.virtual_address));
                                ui.monospace(format!("{:#010x}", dd.size));
                                ui.end_row();
                            }
                        });
                });
            }
        });
    }

    // --- Section Headers (editable) ---
    if let Some((_, _, num_sections, size_of_opt, _)) = layout {
        let e_lfanew = read_u32_le(data, 0x3c) as usize;
        let sections_offset = e_lfanew + 4 + 20 + size_of_opt as usize;
        let section_count = num_sections as usize;

        ui.add_space(4.0);
        egui::CollapsingHeader::new(
            egui::RichText::new(format!("Section Headers ({} sections)", section_count)).color(ACCENT).size(14.0),
        )
        .default_open(false)
        .show(ui, |ui| {
            for i in 0..section_count {
                let sec_base = sections_offset + i * 40;
                if sec_base + 40 > data.len() { break; }

                // Use pending edit value for section name if available
                let sec_name = if let Some(idx) = editor.find_edit(sec_base) {
                    let val_bytes = editor.edits[idx].new_value.to_le_bytes();
                    let end = val_bytes.iter().position(|&b| b == 0).unwrap_or(8);
                    String::from_utf8_lossy(&val_bytes[..end]).to_string()
                } else {
                    let name_bytes = &data[sec_base..sec_base + 8];
                    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
                    String::from_utf8_lossy(&name_bytes[..end]).to_string()
                };

                egui::CollapsingHeader::new(
                    egui::RichText::new(format!("[{}] {}", i, sec_name)).color(Color32::from_rgb(200, 200, 220)).size(12.0),
                )
                .default_open(false)
                .id_salt(format!("sec_editor_{}", i))
                .show(ui, |ui| {
                    egui::Grid::new(format!("editor_section_{}", i))
                        .num_columns(3)
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            // Name (text edit) — uses pending value
                            ui.colored_label(LABEL, "Name:");
                            let mut name_str = sec_name.clone();
                            let resp = ui.add(egui::TextEdit::singleline(&mut name_str).desired_width(80.0).font(egui::FontId::monospace(13.0)));
                            if resp.changed() {
                                let mut name_buf = [0u8; 8];
                                let bytes = name_str.as_bytes();
                                let copy_len = bytes.len().min(8);
                                name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
                                let new_val = u64::from_le_bytes(name_buf);
                                let old_val = read_u64_le(data, sec_base);
                                editor.set_value(sec_base, 8, old_val, new_val, &format!("Section[{}].Name", i));
                            }
                            ui.label("");
                            ui.end_row();

                            edit_u32_hex(ui, data, editor, sec_base + 8, &format!("VirtualSize [{}]", i));
                            ui.end_row();
                            edit_u32_hex(ui, data, editor, sec_base + 12, &format!("VirtualAddress [{}]", i));
                            ui.end_row();
                            edit_u32_hex(ui, data, editor, sec_base + 16, &format!("SizeOfRawData [{}]", i));
                            ui.end_row();
                            edit_u32_hex(ui, data, editor, sec_base + 20, &format!("PointerToRawData [{}]", i));
                            ui.end_row();
                            edit_u32_hex(ui, data, editor, sec_base + 36, &format!("Characteristics [{}]", i));
                            ui.end_row();
                        });

                    ui.add_space(4.0);
                    ui.colored_label(LABEL, "Section Flags:");
                    let sec_chars_offset = sec_base + 36;
                    let current_sec_chars = editor.get_current_u32(data, sec_chars_offset);
                    let sec_flags: &[(&str, u32)] = &[
                        ("CODE", 0x00000020),
                        ("INITIALIZED_DATA", 0x00000040),
                        ("UNINITIALIZED_DATA", 0x00000080),
                        ("MEM_EXECUTE", 0x20000000),
                        ("MEM_READ", 0x40000000),
                        ("MEM_WRITE", 0x80000000),
                    ];
                    show_flag_checkboxes_u32(ui, data, editor, sec_chars_offset, current_sec_chars, sec_flags, &format!("SecChar{}", i));
                });
            }
        });
    }

    // Pending edits summary
    if !editor.edits.is_empty() {
        ui.add_space(8.0);
        egui::CollapsingHeader::new(
            egui::RichText::new(format!("Pending Edits ({})", editor.edits.len())).color(Color32::from_rgb(255, 200, 50)).size(12.0),
        )
        .default_open(false)
        .show(ui, |ui| {
            egui::Grid::new("pending_edits_grid")
                .num_columns(4)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    ui.colored_label(LABEL, "Offset");
                    ui.colored_label(LABEL, "Field");
                    ui.colored_label(LABEL, "Old");
                    ui.colored_label(LABEL, "New");
                    ui.end_row();
                    for edit in &editor.edits {
                        ui.monospace(format!("{:#x}", edit.offset));
                        ui.colored_label(Color32::from_rgb(200, 200, 220), &edit.label);
                        ui.monospace(format!("{:#x}", edit.old_value));
                        ui.colored_label(Color32::from_rgb(255, 200, 50), format!("{:#x}", edit.new_value));
                        ui.end_row();
                    }
                });
        });
    }

    if result.dos_header.is_none() && result.coff_header.is_none() && result.optional_header.is_none() {
        ui.colored_label(LABEL, "No header data available. Enable 'Headers' in options and re-analyze.");
    }
}

// --- Read-only fallbacks ---

fn show_coff_readonly(ui: &mut Ui, coff: &crate::analysis::CoffHeader) {
    egui::Grid::new("coff_header_grid_ro")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            ui.colored_label(LABEL, "Machine:");
            ui.monospace(format!("{} ({:#06x})", coff.machine, coff.machine_raw));
            ui.end_row();
            ui.colored_label(LABEL, "TimeDateStamp:");
            ui.monospace(format!("{:#010x} ({})", coff.time_date_stamp, coff.time_date_stamp_str));
            ui.end_row();
            ui.colored_label(LABEL, "Characteristics:");
            ui.monospace(format!("{:#06x}", coff.characteristics));
            ui.end_row();
        });
}

fn show_opt_readonly(ui: &mut Ui, opt: &crate::analysis::OptionalHeader) {
    egui::Grid::new("opt_header_grid_ro")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            ui.colored_label(LABEL, "Magic:");
            ui.monospace(&opt.magic);
            ui.end_row();
            ui.colored_label(LABEL, "AddressOfEntryPoint:");
            ui.monospace(format!("{:#x}", opt.address_of_entry_point));
            ui.end_row();
            ui.colored_label(LABEL, "ImageBase:");
            ui.monospace(format!("{:#x}", opt.image_base));
            ui.end_row();
        });
}

// --- PE layout helper ---

fn pe_layout(data: &[u8]) -> Option<(bool, usize, u16, u16, usize)> {
    if data.len() < 0x40 { return None; }
    let e_lfanew = read_u32_le(data, 0x3c) as usize;
    if e_lfanew + 4 + 20 > data.len() { return None; }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return None; }
    let coff_offset = e_lfanew + 4;
    let num_sections = read_u16_le(data, coff_offset + 2);
    let size_of_opt = read_u16_le(data, coff_offset + 16);
    let opt_offset = coff_offset + 20;
    if opt_offset + 2 > data.len() { return None; }
    let magic = read_u16_le(data, opt_offset);
    let is_pe32plus = magic == 0x20b;
    Some((is_pe32plus, opt_offset, num_sections, size_of_opt, coff_offset))
}

// --- Editor helpers (reused from editor.rs logic) ---

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 <= data.len() {
        u16::from_le_bytes([data[offset], data[offset + 1]])
    } else { 0 }
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 <= data.len() {
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    } else { 0 }
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 <= data.len() {
        u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ])
    } else { 0 }
}

fn edit_u16_hex(ui: &mut Ui, data: &[u8], state: &mut EditorState, offset: usize, label: &str) {
    let original = read_u16_le(data, offset) as u64;
    let current = state.get_current_u16(data, offset);
    let is_modified = state.find_edit(offset).is_some();
    ui.colored_label(if is_modified { Color32::from_rgb(255, 200, 50) } else { LABEL }, format!("{}:", label));
    let frame = if is_modified {
        egui::Frame::new().fill(MODIFIED_BG).corner_radius(egui::CornerRadius::same(2)).inner_margin(egui::Margin::symmetric(2, 0))
    } else {
        egui::Frame::NONE
    };
    frame.show(ui, |ui| {
        let mut val = current as u32;
        if ui.add(egui::DragValue::new(&mut val).range(0..=0xFFFFu32).hexadecimal(4, false, true)).changed() {
            state.set_value(offset, 2, original, val as u64, label);
        }
    });
    if is_modified { ui.colored_label(FLAG_COLOR, "*"); } else { ui.label(""); }
}

fn edit_u32_hex(ui: &mut Ui, data: &[u8], state: &mut EditorState, offset: usize, label: &str) {
    let original = read_u32_le(data, offset) as u64;
    let current = state.get_current_u32(data, offset);
    let is_modified = state.find_edit(offset).is_some();
    ui.colored_label(if is_modified { Color32::from_rgb(255, 200, 50) } else { LABEL }, format!("{}:", label));
    let frame = if is_modified {
        egui::Frame::new().fill(MODIFIED_BG).corner_radius(egui::CornerRadius::same(2)).inner_margin(egui::Margin::symmetric(2, 0))
    } else {
        egui::Frame::NONE
    };
    frame.show(ui, |ui| {
        let mut val = current;
        if ui.add(egui::DragValue::new(&mut val).range(0..=u32::MAX).hexadecimal(8, false, true)).changed() {
            state.set_value(offset, 4, original, val as u64, label);
        }
    });
    if is_modified { ui.colored_label(FLAG_COLOR, "*"); } else { ui.label(""); }
}

fn edit_u64_hex(ui: &mut Ui, data: &[u8], state: &mut EditorState, offset: usize, label: &str) {
    let original = read_u64_le(data, offset);
    let current = state.get_current_u64(data, offset);
    let is_modified = state.find_edit(offset).is_some();
    ui.colored_label(if is_modified { Color32::from_rgb(255, 200, 50) } else { LABEL }, format!("{}:", label));
    let frame = if is_modified {
        egui::Frame::new().fill(MODIFIED_BG).corner_radius(egui::CornerRadius::same(2)).inner_margin(egui::Margin::symmetric(2, 0))
    } else {
        egui::Frame::NONE
    };
    frame.show(ui, |ui| {
        let mut hex_str = format!("{:#018x}", current);
        let resp = ui.add(egui::TextEdit::singleline(&mut hex_str).desired_width(150.0).font(egui::FontId::monospace(13.0)));
        if resp.changed() {
            let trimmed = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
            if let Ok(val) = u64::from_str_radix(trimmed, 16) {
                state.set_value(offset, 8, original, val, label);
            }
        }
    });
    if is_modified { ui.colored_label(FLAG_COLOR, "*"); } else { ui.label(""); }
}

fn show_flag_checkboxes_u16(
    ui: &mut Ui, data: &[u8], state: &mut EditorState,
    offset: usize, current: u16, flags: &[(&str, u16)], id_prefix: &str,
) {
    let original = read_u16_le(data, offset) as u64;
    ui.horizontal_wrapped(|ui| {
        for (name, bit) in flags {
            let mut set = current & bit != 0;
            let was_set = set;
            ui.add(egui::Checkbox::new(&mut set, *name));
            if set != was_set {
                let new_val = if set { (current | bit) as u64 } else { (current & !bit) as u64 };
                state.set_value(offset, 2, original, new_val, &format!("{}.{}", id_prefix, name));
            }
        }
    });
}

fn show_flag_checkboxes_u32(
    ui: &mut Ui, data: &[u8], state: &mut EditorState,
    offset: usize, current: u32, flags: &[(&str, u32)], id_prefix: &str,
) {
    let original = read_u32_le(data, offset) as u64;
    ui.horizontal_wrapped(|ui| {
        for (name, bit) in flags {
            let mut set = current & bit != 0;
            let was_set = set;
            ui.add(egui::Checkbox::new(&mut set, *name));
            if set != was_set {
                let new_val = if set { (current | bit) as u64 } else { (current & !bit) as u64 };
                state.set_value(offset, 4, original, new_val, &format!("{}.{}", id_prefix, name));
            }
        }
    });
}
