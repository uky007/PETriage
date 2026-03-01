use egui::{Color32, Ui};

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const MODIFIED_BG: Color32 = Color32::from_rgb(80, 60, 0);
const FLAG_COLOR: Color32 = Color32::from_rgb(180, 160, 90);

#[derive(Clone, Debug)]
pub struct PendingEdit {
    pub offset: usize,
    pub size: usize,
    pub old_value: u64,
    pub new_value: u64,
    pub label: String,
}

#[derive(Clone, Debug, Default)]
pub struct EditorState {
    pub edits: Vec<PendingEdit>,
    pub dirty: bool,
    pub save_message: Option<String>,
}

impl EditorState {
    pub fn reset(&mut self) {
        self.edits.clear();
        self.dirty = false;
        self.save_message = None;
    }

    fn find_edit(&self, offset: usize) -> Option<usize> {
        self.edits.iter().position(|e| e.offset == offset)
    }

    fn get_current_u16(&self, data: &[u8], offset: usize) -> u16 {
        if let Some(idx) = self.find_edit(offset) {
            self.edits[idx].new_value as u16
        } else {
            read_u16_le(data, offset)
        }
    }

    fn get_current_u32(&self, data: &[u8], offset: usize) -> u32 {
        if let Some(idx) = self.find_edit(offset) {
            self.edits[idx].new_value as u32
        } else {
            read_u32_le(data, offset)
        }
    }

    fn get_current_u64(&self, data: &[u8], offset: usize) -> u64 {
        if let Some(idx) = self.find_edit(offset) {
            self.edits[idx].new_value
        } else {
            read_u64_le(data, offset)
        }
    }

    fn set_value(&mut self, offset: usize, size: usize, old_value: u64, new_value: u64, label: &str) {
        if old_value == new_value {
            // Remove edit if reverted to original
            if let Some(idx) = self.find_edit(offset)
                && self.edits[idx].old_value == new_value {
                    self.edits.remove(idx);
                    self.dirty = !self.edits.is_empty();
                }
            return;
        }
        if let Some(idx) = self.find_edit(offset) {
            self.edits[idx].new_value = new_value;
        } else {
            self.edits.push(PendingEdit {
                offset,
                size,
                old_value,
                new_value,
                label: label.to_string(),
            });
        }
        self.dirty = true;
    }

    pub fn apply_to(&self, data: &mut [u8]) {
        for edit in &self.edits {
            if edit.offset >= data.len() {
                continue;
            }
            let bytes = edit.new_value.to_le_bytes();
            let end = (edit.offset + edit.size).min(data.len());
            let count = end - edit.offset;
            data[edit.offset..edit.offset + count].copy_from_slice(&bytes[..count]);
        }
    }
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 <= data.len() {
        u16::from_le_bytes([data[offset], data[offset + 1]])
    } else {
        0
    }
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 <= data.len() {
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    } else {
        0
    }
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 <= data.len() {
        u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ])
    } else {
        0
    }
}

/// Returns (is_pe32plus, optional_header_offset, number_of_sections, size_of_optional_header)
fn pe_layout(data: &[u8]) -> Option<(bool, usize, u16, u16)> {
    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = read_u32_le(data, 0x3c) as usize;
    if e_lfanew + 4 + 20 > data.len() {
        return None;
    }
    // Verify PE signature
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff_offset = e_lfanew + 4;
    let num_sections = read_u16_le(data, coff_offset + 2);
    let size_of_opt = read_u16_le(data, coff_offset + 16);
    let opt_offset = coff_offset + 20;
    if opt_offset + 2 > data.len() {
        return None;
    }
    let magic = read_u16_le(data, opt_offset);
    let is_pe32plus = magic == 0x20b;
    Some((is_pe32plus, opt_offset, num_sections, size_of_opt))
}

pub fn show(ui: &mut Ui, data: &[u8], state: &mut EditorState) {
    let layout = match pe_layout(data) {
        Some(l) => l,
        None => {
            ui.colored_label(LABEL, "Cannot parse PE layout for editing.");
            return;
        }
    };
    let (is_pe32plus, opt_offset, num_sections, size_of_opt) = layout;
    let e_lfanew = read_u32_le(data, 0x3c) as usize;
    let coff_offset = e_lfanew + 4;

    ui.colored_label(ACCENT, egui::RichText::new("PE HEADER EDITOR").size(14.0));
    ui.add_space(4.0);
    ui.colored_label(LABEL, format!(
        "Format: {} | Sections: {} | Optional Header Size: {:#x}",
        if is_pe32plus { "PE32+" } else { "PE32" }, num_sections, size_of_opt
    ));
    ui.add_space(8.0);

    if state.dirty {
        ui.horizontal(|ui| {
            ui.colored_label(Color32::from_rgb(255, 200, 50), egui::RichText::new(
                format!("{} pending edit(s)", state.edits.len())
            ).strong());
        });
        ui.add_space(4.0);
    }

    if let Some(ref msg) = state.save_message.clone() {
        ui.colored_label(Color32::from_rgb(80, 200, 120), msg);
        ui.add_space(4.0);
    }

    // --- COFF Header ---
    egui::CollapsingHeader::new(
        egui::RichText::new("COFF Header").color(ACCENT).size(13.0),
    )
    .default_open(true)
    .show(ui, |ui| {
        egui::Grid::new("editor_coff")
            .num_columns(3)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                // TimeDateStamp
                edit_u32_hex(ui, data, state, coff_offset + 4, "TimeDateStamp");
                ui.end_row();

                // Characteristics
                let chars_offset = coff_offset + 18;
                edit_u16_hex(ui, data, state, chars_offset, "Characteristics");
                ui.end_row();
            });

        // COFF Characteristics flags
        ui.add_space(4.0);
        ui.colored_label(LABEL, "COFF Flags:");
        let chars_offset = coff_offset + 18;
        let current_chars = state.get_current_u16(data, chars_offset);
        let coff_flags: &[(&str, u16)] = &[
            ("RELOCS_STRIPPED", 0x0001),
            ("EXECUTABLE_IMAGE", 0x0002),
            ("LARGE_ADDRESS_AWARE", 0x0020),
            ("32BIT_MACHINE", 0x0100),
            ("DLL", 0x2000),
        ];
        show_flag_checkboxes_u16(ui, data, state, chars_offset, current_chars, coff_flags, "CoffChar");
    });

    ui.add_space(8.0);

    // --- Optional Header ---
    // Require at least 72 bytes of optional header (up to DllCharacteristics + 2)
    let opt_end = opt_offset + (size_of_opt as usize);
    let opt_valid = opt_end <= data.len() && size_of_opt >= 72;

    egui::CollapsingHeader::new(
        egui::RichText::new("Optional Header").color(ACCENT).size(13.0),
    )
    .default_open(true)
    .show(ui, |ui| {
        if !opt_valid {
            ui.colored_label(Color32::from_rgb(255, 70, 70), "Optional header too small or truncated for editing.");
            return;
        }
        egui::Grid::new("editor_optional")
            .num_columns(3)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                // AddressOfEntryPoint (always at +16 from opt header)
                edit_u32_hex(ui, data, state, opt_offset + 16, "AddressOfEntryPoint");
                ui.end_row();

                // ImageBase
                if is_pe32plus {
                    edit_u64_hex(ui, data, state, opt_offset + 24, "ImageBase");
                } else {
                    edit_u32_hex(ui, data, state, opt_offset + 28, "ImageBase");
                }
                ui.end_row();

                // SectionAlignment
                edit_u32_hex(ui, data, state, opt_offset + 32, "SectionAlignment");
                ui.end_row();

                // FileAlignment
                edit_u32_hex(ui, data, state, opt_offset + 36, "FileAlignment");
                ui.end_row();

                // SizeOfImage
                edit_u32_hex(ui, data, state, opt_offset + 56, "SizeOfImage");
                ui.end_row();

                // SizeOfHeaders
                edit_u32_hex(ui, data, state, opt_offset + 60, "SizeOfHeaders");
                ui.end_row();

                // CheckSum
                edit_u32_hex(ui, data, state, opt_offset + 64, "CheckSum");
                ui.end_row();

                // Subsystem
                let subsys_offset = opt_offset + 68;
                let subsys_val = state.get_current_u16(data, subsys_offset);
                let subsys_label = match subsys_val {
                    1 => "NATIVE",
                    2 => "WINDOWS_GUI",
                    3 => "WINDOWS_CUI",
                    _ => "Other",
                };
                edit_u16_hex(ui, data, state, subsys_offset, &format!("Subsystem ({})", subsys_label));
                ui.end_row();

                // DllCharacteristics
                edit_u16_hex(ui, data, state, opt_offset + 70, "DllCharacteristics");
                ui.end_row();
            });

        // DllCharacteristics flags
        ui.add_space(4.0);
        ui.colored_label(LABEL, "DllCharacteristics Flags:");
        let dll_chars_offset = opt_offset + 70;
        let current_dll_chars = state.get_current_u16(data, dll_chars_offset);
        let dll_flags: &[(&str, u16)] = &[
            ("HIGH_ENTROPY_VA", 0x0020),
            ("DYNAMIC_BASE (ASLR)", 0x0040),
            ("FORCE_INTEGRITY", 0x0080),
            ("NX_COMPAT (DEP)", 0x0100),
            ("NO_SEH", 0x0400),
            ("GUARD_CF", 0x4000),
            ("TERMINAL_SERVER_AWARE", 0x8000),
        ];
        show_flag_checkboxes_u16(ui, data, state, dll_chars_offset, current_dll_chars, dll_flags, "DllChar");
    });

    ui.add_space(8.0);

    // --- Section Headers ---
    let sections_offset = opt_offset + size_of_opt as usize;
    let section_count = num_sections as usize;

    egui::CollapsingHeader::new(
        egui::RichText::new(format!("Section Headers ({} sections)", section_count)).color(ACCENT).size(13.0),
    )
    .default_open(false)
    .show(ui, |ui| {
        for i in 0..section_count {
            let sec_base = sections_offset + i * 40;
            if sec_base + 40 > data.len() {
                break;
            }

            // Read section name
            let name_bytes = &data[sec_base..sec_base + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let sec_name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

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
                        // Name (8 bytes ASCII) - display as text
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
                            state.set_value(sec_base, 8, old_val, new_val, &format!("Section[{}].Name", i));
                        }
                        ui.label("");
                        ui.end_row();

                        edit_u32_hex(ui, data, state, sec_base + 8, &format!("VirtualSize [{}]", i));
                        ui.end_row();
                        edit_u32_hex(ui, data, state, sec_base + 12, &format!("VirtualAddress [{}]", i));
                        ui.end_row();
                        edit_u32_hex(ui, data, state, sec_base + 16, &format!("SizeOfRawData [{}]", i));
                        ui.end_row();
                        edit_u32_hex(ui, data, state, sec_base + 20, &format!("PointerToRawData [{}]", i));
                        ui.end_row();
                        edit_u32_hex(ui, data, state, sec_base + 36, &format!("Characteristics [{}]", i));
                        ui.end_row();
                    });

                // Section Characteristics flags
                ui.add_space(4.0);
                ui.colored_label(LABEL, "Section Flags:");
                let sec_chars_offset = sec_base + 36;
                let current_sec_chars = state.get_current_u32(data, sec_chars_offset);
                let sec_flags: &[(&str, u32)] = &[
                    ("CODE", 0x00000020),
                    ("INITIALIZED_DATA", 0x00000040),
                    ("UNINITIALIZED_DATA", 0x00000080),
                    ("MEM_EXECUTE", 0x20000000),
                    ("MEM_READ", 0x40000000),
                    ("MEM_WRITE", 0x80000000),
                ];
                show_flag_checkboxes_u32(ui, data, state, sec_chars_offset, current_sec_chars, sec_flags, &format!("SecChar{}", i));
            });
        }
    });

    ui.add_space(16.0);
    ui.separator();
    ui.add_space(8.0);

    // Save As / Reset buttons
    ui.horizontal(|ui| {
        let save_btn = egui::Button::new(
            egui::RichText::new("Save As...").color(Color32::WHITE).strong(),
        )
        .fill(if state.dirty { Color32::from_rgb(0, 100, 140) } else { Color32::from_rgb(40, 40, 60) })
        .stroke(egui::Stroke::new(1.0, if state.dirty { ACCENT } else { Color32::from_rgb(60, 60, 80) }))
        .corner_radius(egui::CornerRadius::same(4));

        if ui.add_enabled(state.dirty, save_btn).clicked()
            && let Some(path) = rfd::FileDialog::new()
                .add_filter("PE files", &["exe", "dll", "sys", "ocx", "scr"])
                .add_filter("All files", &["*"])
                .save_file()
            {
                let mut patched = data.to_vec();
                state.apply_to(&mut patched);
                match std::fs::write(&path, &patched) {
                    Ok(()) => {
                        state.save_message = Some(format!("Saved to {}", path.display()));
                        state.edits.clear();
                        state.dirty = false;
                    }
                    Err(e) => {
                        state.save_message = Some(format!("Save failed: {}", e));
                    }
                }
            }

        let reset_btn = egui::Button::new(
            egui::RichText::new("Reset").color(Color32::WHITE),
        )
        .fill(Color32::from_rgb(80, 30, 30))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(160, 60, 60)))
        .corner_radius(egui::CornerRadius::same(4));

        if ui.add_enabled(state.dirty, reset_btn).clicked() {
            state.reset();
        }
    });

    // Show pending edits summary
    if !state.edits.is_empty() {
        ui.add_space(8.0);
        egui::CollapsingHeader::new(
            egui::RichText::new(format!("Pending Edits ({})", state.edits.len())).color(Color32::from_rgb(255, 200, 50)).size(12.0),
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
                    for edit in &state.edits {
                        ui.monospace(format!("{:#x}", edit.offset));
                        ui.colored_label(Color32::from_rgb(200, 200, 220), &edit.label);
                        ui.monospace(format!("{:#x}", edit.old_value));
                        ui.colored_label(Color32::from_rgb(255, 200, 50), format!("{:#x}", edit.new_value));
                        ui.end_row();
                    }
                });
        });
    }
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

    if is_modified {
        ui.colored_label(FLAG_COLOR, "*");
    } else {
        ui.label("");
    }
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

    if is_modified {
        ui.colored_label(FLAG_COLOR, "*");
    } else {
        ui.label("");
    }
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
        // DragValue doesn't support u64, so use two u32 halves visually shown as a hex text edit
        let mut hex_str = format!("{:#018x}", current);
        let resp = ui.add(egui::TextEdit::singleline(&mut hex_str).desired_width(150.0).font(egui::FontId::monospace(13.0)));
        if resp.changed() {
            let trimmed = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
            if let Ok(val) = u64::from_str_radix(trimmed, 16) {
                state.set_value(offset, 8, original, val, label);
            }
        }
    });

    if is_modified {
        ui.colored_label(FLAG_COLOR, "*");
    } else {
        ui.label("");
    }
}

fn show_flag_checkboxes_u16(
    ui: &mut Ui,
    data: &[u8],
    state: &mut EditorState,
    offset: usize,
    current: u16,
    flags: &[(&str, u16)],
    id_prefix: &str,
) {
    let original = read_u16_le(data, offset) as u64;
    ui.horizontal_wrapped(|ui| {
        for (name, bit) in flags {
            let mut set = current & bit != 0;
            let was_set = set;
            let checkbox = egui::Checkbox::new(&mut set, *name);
            ui.add(checkbox);
            if set != was_set {
                let new_val = if set {
                    (current | bit) as u64
                } else {
                    (current & !bit) as u64
                };
                state.set_value(offset, 2, original, new_val, &format!("{}.{}", id_prefix, name));
            }
        }
    });
}

fn show_flag_checkboxes_u32(
    ui: &mut Ui,
    data: &[u8],
    state: &mut EditorState,
    offset: usize,
    current: u32,
    flags: &[(&str, u32)],
    id_prefix: &str,
) {
    let original = read_u32_le(data, offset) as u64;
    ui.horizontal_wrapped(|ui| {
        for (name, bit) in flags {
            let mut set = current & bit != 0;
            let was_set = set;
            let checkbox = egui::Checkbox::new(&mut set, *name);
            ui.add(checkbox);
            if set != was_set {
                let new_val = if set {
                    (current | bit) as u64
                } else {
                    (current & !bit) as u64
                };
                state.set_value(offset, 4, original, new_val, &format!("{}.{}", id_prefix, name));
            }
        }
    });
}
