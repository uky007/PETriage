use egui::{Color32, Ui};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const ACCENT_DIM: Color32 = Color32::from_rgb(0, 120, 150);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const FLAG_COLOR: Color32 = Color32::from_rgb(180, 160, 90);

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
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

    if let Some(ref coff) = result.coff_header {
        ui.add_space(4.0);
        egui::CollapsingHeader::new(
            egui::RichText::new("COFF Header").color(ACCENT).size(14.0),
        )
        .default_open(true)
        .show(ui, |ui| {
            egui::Grid::new("coff_header_grid")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.colored_label(LABEL, "Machine:");
                    ui.monospace(format!("{} ({:#06x})", coff.machine, coff.machine_raw));
                    ui.end_row();

                    ui.colored_label(LABEL, "NumberOfSections:");
                    ui.monospace(coff.number_of_sections.to_string());
                    ui.end_row();

                    ui.colored_label(LABEL, "TimeDateStamp:");
                    ui.monospace(format!("{:#010x} ({})", coff.time_date_stamp, coff.time_date_stamp_str));
                    ui.end_row();

                    ui.colored_label(LABEL, "PointerToSymbolTable:");
                    ui.monospace(format!("{:#x}", coff.pointer_to_symbol_table));
                    ui.end_row();

                    ui.colored_label(LABEL, "NumberOfSymbols:");
                    ui.monospace(coff.number_of_symbols.to_string());
                    ui.end_row();

                    ui.colored_label(LABEL, "SizeOfOptionalHeader:");
                    ui.monospace(format!("{:#x}", coff.size_of_optional_header));
                    ui.end_row();

                    ui.colored_label(LABEL, "Characteristics:");
                    ui.monospace(format!("{:#06x}", coff.characteristics));
                    ui.end_row();
                });
            if !coff.characteristics_str.is_empty() {
                ui.add_space(4.0);
                for flag in &coff.characteristics_str {
                    ui.horizontal(|ui| {
                        ui.add_space(16.0);
                        ui.colored_label(FLAG_COLOR, format!("\u{25b8} {flag}"));
                    });
                }
            }
        });
    }

    if let Some(ref opt) = result.optional_header {
        ui.add_space(4.0);
        egui::CollapsingHeader::new(
            egui::RichText::new("Optional Header").color(ACCENT).size(14.0),
        )
        .default_open(true)
        .show(ui, |ui| {
            egui::Grid::new("opt_header_grid")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.colored_label(LABEL, "Magic:");
                    ui.monospace(&opt.magic);
                    ui.end_row();

                    ui.colored_label(LABEL, "LinkerVersion:");
                    ui.monospace(format!("{}.{}", opt.major_linker_version, opt.minor_linker_version));
                    ui.end_row();

                    ui.colored_label(LABEL, "SizeOfCode:");
                    ui.monospace(format!("{:#x}", opt.size_of_code));
                    ui.end_row();

                    ui.colored_label(LABEL, "AddressOfEntryPoint:");
                    ui.monospace(format!("{:#x}", opt.address_of_entry_point));
                    ui.end_row();

                    ui.colored_label(LABEL, "ImageBase:");
                    ui.monospace(format!("{:#x}", opt.image_base));
                    ui.end_row();

                    ui.colored_label(LABEL, "SectionAlignment:");
                    ui.monospace(format!("{:#x}", opt.section_alignment));
                    ui.end_row();

                    ui.colored_label(LABEL, "FileAlignment:");
                    ui.monospace(format!("{:#x}", opt.file_alignment));
                    ui.end_row();

                    ui.colored_label(LABEL, "OSVersion:");
                    ui.monospace(format!("{}.{}", opt.major_os_version, opt.minor_os_version));
                    ui.end_row();

                    ui.colored_label(LABEL, "SizeOfImage:");
                    ui.monospace(format!("{:#x}", opt.size_of_image));
                    ui.end_row();

                    ui.colored_label(LABEL, "SizeOfHeaders:");
                    ui.monospace(format!("{:#x}", opt.size_of_headers));
                    ui.end_row();

                    ui.colored_label(LABEL, "CheckSum:");
                    ui.monospace(format!("{:#x}", opt.checksum));
                    ui.end_row();

                    ui.colored_label(LABEL, "Subsystem:");
                    ui.monospace(&opt.subsystem);
                    ui.end_row();

                    ui.colored_label(LABEL, "DllCharacteristics:");
                    ui.monospace(format!("{:#06x}", opt.dll_characteristics));
                    ui.end_row();
                });
            if !opt.dll_characteristics_str.is_empty() {
                ui.add_space(4.0);
                for flag in &opt.dll_characteristics_str {
                    ui.horizontal(|ui| {
                        ui.add_space(16.0);
                        ui.colored_label(FLAG_COLOR, format!("\u{25b8} {flag}"));
                    });
                }
            }

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

    if result.dos_header.is_none() && result.coff_header.is_none() && result.optional_header.is_none() {
        ui.colored_label(LABEL, "No header data available. Enable 'Headers' in options and re-analyze.");
    }
}
