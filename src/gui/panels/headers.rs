use egui::Ui;

use crate::analysis::AnalysisResult;

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    if let Some(ref dos) = result.dos_header {
        egui::CollapsingHeader::new("DOS Header")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("dos_header_grid")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        ui.strong("e_magic:");
                        ui.monospace(&dos.e_magic);
                        ui.end_row();

                        ui.strong("e_lfanew:");
                        ui.monospace(format!("{:#x}", dos.e_lfanew));
                        ui.end_row();
                    });
            });
    }

    if let Some(ref coff) = result.coff_header {
        ui.add_space(4.0);
        egui::CollapsingHeader::new("COFF Header")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("coff_header_grid")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        ui.strong("Machine:");
                        ui.monospace(format!("{} ({:#06x})", coff.machine, coff.machine_raw));
                        ui.end_row();

                        ui.strong("NumberOfSections:");
                        ui.monospace(coff.number_of_sections.to_string());
                        ui.end_row();

                        ui.strong("TimeDateStamp:");
                        ui.monospace(format!("{:#010x} ({})", coff.time_date_stamp, coff.time_date_stamp_str));
                        ui.end_row();

                        ui.strong("PointerToSymbolTable:");
                        ui.monospace(format!("{:#x}", coff.pointer_to_symbol_table));
                        ui.end_row();

                        ui.strong("NumberOfSymbols:");
                        ui.monospace(coff.number_of_symbols.to_string());
                        ui.end_row();

                        ui.strong("SizeOfOptionalHeader:");
                        ui.monospace(format!("{:#x}", coff.size_of_optional_header));
                        ui.end_row();

                        ui.strong("Characteristics:");
                        ui.monospace(format!("{:#06x}", coff.characteristics));
                        ui.end_row();
                    });
                if !coff.characteristics_str.is_empty() {
                    ui.add_space(2.0);
                    ui.label("Flags:");
                    for flag in &coff.characteristics_str {
                        ui.horizontal(|ui| {
                            ui.add_space(16.0);
                            ui.monospace(format!("• {flag}"));
                        });
                    }
                }
            });
    }

    if let Some(ref opt) = result.optional_header {
        ui.add_space(4.0);
        egui::CollapsingHeader::new("Optional Header")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("opt_header_grid")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        ui.strong("Magic:");
                        ui.monospace(&opt.magic);
                        ui.end_row();

                        ui.strong("LinkerVersion:");
                        ui.monospace(format!("{}.{}", opt.major_linker_version, opt.minor_linker_version));
                        ui.end_row();

                        ui.strong("SizeOfCode:");
                        ui.monospace(format!("{:#x}", opt.size_of_code));
                        ui.end_row();

                        ui.strong("AddressOfEntryPoint:");
                        ui.monospace(format!("{:#x}", opt.address_of_entry_point));
                        ui.end_row();

                        ui.strong("ImageBase:");
                        ui.monospace(format!("{:#x}", opt.image_base));
                        ui.end_row();

                        ui.strong("SectionAlignment:");
                        ui.monospace(format!("{:#x}", opt.section_alignment));
                        ui.end_row();

                        ui.strong("FileAlignment:");
                        ui.monospace(format!("{:#x}", opt.file_alignment));
                        ui.end_row();

                        ui.strong("OSVersion:");
                        ui.monospace(format!("{}.{}", opt.major_os_version, opt.minor_os_version));
                        ui.end_row();

                        ui.strong("SizeOfImage:");
                        ui.monospace(format!("{:#x}", opt.size_of_image));
                        ui.end_row();

                        ui.strong("SizeOfHeaders:");
                        ui.monospace(format!("{:#x}", opt.size_of_headers));
                        ui.end_row();

                        ui.strong("CheckSum:");
                        ui.monospace(format!("{:#x}", opt.checksum));
                        ui.end_row();

                        ui.strong("Subsystem:");
                        ui.monospace(&opt.subsystem);
                        ui.end_row();

                        ui.strong("DllCharacteristics:");
                        ui.monospace(format!("{:#06x}", opt.dll_characteristics));
                        ui.end_row();
                    });
                if !opt.dll_characteristics_str.is_empty() {
                    ui.add_space(2.0);
                    ui.label("DLL Flags:");
                    for flag in &opt.dll_characteristics_str {
                        ui.horizontal(|ui| {
                            ui.add_space(16.0);
                            ui.monospace(format!("• {flag}"));
                        });
                    }
                }

                if !opt.data_directories.is_empty() {
                    ui.add_space(8.0);
                    egui::CollapsingHeader::new("Data Directories")
                        .default_open(false)
                        .show(ui, |ui| {
                            egui::Grid::new("data_dir_grid")
                                .num_columns(3)
                                .spacing([16.0, 2.0])
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.strong("Name");
                                    ui.strong("RVA");
                                    ui.strong("Size");
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
        ui.label("No header data available. Enable 'Headers' in options and re-analyze.");
    }
}
