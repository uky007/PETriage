use egui::{Color32, Ui};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const OPSEC_BG: Color32 = Color32::from_rgb(255, 200, 50);
const RISK_MEDIUM: Color32 = Color32::from_rgb(255, 200, 50);

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let debug = match result.debug {
        Some(ref d) => d,
        None => {
            ui.colored_label(LABEL, "No Debug Directory found in this PE file.");
            return;
        }
    };

    ui.colored_label(ACCENT, egui::RichText::new(format!("DEBUG DIRECTORY ({} entries)", debug.entries.len())).size(14.0));
    ui.add_space(6.0);

    for (i, entry) in debug.entries.iter().enumerate() {
        if i > 0 {
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);
        }

        ui.colored_label(ACCENT, egui::RichText::new(format!("[{}] {}", i, entry.debug_type)).size(12.0));
        ui.add_space(4.0);

        egui::Grid::new(format!("debug_entry_{}", i))
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.colored_label(LABEL, "Type:");
                ui.monospace(format!("{} ({})", entry.debug_type, entry.debug_type_raw));
                ui.end_row();

                ui.colored_label(LABEL, "Timestamp:");
                ui.monospace(format!("{:#010x}", entry.timestamp));
                ui.end_row();

                ui.colored_label(LABEL, "Version:");
                ui.monospace(format!("{}.{}", entry.major_version, entry.minor_version));
                ui.end_row();

                ui.colored_label(LABEL, "SizeOfData:");
                ui.monospace(format!("{:#x}", entry.size_of_data));
                ui.end_row();

                ui.colored_label(LABEL, "PointerToRawData:");
                ui.monospace(format!("{:#x}", entry.pointer_to_raw_data));
                ui.end_row();

                if let Some(ref guid) = entry.guid {
                    ui.colored_label(LABEL, "GUID:");
                    ui.monospace(guid);
                    ui.end_row();
                }

                if let Some(age) = entry.age {
                    ui.colored_label(LABEL, "Age:");
                    ui.monospace(age.to_string());
                    ui.end_row();
                }

                if let Some(ref pdb) = entry.pdb_path {
                    ui.colored_label(RISK_MEDIUM, "PDB Path (OPSEC):");
                    egui::Frame::new()
                        .fill(OPSEC_BG.gamma_multiply(0.2))
                        .corner_radius(egui::CornerRadius::same(3))
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(pdb).color(OPSEC_BG).strong().monospace());
                        });
                    ui.end_row();
                }
            });
    }
}
