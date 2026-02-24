use egui::{Color32, Ui};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const WARNING: Color32 = Color32::from_rgb(230, 190, 50);

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let tls = match result.tls {
        Some(ref t) => t,
        None => {
            ui.colored_label(LABEL, "No TLS Directory found in this PE file.");
            return;
        }
    };

    ui.colored_label(ACCENT, egui::RichText::new("TLS DIRECTORY").size(14.0));
    ui.add_space(6.0);

    egui::Grid::new("tls_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.colored_label(LABEL, "RawDataStart:");
            ui.monospace(&tls.raw_data_start);
            ui.end_row();

            ui.colored_label(LABEL, "RawDataEnd:");
            ui.monospace(&tls.raw_data_end);
            ui.end_row();

            ui.colored_label(LABEL, "AddressOfIndex:");
            ui.monospace(&tls.address_of_index);
            ui.end_row();

            ui.colored_label(LABEL, "AddressOfCallBacks:");
            ui.monospace(&tls.address_of_callbacks);
            ui.end_row();

            ui.colored_label(LABEL, "SizeOfZeroFill:");
            ui.monospace(format!("{:#x}", tls.size_of_zero_fill));
            ui.end_row();

            ui.colored_label(LABEL, "Characteristics:");
            ui.monospace(format!("{:#x}", tls.characteristics));
            ui.end_row();

            ui.colored_label(LABEL, "Callbacks:");
            if tls.callback_count > 0 {
                ui.colored_label(WARNING, format!("{}", tls.callback_count));
            } else {
                ui.monospace("0");
            }
            ui.end_row();
        });

    if !tls.callbacks.is_empty() {
        ui.add_space(10.0);
        ui.colored_label(ACCENT, egui::RichText::new("CALLBACK ADDRESSES").size(12.0));
        ui.add_space(4.0);

        for (i, cb) in tls.callbacks.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.colored_label(LABEL, format!("  [{}]", i));
                ui.monospace(cb);
            });
        }
    }
}
