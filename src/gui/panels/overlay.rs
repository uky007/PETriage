use egui::{Color32, Ui};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const WARNING: Color32 = Color32::from_rgb(230, 190, 50);

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let overlay = match result.overlay {
        Some(ref o) => o,
        None => {
            ui.colored_label(LABEL, "No overlay data available. Enable 'Overlay' in options and re-analyze.");
            return;
        }
    };

    ui.colored_label(ACCENT, egui::RichText::new("OVERLAY").size(14.0));
    ui.add_space(6.0);

    egui::Grid::new("overlay_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.colored_label(LABEL, "Present:");
            if overlay.present {
                ui.colored_label(WARNING, "Yes");
            } else {
                ui.label("No");
            }
            ui.end_row();

            if overlay.present {
                ui.colored_label(LABEL, "Offset:");
                ui.monospace(format!("{:#x}", overlay.offset));
                ui.end_row();

                ui.colored_label(LABEL, "Size:");
                ui.monospace(format!("{} bytes ({:.2} KB)", overlay.size, overlay.size as f64 / 1024.0));
                ui.end_row();
            }
        });
}
