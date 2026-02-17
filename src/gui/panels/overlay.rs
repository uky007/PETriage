use egui::Ui;

use crate::analysis::AnalysisResult;

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let overlay = match result.overlay {
        Some(ref o) => o,
        None => {
            ui.label("No overlay data available. Enable 'Overlay' in options and re-analyze.");
            return;
        }
    };

    ui.heading("Overlay");
    ui.add_space(4.0);

    egui::Grid::new("overlay_grid")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            ui.strong("Present:");
            ui.label(if overlay.present { "Yes" } else { "No" });
            ui.end_row();

            if overlay.present {
                ui.strong("Offset:");
                ui.monospace(format!("{:#x}", overlay.offset));
                ui.end_row();

                ui.strong("Size:");
                ui.label(format!("{} bytes ({:.2} KB)", overlay.size, overlay.size as f64 / 1024.0));
                ui.end_row();
            }
        });
}
