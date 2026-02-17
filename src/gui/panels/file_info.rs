use egui::Ui;

use crate::analysis::AnalysisResult;

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    if let Some(ref info) = result.file_info {
        ui.heading("File Info");
        ui.add_space(4.0);
        egui::Grid::new("file_info_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.strong("File:");
                ui.label(&info.name);
                ui.end_row();

                ui.strong("Size:");
                ui.label(format!("{} bytes ({:.2} KB)", info.size, info.size as f64 / 1024.0));
                ui.end_row();

                ui.strong("Type:");
                ui.label(&info.pe_type);
                ui.end_row();
            });
    }

    if let Some(ref hashes) = result.hashes {
        ui.add_space(12.0);
        ui.heading("Hashes");
        ui.add_space(4.0);
        egui::Grid::new("hashes_grid")
            .num_columns(3)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                hash_row(ui, "MD5:", &hashes.md5);
                hash_row(ui, "SHA1:", &hashes.sha1);
                hash_row(ui, "SHA256:", &hashes.sha256);
            });
    }
}

fn hash_row(ui: &mut Ui, label: &str, value: &str) {
    ui.strong(label);
    ui.monospace(value);
    if ui.small_button("Copy").clicked() {
        ui.ctx().copy_text(value.to_string());
    }
    ui.end_row();
}
