use egui::{Color32, Ui};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const WARNING: Color32 = Color32::from_rgb(230, 190, 50);
const SUCCESS: Color32 = Color32::from_rgb(80, 200, 120);

pub fn show(ui: &mut Ui, result: &AnalysisResult, data: &[u8], save_message: &mut Option<String>) {
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

                if let Some(ref classes) = overlay.classification {
                    for c in classes {
                        ui.colored_label(LABEL, "Format:");
                        ui.monospace(format!("{} (confidence: {:.0}%)", c.format, c.confidence * 100.0));
                        ui.end_row();
                    }
                }
            }
        });

    if overlay.present {
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Save Overlay...").clicked() {
                let default_ext = overlay.classification.as_ref()
                    .and_then(|cs| cs.first())
                    .map(|c| match c.format.as_str() {
                        "ZIP" => "zip",
                        "RAR" => "rar",
                        "7z" => "7z",
                        "CAB" => "cab",
                        "PE" => "exe",
                        "PDF" => "pdf",
                        "GZIP" => "gz",
                        "XZ" => "xz",
                        _ => "bin",
                    })
                    .unwrap_or("bin");

                let dialog = rfd::FileDialog::new()
                    .set_file_name(format!("overlay.{}", default_ext))
                    .add_filter("All files", &["*"]);
                if let Some(path) = dialog.save_file() {
                    let overlay_bytes = &data[overlay.offset..overlay.offset + overlay.size];
                    match std::fs::write(&path, overlay_bytes) {
                        Ok(()) => *save_message = Some(format!("Overlay saved: {} bytes → {}", overlay.size, path.display())),
                        Err(e) => *save_message = Some(format!("Error: {}", e)),
                    }
                }
            }

            if ui.button("Save PE without Overlay...").clicked() {
                let dialog = rfd::FileDialog::new()
                    .set_file_name("stripped.exe")
                    .add_filter("PE files", &["exe", "dll", "sys", "ocx", "scr"])
                    .add_filter("All files", &["*"]);
                if let Some(path) = dialog.save_file() {
                    let stripped = &data[..overlay.offset];
                    match std::fs::write(&path, stripped) {
                        Ok(()) => *save_message = Some(format!("Stripped PE saved: {} bytes → {} (removed {} bytes)", overlay.offset, path.display(), overlay.size)),
                        Err(e) => *save_message = Some(format!("Error: {}", e)),
                    }
                }
            }
        });

        if let Some(msg) = save_message.as_ref() {
            ui.add_space(4.0);
            let color = if msg.starts_with("Error") { WARNING } else { SUCCESS };
            ui.colored_label(color, msg);
        }
    }
}
