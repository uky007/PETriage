use egui::{Color32, Ui};
use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const ACCENT_DIM: Color32 = Color32::from_rgb(0, 120, 150);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const BG_DARK: Color32 = Color32::from_rgb(12, 12, 24);
const BORDER: Color32 = Color32::from_rgb(40, 45, 65);

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    // Build Fingerprint section
    if let Some(ref fp) = result.build_fingerprint {
        ui.colored_label(ACCENT, egui::RichText::new("BUILD FINGERPRINT").size(14.0));
        ui.add_space(6.0);
        egui::Frame::new()
            .fill(BG_DARK)
            .corner_radius(egui::CornerRadius::same(4))
            .stroke(egui::Stroke::new(0.5, BORDER))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                egui::Grid::new("build_fp_grid")
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        ui.colored_label(LABEL, "Compiler:");
                        ui.monospace(&fp.compiler);
                        ui.end_row();
                        if let Some(ref ver) = fp.compiler_version {
                            ui.colored_label(LABEL, "Version:");
                            ui.monospace(ver);
                            ui.end_row();
                        }
                        ui.colored_label(LABEL, "Managed:");
                        ui.monospace(if fp.is_managed { "Yes" } else { "No" });
                        ui.end_row();
                        ui.colored_label(LABEL, "Confidence:");
                        ui.monospace(format!("{:.0}%", fp.confidence * 100.0));
                        ui.end_row();
                    });
            });
        ui.add_space(12.0);
    }

    // .NET section
    if let Some(ref dn) = result.dotnet {
        ui.colored_label(ACCENT, egui::RichText::new(".NET METADATA").size(14.0));
        ui.add_space(6.0);
        egui::Frame::new()
            .fill(BG_DARK)
            .corner_radius(egui::CornerRadius::same(4))
            .stroke(egui::Stroke::new(0.5, BORDER))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                egui::Grid::new("dotnet_grid")
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        ui.colored_label(LABEL, "Runtime:");
                        ui.monospace(&dn.runtime_version);
                        ui.end_row();
                        if let Some(ref name) = dn.assembly_name {
                            ui.colored_label(LABEL, "Assembly:");
                            ui.monospace(name);
                            ui.end_row();
                        }
                        if let Some(ref ver) = dn.assembly_version {
                            ui.colored_label(LABEL, "Version:");
                            ui.monospace(ver);
                            ui.end_row();
                        }
                        if !dn.flags.is_empty() {
                            ui.colored_label(LABEL, "Flags:");
                            ui.monospace(dn.flags.join(", "));
                            ui.end_row();
                        }
                    });
                if !dn.references.is_empty() {
                    ui.add_space(8.0);
                    ui.colored_label(ACCENT_DIM, format!("Assembly References ({})", dn.references.len()));
                    ui.add_space(4.0);
                    for r in &dn.references {
                        ui.monospace(format!("  {}", r));
                    }
                }
            });
        ui.add_space(12.0);
    }

    // Go section
    if let Some(ref go) = result.go {
        ui.colored_label(ACCENT, egui::RichText::new("GO BUILD INFO").size(14.0));
        ui.add_space(6.0);
        egui::Frame::new()
            .fill(BG_DARK)
            .corner_radius(egui::CornerRadius::same(4))
            .stroke(egui::Stroke::new(0.5, BORDER))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                egui::Grid::new("go_grid")
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        if let Some(ref bid) = go.build_id {
                            ui.colored_label(LABEL, "Build ID:");
                            ui.monospace(bid);
                            ui.end_row();
                        }
                        ui.colored_label(LABEL, "Confidence:");
                        ui.monospace(format!("{:.0}%", go.confidence * 100.0));
                        ui.end_row();
                        ui.colored_label(LABEL, "Markers:");
                        ui.monospace(go.markers.join(", "));
                        ui.end_row();
                    });
            });
        ui.add_space(12.0);
    }

    if result.build_fingerprint.is_none() && result.dotnet.is_none() && result.go.is_none() {
        ui.colored_label(LABEL, "No build fingerprint or runtime metadata detected.");
    }
}
