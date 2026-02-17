use egui::{Color32, Ui};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const ACCENT_DIM: Color32 = Color32::from_rgb(0, 120, 150);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const RISK_HIGH: Color32 = Color32::from_rgb(255, 70, 70);
const RISK_MEDIUM: Color32 = Color32::from_rgb(255, 200, 50);
const RISK_LOW: Color32 = Color32::from_rgb(0, 200, 220);
const BG_DARK: Color32 = Color32::from_rgb(12, 12, 24);
const BORDER: Color32 = Color32::from_rgb(40, 45, 65);

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    if let Some(ref info) = result.file_info {
        ui.colored_label(ACCENT, egui::RichText::new("FILE INFO").size(14.0));
        ui.add_space(6.0);
        egui::Grid::new("file_info_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.colored_label(LABEL, "File:");
                ui.monospace(&info.name);
                ui.end_row();

                ui.colored_label(LABEL, "Size:");
                ui.monospace(format!("{} bytes ({:.2} KB)", info.size, info.size as f64 / 1024.0));
                ui.end_row();

                ui.colored_label(LABEL, "Type:");
                ui.colored_label(ACCENT_DIM, &info.pe_type);
                ui.end_row();
            });
    }

    if let Some(ref hashes) = result.hashes {
        ui.add_space(16.0);
        ui.colored_label(ACCENT, egui::RichText::new("HASHES").size(14.0));
        ui.add_space(6.0);
        egui::Grid::new("hashes_grid")
            .num_columns(3)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                hash_row(ui, "MD5:", &hashes.md5);
                hash_row(ui, "SHA1:", &hashes.sha1);
                hash_row(ui, "SHA256:", &hashes.sha256);
            });
    }

    if let Some(ref summary) = result.suspicious_summary {
        if summary.total_suspicious > 0 {
            ui.add_space(16.0);
            ui.colored_label(RISK_HIGH, egui::RichText::new("SUSPICIOUS API INDICATORS").size(14.0));
            ui.add_space(6.0);

            // Severity badges
            ui.horizontal(|ui| {
                severity_badge(ui, "HIGH", summary.high_count, RISK_HIGH);
                severity_badge(ui, "MED", summary.medium_count, RISK_MEDIUM);
                severity_badge(ui, "LOW", summary.low_count, RISK_LOW);
                ui.colored_label(LABEL, format!("({} total)", summary.total_suspicious));
            });
            ui.add_space(8.0);

            // Category breakdown
            egui::Frame::new()
                .fill(BG_DARK)
                .corner_radius(egui::CornerRadius::same(4))
                .stroke(egui::Stroke::new(0.5, BORDER))
                .inner_margin(egui::Margin::same(8))
                .show(ui, |ui| {
                    egui::Grid::new("suspicious_summary_grid")
                        .num_columns(2)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            for cat in &summary.categories {
                                ui.colored_label(ACCENT_DIM, &cat.category);
                                ui.colored_label(Color32::WHITE, format!("{}", cat.count));
                                ui.end_row();
                            }
                        });
                });
        }
    }

    if let Some(ref anomalies) = result.anomalies {
        if !anomalies.is_empty() {
            ui.add_space(16.0);
            ui.colored_label(RISK_HIGH, egui::RichText::new("ANOMALY DETECTION").size(14.0));
            ui.add_space(6.0);

            let critical = anomalies.iter().filter(|a| a.severity == "critical").count();
            let warning = anomalies.iter().filter(|a| a.severity == "warning").count();
            let info_count = anomalies.iter().filter(|a| a.severity == "info").count();

            ui.horizontal(|ui| {
                severity_badge(ui, "CRIT", critical, RISK_HIGH);
                severity_badge(ui, "WARN", warning, RISK_MEDIUM);
                severity_badge(ui, "INFO", info_count, RISK_LOW);
                ui.colored_label(LABEL, format!("({} total)", anomalies.len()));
            });
            ui.add_space(8.0);

            egui::Frame::new()
                .fill(BG_DARK)
                .corner_radius(egui::CornerRadius::same(4))
                .stroke(egui::Stroke::new(0.5, BORDER))
                .inner_margin(egui::Margin::same(8))
                .show(ui, |ui| {
                    egui::Grid::new("anomaly_grid")
                        .num_columns(3)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            for anomaly in anomalies {
                                let severity_color = match anomaly.severity.as_str() {
                                    "critical" => RISK_HIGH,
                                    "warning" => RISK_MEDIUM,
                                    "info" => RISK_LOW,
                                    _ => LABEL,
                                };
                                let badge = match anomaly.severity.as_str() {
                                    "critical" => "CRIT",
                                    "warning" => "WARN",
                                    "info" => "INFO",
                                    _ => "???",
                                };
                                ui.colored_label(severity_color, egui::RichText::new(badge).strong());
                                ui.colored_label(ACCENT_DIM, &anomaly.category);
                                ui.colored_label(Color32::from_rgb(200, 200, 210), &anomaly.description);
                                ui.end_row();
                            }
                        });
                });
        }
    }
}

fn severity_badge(ui: &mut Ui, label: &str, count: usize, color: Color32) {
    if count > 0 {
        let btn = egui::Button::new(
            egui::RichText::new(format!("{label}: {count}")).color(Color32::WHITE).strong(),
        )
        .fill(color.gamma_multiply(0.3))
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(egui::CornerRadius::same(4));
        ui.add(btn);
    }
}

fn hash_row(ui: &mut Ui, label: &str, value: &str) {
    ui.colored_label(LABEL, label);
    ui.monospace(value);
    let btn = egui::Button::new(
        egui::RichText::new("\u{2398}").color(Color32::WHITE),
    )
    .fill(Color32::from_rgb(0, 80, 110))
    .corner_radius(egui::CornerRadius::same(3))
    .min_size(egui::vec2(24.0, 18.0));
    if ui.add(btn).on_hover_text("Copy to clipboard").clicked() {
        ui.ctx().copy_text(value.to_string());
    }
    ui.end_row();
}
