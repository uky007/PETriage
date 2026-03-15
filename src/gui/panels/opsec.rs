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
    let opsec = match result.opsec {
        Some(ref o) => o,
        None => {
            ui.colored_label(LABEL, "No OPSEC findings detected in this PE file.");
            ui.add_space(8.0);
            ui.colored_label(LABEL, "Tip: OPSEC findings include PDB path analysis, version metadata mismatches,");
            ui.colored_label(LABEL, "credential patterns, endpoint detection, and Rich Header integrity checks.");
            return;
        }
    };

    ui.colored_label(ACCENT, egui::RichText::new("OPSEC ANALYSIS").size(14.0));
    ui.add_space(6.0);

    // Summary badges
    let crit = opsec.findings.iter().filter(|f| f.severity == "critical").count();
    let warn = opsec.findings.iter().filter(|f| f.severity == "warning").count();
    let info = opsec.findings.iter().filter(|f| f.severity == "info").count();

    ui.horizontal(|ui| {
        severity_badge(ui, "CRIT", crit, RISK_HIGH);
        severity_badge(ui, "WARN", warn, RISK_MEDIUM);
        severity_badge(ui, "INFO", info, RISK_LOW);
        ui.colored_label(LABEL, format!("({} total findings)", opsec.summary.finding_count));
    });
    ui.add_space(8.0);

    // Type breakdown
    if !opsec.summary.types.is_empty() {
        egui::Frame::new()
            .fill(BG_DARK)
            .corner_radius(egui::CornerRadius::same(4))
            .stroke(egui::Stroke::new(0.5, BORDER))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.colored_label(ACCENT_DIM, egui::RichText::new("Finding Types").size(12.0));
                ui.add_space(4.0);
                egui::Grid::new("opsec_types_grid")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        for (t, c) in &opsec.summary.types {
                            ui.colored_label(LABEL, t);
                            ui.colored_label(Color32::WHITE, format!("{}", c));
                            ui.end_row();
                        }
                    });
            });
        ui.add_space(12.0);
    }

    // Individual findings grouped by type
    let type_order = ["pdb_path", "nulled_pdb", "version_mismatch", "vendor_mismatch",
                      "credential", "endpoint", "source_path_leak", "ci_cd_trace",
                      "rich_header"];

    for finding_type in &type_order {
        let group: Vec<_> = opsec.findings.iter()
            .filter(|f| f.finding_type == *finding_type)
            .collect();
        if group.is_empty() { continue; }

        let type_label = match *finding_type {
            "pdb_path" => "PDB Path Classification",
            "nulled_pdb" => "Nulled PDB Path",
            "version_mismatch" => "Version Metadata Mismatch",
            "vendor_mismatch" => "Vendor Masquerading",
            "credential" => "Credential Patterns",
            "endpoint" => "Network Endpoints",
            "rich_header" => "Rich Header Integrity",
            "source_path_leak" => "Source Path Username Leak",
            "ci_cd_trace" => "CI/CD Build Trace",
            other => other,
        };

        ui.colored_label(RISK_MEDIUM, egui::RichText::new(type_label.to_ascii_uppercase()).size(12.0));
        ui.add_space(4.0);

        for finding in &group {
            let severity_color = match finding.severity.as_str() {
                "critical" => RISK_HIGH,
                "warning" => RISK_MEDIUM,
                "info" => RISK_LOW,
                _ => LABEL,
            };
            let frame_bg = severity_color.gamma_multiply(0.1);

            egui::Frame::new()
                .fill(frame_bg)
                .corner_radius(egui::CornerRadius::same(4))
                .stroke(egui::Stroke::new(0.5, severity_color.gamma_multiply(0.4)))
                .inner_margin(egui::Margin::same(8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let badge = match finding.severity.as_str() {
                            "critical" => "CRIT",
                            "warning" => "WARN",
                            "info" => "INFO",
                            _ => "???",
                        };
                        ui.colored_label(severity_color, egui::RichText::new(
                            format!("[{}] {}", finding.id, badge)).strong());
                        ui.colored_label(LABEL, format!("confidence: {:.0}%", finding.confidence * 100.0));
                    });
                    ui.add_space(2.0);
                    ui.colored_label(Color32::from_rgb(200, 200, 210), &finding.description);

                    if !finding.evidence.is_empty() {
                        ui.add_space(4.0);
                        egui::Grid::new(format!("opsec_evidence_{}_{}", finding.id,
                            finding.evidence.values().next().unwrap_or(&String::new())))
                            .num_columns(2)
                            .spacing([12.0, 2.0])
                            .show(ui, |ui| {
                                for (k, v) in &finding.evidence {
                                    ui.colored_label(LABEL, format!("{}:", k));
                                    ui.label(egui::RichText::new(v).color(Color32::WHITE).monospace());
                                    ui.end_row();
                                }
                            });
                    }
                });
            ui.add_space(4.0);
        }
        ui.add_space(8.0);
    }

    // Show any findings with types not in type_order
    let other_findings: Vec<_> = opsec.findings.iter()
        .filter(|f| !type_order.contains(&f.finding_type.as_str()))
        .collect();
    if !other_findings.is_empty() {
        ui.colored_label(RISK_MEDIUM, egui::RichText::new("OTHER").size(12.0));
        ui.add_space(4.0);
        for finding in &other_findings {
            ui.colored_label(LABEL, &finding.description);
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
