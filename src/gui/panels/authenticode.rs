use egui::{Color32, Ui};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const SUCCESS: Color32 = Color32::from_rgb(80, 200, 120);
const WARNING: Color32 = Color32::from_rgb(230, 190, 50);
const ERROR_RED: Color32 = Color32::from_rgb(255, 70, 70);

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let auth = match result.authenticode {
        Some(ref a) => a,
        None => {
            ui.colored_label(LABEL, "No Authenticode data available. Enable 'Authenticode' in options and re-analyze.");
            return;
        }
    };

    ui.colored_label(ACCENT, egui::RichText::new("AUTHENTICODE / CODE SIGNING").size(14.0));
    ui.add_space(6.0);

    // Status grid
    egui::Grid::new("auth_status_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.colored_label(LABEL, "Signed:");
            if auth.signed {
                ui.colored_label(SUCCESS, "Yes");
            } else {
                ui.colored_label(ERROR_RED, "No");
            }
            ui.end_row();

            ui.colored_label(LABEL, "Parse OK:");
            if auth.parse_ok {
                ui.colored_label(SUCCESS, "Yes");
            } else {
                ui.colored_label(ERROR_RED, "No");
            }
            ui.end_row();

            ui.colored_label(LABEL, "Trust Verified:");
            ui.colored_label(LABEL, "No (not implemented)");
            ui.end_row();
        });

    // WIN_CERTIFICATE info
    if let Some(ref wc) = auth.win_certificate {
        ui.add_space(12.0);
        ui.colored_label(ACCENT, egui::RichText::new("WIN_CERTIFICATE").size(13.0));
        ui.add_space(4.0);
        egui::Grid::new("win_cert_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.colored_label(LABEL, "Length:");
                ui.monospace(format!("{} bytes", wc.length));
                ui.end_row();

                ui.colored_label(LABEL, "Revision:");
                ui.monospace(format!("{} ({:#06x})", wc.revision, wc.revision_raw));
                ui.end_row();

                ui.colored_label(LABEL, "Type:");
                ui.monospace(format!("{} ({:#06x})", wc.certificate_type, wc.certificate_type_raw));
                ui.end_row();
            });
    }

    // Signer
    if let Some(ref signer) = auth.signer {
        ui.add_space(12.0);
        ui.colored_label(ACCENT, egui::RichText::new("SIGNER").size(13.0));
        ui.add_space(4.0);
        show_cert_grid(ui, "signer_grid", signer);
    }

    // Certificate chain
    if !auth.certificates.is_empty() {
        ui.add_space(12.0);
        ui.colored_label(ACCENT, egui::RichText::new(
            format!("CERTIFICATE CHAIN ({} certificates)", auth.certificates.len())
        ).size(13.0));
        ui.add_space(4.0);

        for (i, cert) in auth.certificates.iter().enumerate() {
            let label = if cert.is_signer {
                format!("[{}] {} (signer)", i, cert.subject)
            } else {
                format!("[{}] {}", i, cert.subject)
            };
            egui::CollapsingHeader::new(egui::RichText::new(label).color(if cert.is_signer { ACCENT } else { Color32::from_rgb(220, 225, 235) }))
                .id_salt(format!("cert_{}", i))
                .show(ui, |ui| {
                    show_cert_grid(ui, &format!("cert_grid_{}", i), cert);
                });
        }
    }

    // Warnings
    if !auth.warnings.is_empty() {
        ui.add_space(12.0);
        ui.colored_label(WARNING, egui::RichText::new("WARNINGS").size(13.0));
        ui.add_space(4.0);
        for w in &auth.warnings {
            ui.horizontal(|ui| {
                ui.colored_label(WARNING, "!");
                ui.label(w);
            });
        }
    }
}

fn show_cert_grid(ui: &mut Ui, id: &str, cert: &crate::analysis::CertificateEntry) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.colored_label(LABEL, "Subject:");
            ui.monospace(&cert.subject);
            ui.end_row();

            ui.colored_label(LABEL, "Issuer:");
            ui.monospace(&cert.issuer);
            ui.end_row();

            ui.colored_label(LABEL, "Serial:");
            ui.monospace(&cert.serial);
            ui.end_row();

            ui.colored_label(LABEL, "Not Before:");
            ui.monospace(&cert.not_before);
            ui.end_row();

            ui.colored_label(LABEL, "Not After:");
            ui.monospace(&cert.not_after);
            ui.end_row();

            ui.colored_label(LABEL, "Thumbprint (SHA-1):");
            ui.monospace(&cert.thumbprint_sha1);
            ui.end_row();
        });
}
