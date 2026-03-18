use egui::{Color32, Ui};
use egui_extras::{Column, TableBuilder};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const ANOMALY_BG: Color32 = Color32::from_rgb(120, 20, 20);

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let exports = match result.exports {
        Some(ref e) => e,
        None => {
            ui.colored_label(LABEL, "No export data available. Enable 'Exports' in options and re-analyze.");
            return;
        }
    };

    if exports.is_empty() {
        ui.colored_label(LABEL, "This PE file has no exports.");
        return;
    }

    ui.colored_label(ACCENT, egui::RichText::new(format!("EXPORTS ({})", exports.len())).size(14.0));
    ui.add_space(6.0);

    // Export Directory info
    if let Some(ref ed) = result.export_directory {
        egui::Grid::new("export_dir_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.colored_label(LABEL, "DLL Name:");
                ui.monospace(&ed.dll_name);
                ui.end_row();

                ui.colored_label(LABEL, "Timestamp:");
                if ed.timestamp_anomaly {
                    let frame = egui::Frame::new()
                        .fill(ANOMALY_BG)
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .corner_radius(2);
                    frame.show(ui, |ui| {
                        ui.monospace(
                            egui::RichText::new(format!("{:#010x} ({})", ed.timestamp, ed.timestamp_str))
                                .color(Color32::WHITE),
                        );
                    });
                } else {
                    ui.monospace(format!("{:#010x} ({})", ed.timestamp, ed.timestamp_str));
                }
                ui.end_row();

                ui.colored_label(LABEL, "Functions:");
                ui.monospace(format!("{}  Names: {}  OrdinalBase: {}",
                    ed.number_of_functions, ed.number_of_names, ed.ordinal_base));
                ui.end_row();
            });
        ui.add_space(8.0);
    }

    let available = ui.available_size();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .min_scrolled_height(0.0)
        .max_scroll_height(available.y)
        .column(Column::auto().at_least(60.0))
        .column(Column::auto().at_least(100.0))
        .column(Column::remainder())
        .header(20.0, |mut header| {
            header.col(|ui| { ui.colored_label(LABEL, "Ordinal"); });
            header.col(|ui| { ui.colored_label(LABEL, "RVA"); });
            header.col(|ui| { ui.colored_label(LABEL, "Name"); });
        })
        .body(|mut body| {
            for exp in exports {
                body.row(20.0, |mut row| {
                    row.col(|ui| { ui.monospace(exp.ordinal.to_string()); });
                    row.col(|ui| { ui.monospace(format!("{:#010x}", exp.rva)); });
                    row.col(|ui| { ui.monospace(&exp.name); });
                });
            }
        });
}
