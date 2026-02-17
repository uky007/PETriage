use egui::{Color32, Ui};
use egui_extras::{Column, TableBuilder};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);

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
