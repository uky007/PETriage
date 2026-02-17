use egui::Ui;
use egui_extras::{Column, TableBuilder};

use crate::analysis::AnalysisResult;

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let exports = match result.exports {
        Some(ref e) => e,
        None => {
            ui.label("No export data available. Enable 'Exports' in options and re-analyze.");
            return;
        }
    };

    if exports.is_empty() {
        ui.label("This PE file has no exports.");
        return;
    }

    ui.heading(format!("Exports ({})", exports.len()));
    ui.add_space(4.0);

    let available = ui.available_size();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .min_scrolled_height(0.0)
        .max_scroll_height(available.y)
        .column(Column::auto().at_least(60.0)) // Ordinal
        .column(Column::auto().at_least(100.0)) // RVA
        .column(Column::remainder()) // Name
        .header(18.0, |mut header| {
            header.col(|ui| { ui.strong("Ordinal"); });
            header.col(|ui| { ui.strong("RVA"); });
            header.col(|ui| { ui.strong("Name"); });
        })
        .body(|mut body| {
            for exp in exports {
                body.row(18.0, |mut row| {
                    row.col(|ui| { ui.monospace(exp.ordinal.to_string()); });
                    row.col(|ui| { ui.monospace(format!("{:#010x}", exp.rva)); });
                    row.col(|ui| { ui.monospace(&exp.name); });
                });
            }
        });
}
