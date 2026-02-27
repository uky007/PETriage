use egui::{Color32, Ui};
use egui_extras::{Column, TableBuilder};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const GREEN: Color32 = Color32::from_rgb(80, 200, 80);
const RED: Color32 = Color32::from_rgb(220, 80, 80);

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let rich = match result.rich_header {
        Some(ref r) => r,
        None => {
            ui.colored_label(LABEL, "No Rich Header found in this PE file.");
            return;
        }
    };

    ui.colored_label(ACCENT, egui::RichText::new("RICH HEADER").size(14.0));
    ui.add_space(6.0);

    egui::Grid::new("rich_header_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.colored_label(LABEL, "XOR Key:");
            ui.monospace(&rich.xor_key);
            ui.end_row();

            if let Some(ref hash) = rich.rich_hash {
                ui.colored_label(LABEL, "Rich Hash:");
                ui.monospace(hash);
                ui.end_row();
            }

            ui.colored_label(LABEL, "Checksum:");
            if rich.checksum_valid {
                ui.colored_label(GREEN, "Valid");
            } else {
                ui.colored_label(RED, "Invalid");
            }
            ui.end_row();

            ui.colored_label(LABEL, "Entries:");
            ui.monospace(rich.entries.len().to_string());
            ui.end_row();
        });

    if rich.entries.is_empty() {
        return;
    }

    ui.add_space(10.0);
    ui.colored_label(ACCENT, egui::RichText::new("TOOL ENTRIES").size(12.0));
    ui.add_space(4.0);

    let available = ui.available_size();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .min_scrolled_height(0.0)
        .max_scroll_height(available.y)
        .column(Column::auto().at_least(100.0))
        .column(Column::auto().at_least(60.0))
        .column(Column::auto().at_least(70.0))
        .column(Column::auto().at_least(60.0))
        .column(Column::remainder())
        .header(20.0, |mut header| {
            header.col(|ui| { ui.colored_label(LABEL, "CompID"); });
            header.col(|ui| { ui.colored_label(LABEL, "ProdID"); });
            header.col(|ui| { ui.colored_label(LABEL, "BuildID"); });
            header.col(|ui| { ui.colored_label(LABEL, "Count"); });
            header.col(|ui| { ui.colored_label(LABEL, "Description"); });
        })
        .body(|mut body| {
            for entry in &rich.entries {
                body.row(20.0, |mut row| {
                    row.col(|ui| { ui.monospace(&entry.comp_id); });
                    row.col(|ui| { ui.monospace(entry.prod_id.to_string()); });
                    row.col(|ui| { ui.monospace(entry.build_id.to_string()); });
                    row.col(|ui| { ui.monospace(entry.count.to_string()); });
                    row.col(|ui| {
                        ui.monospace(entry.description.as_deref().unwrap_or(""));
                    });
                });
            }
        });
}
