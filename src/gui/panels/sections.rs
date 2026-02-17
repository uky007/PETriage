use egui::{Color32, Ui};
use egui_extras::{Column, TableBuilder};

use crate::analysis::AnalysisResult;

fn entropy_color(entropy: f64) -> Color32 {
    if entropy < 6.0 {
        Color32::from_rgb(100, 200, 100) // green — normal
    } else if entropy < 7.0 {
        Color32::from_rgb(230, 200, 50) // yellow — suspicious
    } else {
        Color32::from_rgb(230, 80, 80) // red — packed/encrypted
    }
}

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let sections = match result.sections {
        Some(ref s) => s,
        None => {
            ui.label("No section data available. Enable 'Sections' in options and re-analyze.");
            return;
        }
    };

    ui.heading(format!("Sections ({})", sections.len()));
    ui.add_space(4.0);

    let available = ui.available_size();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .min_scrolled_height(0.0)
        .max_scroll_height(available.y)
        .column(Column::auto().at_least(80.0)) // Name
        .column(Column::auto().at_least(90.0)) // VirtSize
        .column(Column::auto().at_least(100.0)) // VirtAddr
        .column(Column::auto().at_least(90.0)) // RawSize
        .column(Column::auto().at_least(100.0)) // RawAddr
        .column(Column::auto().at_least(70.0)) // Entropy
        .column(Column::remainder()) // Characteristics
        .header(18.0, |mut header| {
            header.col(|ui| { ui.strong("Name"); });
            header.col(|ui| { ui.strong("VirtSize"); });
            header.col(|ui| { ui.strong("VirtAddr"); });
            header.col(|ui| { ui.strong("RawSize"); });
            header.col(|ui| { ui.strong("RawAddr"); });
            header.col(|ui| { ui.strong("Entropy"); });
            header.col(|ui| { ui.strong("Characteristics"); });
        })
        .body(|mut body| {
            for sec in sections {
                body.row(18.0, |mut row| {
                    row.col(|ui| { ui.monospace(&sec.name); });
                    row.col(|ui| { ui.monospace(format!("{:#010x}", sec.virtual_size)); });
                    row.col(|ui| { ui.monospace(format!("{:#010x}", sec.virtual_address)); });
                    row.col(|ui| { ui.monospace(format!("{:#010x}", sec.raw_size)); });
                    row.col(|ui| { ui.monospace(format!("{:#010x}", sec.raw_address)); });
                    row.col(|ui| {
                        let color = entropy_color(sec.entropy);
                        ui.colored_label(color, format!("{:.4}", sec.entropy));
                    });
                    row.col(|ui| { ui.monospace(sec.characteristics_str.join(" | ")); });
                });
            }
        });
}
