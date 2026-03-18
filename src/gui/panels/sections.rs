use egui::{Color32, Ui};
use egui_extras::{Column, TableBuilder};

use crate::analysis::{self, AnalysisResult};

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const NONSTANDARD_BG: Color32 = Color32::from_rgb(100, 85, 0);

fn entropy_color(entropy: f64) -> Color32 {
    if entropy < 6.0 {
        Color32::from_rgb(80, 200, 120) // green — normal
    } else if entropy < 7.0 {
        Color32::from_rgb(230, 190, 50) // yellow — suspicious
    } else {
        Color32::from_rgb(255, 70, 70) // red — packed/encrypted
    }
}

pub fn show(ui: &mut Ui, result: &AnalysisResult) {
    let sections = match result.sections {
        Some(ref s) => s,
        None => {
            ui.colored_label(LABEL, "No section data available. Enable 'Sections' in options and re-analyze.");
            return;
        }
    };

    ui.colored_label(ACCENT, egui::RichText::new(format!("SECTIONS ({})", sections.len())).size(14.0));
    ui.add_space(6.0);

    let available = ui.available_size();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .min_scrolled_height(0.0)
        .max_scroll_height(available.y)
        .column(Column::auto().at_least(80.0))
        .column(Column::auto().at_least(90.0))
        .column(Column::auto().at_least(100.0))
        .column(Column::auto().at_least(90.0))
        .column(Column::auto().at_least(100.0))
        .column(Column::auto().at_least(70.0))
        .column(Column::remainder())
        .header(20.0, |mut header| {
            header.col(|ui| { ui.colored_label(LABEL, "Name"); });
            header.col(|ui| { ui.colored_label(LABEL, "VirtSize"); });
            header.col(|ui| { ui.colored_label(LABEL, "VirtAddr"); });
            header.col(|ui| { ui.colored_label(LABEL, "RawSize"); });
            header.col(|ui| { ui.colored_label(LABEL, "RawAddr"); });
            header.col(|ui| { ui.colored_label(LABEL, "Entropy"); });
            header.col(|ui| { ui.colored_label(LABEL, "Characteristics"); });
        })
        .body(|mut body| {
            for sec in sections {
                body.row(20.0, |mut row| {
                    row.col(|ui| {
                        if analysis::is_standard_section_name(&sec.name) {
                            ui.strong(&sec.name);
                        } else {
                            egui::Frame::new()
                                .fill(NONSTANDARD_BG)
                                .inner_margin(egui::Margin::symmetric(4, 1))
                                .corner_radius(2)
                                .show(ui, |ui| {
                                    ui.strong(egui::RichText::new(&sec.name).color(Color32::WHITE));
                                });
                        }
                    });
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
