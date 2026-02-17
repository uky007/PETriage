use egui::{Color32, CornerRadius, Ui};
use egui_extras::{Column, TableBuilder};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const ACCENT_DIM: Color32 = Color32::from_rgb(0, 120, 150);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingFilter {
    All,
    Ascii,
    Utf16,
}

pub struct StringsState {
    pub filter: String,
    pub encoding_filter: EncodingFilter,
}

impl Default for StringsState {
    fn default() -> Self {
        Self {
            filter: String::new(),
            encoding_filter: EncodingFilter::All,
        }
    }
}

pub fn show(ui: &mut Ui, result: &AnalysisResult, state: &mut StringsState) {
    let strings = match result.strings {
        Some(ref s) => s,
        None => {
            ui.colored_label(LABEL, "No string data available. Enable 'Strings' in options and re-analyze.");
            return;
        }
    };

    ui.colored_label(ACCENT, egui::RichText::new(format!("STRINGS ({})", strings.len())).size(14.0));
    ui.add_space(6.0);

    // Filter bar
    ui.horizontal(|ui| {
        ui.colored_label(LABEL, "\u{1f50d}");
        ui.add(
            egui::TextEdit::singleline(&mut state.filter)
                .hint_text("Filter strings...")
                .desired_width(250.0),
        );
        if !state.filter.is_empty() {
            if ui.small_button("\u{2715}").clicked() {
                state.filter.clear();
            }
        }
        ui.separator();
        ui.colored_label(LABEL, "Encoding:");
        let enc_btn = |val: EncodingFilter, label: &str, current: &mut EncodingFilter, ui: &mut Ui| {
            let selected = *current == val;
            let text = egui::RichText::new(label)
                .color(if selected { ACCENT } else { LABEL });
            let btn = egui::Button::new(text)
                .fill(if selected { Color32::from_rgb(0, 60, 90) } else { Color32::TRANSPARENT })
                .stroke(if selected {
                    egui::Stroke::new(1.0, ACCENT_DIM)
                } else {
                    egui::Stroke::NONE
                })
                .corner_radius(CornerRadius::same(3));
            if ui.add(btn).clicked() {
                *current = val;
            }
        };
        enc_btn(EncodingFilter::All, "All", &mut state.encoding_filter, ui);
        enc_btn(EncodingFilter::Ascii, "ASCII", &mut state.encoding_filter, ui);
        enc_btn(EncodingFilter::Utf16, "UTF-16", &mut state.encoding_filter, ui);
    });
    ui.add_space(4.0);

    let filter_lower = state.filter.to_lowercase();

    let filtered: Vec<_> = strings
        .iter()
        .filter(|s| {
            let enc_ok = match state.encoding_filter {
                EncodingFilter::All => true,
                EncodingFilter::Ascii => s.encoding == "ASCII",
                EncodingFilter::Utf16 => s.encoding == "UTF-16LE",
            };
            let text_ok = filter_lower.is_empty()
                || s.value.to_lowercase().contains(&filter_lower);
            enc_ok && text_ok
        })
        .collect();

    ui.colored_label(LABEL, format!("Showing {} of {} strings", filtered.len(), strings.len()));
    ui.add_space(4.0);

    let available = ui.available_size();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .min_scrolled_height(0.0)
        .max_scroll_height(available.y)
        .column(Column::auto().at_least(100.0))
        .column(Column::auto().at_least(70.0))
        .column(Column::remainder())
        .header(20.0, |mut header| {
            header.col(|ui| { ui.colored_label(LABEL, "Offset"); });
            header.col(|ui| { ui.colored_label(LABEL, "Encoding"); });
            header.col(|ui| { ui.colored_label(LABEL, "Value"); });
        })
        .body(|body| {
            body.rows(20.0, filtered.len(), |mut row| {
                let s = &filtered[row.index()];
                row.col(|ui| { ui.monospace(format!("{:#010x}", s.offset)); });
                row.col(|ui| {
                    let color = if s.encoding == "UTF-16LE" { ACCENT_DIM } else { LABEL };
                    ui.colored_label(color, &s.encoding);
                });
                row.col(|ui| { ui.monospace(&s.value); });
            });
        });
}
