use egui::Ui;
use egui_extras::{Column, TableBuilder};

use crate::analysis::AnalysisResult;

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
            ui.label("No string data available. Enable 'Strings' in options and re-analyze.");
            return;
        }
    };

    ui.heading(format!("Strings ({})", strings.len()));
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut state.filter);
        if ui.small_button("Clear").clicked() {
            state.filter.clear();
        }
        ui.separator();
        ui.label("Encoding:");
        ui.selectable_value(&mut state.encoding_filter, EncodingFilter::All, "All");
        ui.selectable_value(&mut state.encoding_filter, EncodingFilter::Ascii, "ASCII");
        ui.selectable_value(&mut state.encoding_filter, EncodingFilter::Utf16, "UTF-16");
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

    ui.label(format!("Showing {} of {} strings", filtered.len(), strings.len()));
    ui.add_space(4.0);

    let available = ui.available_size();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .min_scrolled_height(0.0)
        .max_scroll_height(available.y)
        .column(Column::auto().at_least(100.0)) // Offset
        .column(Column::auto().at_least(70.0)) // Encoding
        .column(Column::remainder()) // Value
        .header(18.0, |mut header| {
            header.col(|ui| { ui.strong("Offset"); });
            header.col(|ui| { ui.strong("Encoding"); });
            header.col(|ui| { ui.strong("Value"); });
        })
        .body(|body| {
            body.rows(18.0, filtered.len(), |mut row| {
                let s = &filtered[row.index()];
                row.col(|ui| { ui.monospace(format!("{:#010x}", s.offset)); });
                row.col(|ui| { ui.monospace(&s.encoding); });
                row.col(|ui| { ui.monospace(&s.value); });
            });
        });
}
