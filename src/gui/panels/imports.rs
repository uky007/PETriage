use egui::Ui;

use crate::analysis::AnalysisResult;

pub struct ImportsState {
    pub filter: String,
    pub selected_dll: Option<usize>,
}

impl Default for ImportsState {
    fn default() -> Self {
        Self {
            filter: String::new(),
            selected_dll: None,
        }
    }
}

pub fn show(ui: &mut Ui, result: &AnalysisResult, state: &mut ImportsState) {
    let imports = match result.imports {
        Some(ref i) => i,
        None => {
            ui.label("No import data available. Enable 'Imports' in options and re-analyze.");
            return;
        }
    };

    let total_funcs: usize = imports.iter().map(|i| i.functions.len()).sum();
    ui.heading(format!("Imports ({} DLLs, {} functions)", imports.len(), total_funcs));
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut state.filter);
        if ui.small_button("Clear").clicked() {
            state.filter.clear();
        }
    });
    ui.add_space(4.0);

    let filter_lower = state.filter.to_lowercase();

    // Two-pane layout: DLL list on the left, functions on the right
    ui.columns(2, |cols| {
        // Left pane: DLL list
        egui::ScrollArea::vertical()
            .id_salt("dll_list")
            .show(&mut cols[0], |ui| {
                for (idx, imp) in imports.iter().enumerate() {
                    let matches_filter = filter_lower.is_empty()
                        || imp.dll.to_lowercase().contains(&filter_lower)
                        || imp.functions.iter().any(|f| f.to_lowercase().contains(&filter_lower));

                    if !matches_filter {
                        continue;
                    }

                    let selected = state.selected_dll == Some(idx);
                    let label = format!("{} ({})", imp.dll, imp.functions.len());
                    if ui.selectable_label(selected, &label).clicked() {
                        state.selected_dll = Some(idx);
                    }
                }
            });

        // Right pane: Functions for selected DLL
        egui::ScrollArea::vertical()
            .id_salt("func_list")
            .show(&mut cols[1], |ui| {
                if let Some(idx) = state.selected_dll {
                    if let Some(imp) = imports.get(idx) {
                        ui.strong(&imp.dll);
                        ui.add_space(4.0);
                        for func in &imp.functions {
                            let matches = filter_lower.is_empty()
                                || func.to_lowercase().contains(&filter_lower);
                            if matches {
                                ui.monospace(func);
                            }
                        }
                    }
                } else {
                    ui.label("Select a DLL from the left panel");
                }
            });
    });
}
