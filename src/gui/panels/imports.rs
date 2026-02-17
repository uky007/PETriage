use egui::{Color32, CornerRadius, Margin, Ui};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const ACCENT_DIM: Color32 = Color32::from_rgb(0, 120, 150);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const BG_DARK: Color32 = Color32::from_rgb(12, 12, 24);
const BORDER: Color32 = Color32::from_rgb(40, 45, 65);
const HIGHLIGHT: Color32 = Color32::from_rgb(255, 220, 80);

const RISK_HIGH: Color32 = Color32::from_rgb(255, 70, 70);
const RISK_MEDIUM: Color32 = Color32::from_rgb(255, 200, 50);
const RISK_LOW: Color32 = Color32::from_rgb(0, 200, 220);

pub struct ImportsState {
    pub filter: String,
    pub selected_dll: Option<usize>,
    pub show_suspicious_only: bool,
}

impl Default for ImportsState {
    fn default() -> Self {
        Self {
            filter: String::new(),
            selected_dll: None,
            show_suspicious_only: false,
        }
    }
}

pub fn show(ui: &mut Ui, result: &AnalysisResult, state: &mut ImportsState) {
    let imports = match result.imports {
        Some(ref i) => i,
        None => {
            ui.colored_label(LABEL, "No import data available. Enable 'Imports' in options and re-analyze.");
            return;
        }
    };

    let total_funcs: usize = imports.iter().map(|i| i.functions.len()).sum();
    ui.colored_label(ACCENT, egui::RichText::new(
        format!("IMPORTS ({} DLLs, {} functions)", imports.len(), total_funcs),
    ).size(14.0));
    ui.add_space(6.0);

    // Filter bar
    ui.horizontal(|ui| {
        ui.colored_label(LABEL, "\u{1f50d}");
        ui.add(
            egui::TextEdit::singleline(&mut state.filter)
                .hint_text("Filter APIs...")
                .desired_width(250.0),
        );
        if !state.filter.is_empty() {
            if ui.small_button("\u{2715}").clicked() {
                state.filter.clear();
            }
        }
        ui.separator();
        ui.checkbox(&mut state.show_suspicious_only, egui::RichText::new("Suspicious only").color(RISK_HIGH));
    });
    ui.add_space(6.0);

    let filter_lower = state.filter.to_lowercase();

    let suspicious_only = state.show_suspicious_only;

    // Two-pane layout
    ui.columns(2, |cols| {
        // Left pane: DLL list
        egui::Frame::new()
            .fill(BG_DARK)
            .corner_radius(CornerRadius::same(4))
            .stroke(egui::Stroke::new(0.5, BORDER))
            .inner_margin(Margin::same(4))
            .show(&mut cols[0], |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("dll_list")
                    .show(ui, |ui| {
                        for (idx, imp) in imports.iter().enumerate() {
                            let dll_matches = imp.dll.to_lowercase().contains(&filter_lower);
                            let func_match_count = if filter_lower.is_empty() {
                                0
                            } else {
                                imp.functions.iter().filter(|f| f.name.to_lowercase().contains(&filter_lower)).count()
                            };
                            let suspicious_count = imp.functions.iter().filter(|f| f.risk.is_some()).count();

                            let has_visible_funcs = if suspicious_only {
                                suspicious_count > 0
                            } else {
                                true
                            };

                            let matches_filter = (filter_lower.is_empty()
                                || dll_matches
                                || func_match_count > 0)
                                && has_visible_funcs;

                            if !matches_filter {
                                continue;
                            }

                            let selected = state.selected_dll == Some(idx);
                            let count_text = if suspicious_count > 0 {
                                if func_match_count > 0 && !filter_lower.is_empty() {
                                    format!("{} ({}/{}) [!{}]", imp.dll, func_match_count, imp.functions.len(), suspicious_count)
                                } else {
                                    format!("{} ({}) [!{}]", imp.dll, imp.functions.len(), suspicious_count)
                                }
                            } else if func_match_count > 0 && !filter_lower.is_empty() {
                                format!("{} ({}/{})", imp.dll, func_match_count, imp.functions.len())
                            } else {
                                format!("{} ({})", imp.dll, imp.functions.len())
                            };

                            let text = if selected {
                                egui::RichText::new(&count_text).color(ACCENT)
                            } else if suspicious_count > 0 {
                                egui::RichText::new(&count_text).color(RISK_HIGH)
                            } else {
                                egui::RichText::new(&count_text)
                            };

                            if ui.selectable_label(selected, text).clicked() {
                                state.selected_dll = Some(idx);
                            }
                        }
                    });
            });

        // Right pane: Functions
        egui::Frame::new()
            .fill(BG_DARK)
            .corner_radius(CornerRadius::same(4))
            .stroke(egui::Stroke::new(0.5, BORDER))
            .inner_margin(Margin::same(8))
            .show(&mut cols[1], |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("func_list")
                    .show(ui, |ui| {
                        if let Some(idx) = state.selected_dll {
                            if let Some(imp) = imports.get(idx) {
                                ui.colored_label(ACCENT_DIM, &imp.dll);
                                ui.add_space(6.0);
                                for func in &imp.functions {
                                    if suspicious_only && func.risk.is_none() {
                                        continue;
                                    }
                                    let func_lower = func.name.to_lowercase();
                                    let matches = filter_lower.is_empty()
                                        || func_lower.contains(&filter_lower);
                                    if matches {
                                        if let Some(ref risk) = func.risk {
                                            let severity_color = match risk.severity.as_str() {
                                                "high" => RISK_HIGH,
                                                "medium" => RISK_MEDIUM,
                                                "low" => RISK_LOW,
                                                _ => Color32::from_rgb(220, 225, 235),
                                            };
                                            ui.horizontal(|ui| {
                                                ui.colored_label(severity_color, &func.name);
                                                ui.colored_label(LABEL, format!("[{}]", risk.category));
                                            });
                                        } else {
                                            let color = if !filter_lower.is_empty()
                                                && func_lower.contains(&filter_lower)
                                            {
                                                HIGHLIGHT
                                            } else {
                                                Color32::from_rgb(220, 225, 235)
                                            };
                                            ui.colored_label(color, &func.name);
                                        }
                                    }
                                }
                            }
                        } else {
                            ui.colored_label(LABEL, "Select a DLL from the left panel");
                        }
                    });
            });
    });
}
