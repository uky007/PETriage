use egui::{Color32, TextureHandle, Ui, Vec2};

use crate::analysis::AnalysisResult;

const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const ACCENT_DIM: Color32 = Color32::from_rgb(0, 120, 150);
const LABEL: Color32 = Color32::from_rgb(120, 130, 150);
const BG_DARK: Color32 = Color32::from_rgb(12, 12, 24);
const BORDER: Color32 = Color32::from_rgb(40, 45, 65);

pub fn show(ui: &mut Ui, result: &AnalysisResult, icon_groups: &[(String, Vec<(String, TextureHandle)>)]) {
    let resources = match result.resources {
        Some(ref r) => r,
        None => {
            ui.colored_label(LABEL, "No resource data available. Enable 'Resources' in options and re-analyze.");
            return;
        }
    };

    ui.colored_label(ACCENT, egui::RichText::new(format!("RESOURCES ({} entries)", resources.total_entries)).size(14.0));
    ui.add_space(6.0);

    // Icons
    if !icon_groups.is_empty() {
        let id = ui.make_persistent_id("icons_header");
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
            .show_header(ui, |ui| {
                ui.colored_label(ACCENT_DIM, egui::RichText::new("Icons").strong());
            })
            .body(|ui| {
                egui::Frame::new()
                    .fill(BG_DARK)
                    .corner_radius(egui::CornerRadius::same(4))
                    .stroke(egui::Stroke::new(0.5, BORDER))
                    .inner_margin(egui::Margin::same(8))
                    .show(ui, |ui| {
                        for (group_name, textures) in icon_groups {
                            ui.colored_label(LABEL, format!("Group {group_name}"));
                            ui.add_space(4.0);
                            ui.horizontal_wrapped(|ui| {
                                for (size_label, tex) in textures {
                                    ui.vertical(|ui| {
                                        ui.image(egui::load::SizedTexture::new(
                                            tex.id(),
                                            Vec2::new(48.0, 48.0),
                                        ));
                                        ui.colored_label(LABEL, size_label);
                                    });
                                }
                            });
                            ui.add_space(4.0);
                        }
                    });
            });
        ui.add_space(8.0);
    }

    // Version Info
    if let Some(ref ver) = resources.version_info {
        let id = ui.make_persistent_id("version_info_header");
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
            .show_header(ui, |ui| {
                ui.colored_label(ACCENT_DIM, egui::RichText::new("Version Info").strong());
            })
            .body(|ui| {
                egui::Frame::new()
                    .fill(BG_DARK)
                    .corner_radius(egui::CornerRadius::same(4))
                    .stroke(egui::Stroke::new(0.5, BORDER))
                    .inner_margin(egui::Margin::same(8))
                    .show(ui, |ui| {
                        if let Some(ref fixed) = ver.fixed {
                            egui::Grid::new("fixed_file_info_grid")
                                .num_columns(2)
                                .spacing([16.0, 4.0])
                                .show(ui, |ui| {
                                    ui.colored_label(LABEL, "FileVersion:");
                                    ui.monospace(&fixed.file_version);
                                    ui.end_row();

                                    ui.colored_label(LABEL, "ProductVersion:");
                                    ui.monospace(&fixed.product_version);
                                    ui.end_row();

                                    ui.colored_label(LABEL, "FileType:");
                                    ui.monospace(format!("{} ({})", fixed.file_type_str, fixed.file_type));
                                    ui.end_row();

                                    ui.colored_label(LABEL, "FileOS:");
                                    ui.monospace(format!("{:#x}", fixed.file_os));
                                    ui.end_row();

                                    ui.colored_label(LABEL, "FileFlags:");
                                    ui.monospace(format!("{:#x}", fixed.file_flags));
                                    ui.end_row();
                                });
                            ui.add_space(8.0);
                        }

                        if !ver.string_info.is_empty() {
                            ui.colored_label(ACCENT_DIM, "String Info");
                            ui.add_space(4.0);
                            egui::Grid::new("string_file_info_grid")
                                .num_columns(2)
                                .spacing([16.0, 4.0])
                                .show(ui, |ui| {
                                    for s in &ver.string_info {
                                        ui.colored_label(LABEL, format!("{}:", s.key));
                                        ui.monospace(&s.value);
                                        ui.end_row();
                                    }
                                });
                        }
                    });
            });
        ui.add_space(8.0);
    }

    // Manifest
    if let Some(ref manifest) = resources.manifest {
        let id = ui.make_persistent_id("manifest_header");
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
            .show_header(ui, |ui| {
                ui.colored_label(ACCENT_DIM, egui::RichText::new("Manifest").strong());
            })
            .body(|ui| {
                egui::Frame::new()
                    .fill(BG_DARK)
                    .corner_radius(egui::CornerRadius::same(4))
                    .stroke(egui::Stroke::new(0.5, BORDER))
                    .inner_margin(egui::Margin::same(8))
                    .show(ui, |ui| {
                        ui.monospace(manifest);
                    });
            });
        ui.add_space(8.0);
    }

    // All Entries table
    if !resources.entries.is_empty() {
        let id = ui.make_persistent_id("resource_entries_header");
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
            .show_header(ui, |ui| {
                ui.colored_label(ACCENT_DIM, egui::RichText::new("All Entries").strong());
            })
            .body(|ui| {
                use egui_extras::{TableBuilder, Column};
                TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::auto().at_least(120.0))  // Type
                    .column(Column::auto().at_least(100.0))  // Name
                    .column(Column::auto().at_least(80.0))   // Language
                    .column(Column::auto().at_least(70.0))   // Size
                    .column(Column::auto().at_least(100.0))  // RVA
                    .header(20.0, |mut header| {
                        header.col(|ui| { ui.colored_label(ACCENT_DIM, "Type"); });
                        header.col(|ui| { ui.colored_label(ACCENT_DIM, "Name"); });
                        header.col(|ui| { ui.colored_label(ACCENT_DIM, "Language"); });
                        header.col(|ui| { ui.colored_label(ACCENT_DIM, "Size"); });
                        header.col(|ui| { ui.colored_label(ACCENT_DIM, "RVA"); });
                    })
                    .body(|body| {
                        body.rows(18.0, resources.entries.len(), |mut row| {
                            let entry = &resources.entries[row.index()];
                            row.col(|ui| { ui.monospace(&entry.resource_type); });
                            row.col(|ui| { ui.monospace(&entry.name); });
                            row.col(|ui| { ui.monospace(&entry.language_str); });
                            row.col(|ui| { ui.monospace(format!("{}", entry.size)); });
                            row.col(|ui| { ui.monospace(format!("{:#x}", entry.rva)); });
                        });
                    });
            });
    }
}
