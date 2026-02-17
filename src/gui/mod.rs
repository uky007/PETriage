mod app_state;
mod panels;

use std::path::PathBuf;

use eframe::egui;

use crate::analysis::{self, AnalysisOptions};
use app_state::{AppState, OptionsPanel, Tab};
use panels::imports::ImportsState;
use panels::strings::StringsState;

pub fn run(file: Option<PathBuf>) {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };

    let _ = eframe::run_native(
        "readpe",
        options,
        Box::new(move |cc| {
            setup_fonts(&cc.egui_ctx);
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            let mut app = ReadpeApp::default();
            if let Some(path) = file {
                app.load_file(path);
            }
            Ok(Box::new(app))
        }),
    );
}

fn setup_fonts(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.override_font_id = Some(egui::FontId::monospace(13.0));
    style.spacing.item_spacing = egui::vec2(8.0, 4.0);
    ctx.set_style(style);
}

struct ReadpeApp {
    state: AppState,
    options: OptionsPanel,
    current_tab: Tab,
    imports_state: ImportsState,
    strings_state: StringsState,
}

impl Default for ReadpeApp {
    fn default() -> Self {
        Self {
            state: AppState::NoFile,
            options: OptionsPanel::default(),
            current_tab: Tab::FileInfo,
            imports_state: ImportsState::default(),
            strings_state: StringsState::default(),
        }
    }
}

impl ReadpeApp {
    fn load_file(&mut self, path: PathBuf) {
        let file_name = path.display().to_string();
        match std::fs::read(&path) {
            Ok(data) => {
                match goblin::pe::PE::parse(&data) {
                    Ok(pe) => {
                        let opts = AnalysisOptions {
                            show_headers: self.options.show_headers,
                            show_sections: self.options.show_sections,
                            show_imports: self.options.show_imports,
                            show_exports: self.options.show_exports,
                            show_strings: self.options.show_strings,
                            show_hashes: self.options.show_hashes,
                            show_overlay: self.options.show_overlay,
                            min_str_len: self.options.min_str_len,
                            file_name: file_name.clone(),
                        };
                        let result = analysis::analyze(&data, &pe, &opts);
                        self.imports_state = ImportsState::default();
                        self.strings_state = StringsState::default();
                        self.state = AppState::Loaded {
                            file_name,
                            data,
                            result,
                        };
                    }
                    Err(e) => {
                        self.state = AppState::Error(format!("Failed to parse PE: {e}"));
                    }
                }
            }
            Err(e) => {
                self.state = AppState::Error(format!("Failed to read file: {e}"));
            }
        }
    }

    fn reanalyze(&mut self) {
        if let AppState::Loaded { ref file_name, ref data, .. } = self.state {
            let file_name = file_name.clone();
            let data = data.clone();
            match goblin::pe::PE::parse(&data) {
                Ok(pe) => {
                    let opts = AnalysisOptions {
                        show_headers: self.options.show_headers,
                        show_sections: self.options.show_sections,
                        show_imports: self.options.show_imports,
                        show_exports: self.options.show_exports,
                        show_strings: self.options.show_strings,
                        show_hashes: self.options.show_hashes,
                        show_overlay: self.options.show_overlay,
                        min_str_len: self.options.min_str_len,
                        file_name: file_name.clone(),
                    };
                    let result = analysis::analyze(&data, &pe, &opts);
                    self.imports_state = ImportsState::default();
                    self.strings_state = StringsState::default();
                    self.state = AppState::Loaded {
                        file_name,
                        data,
                        result,
                    };
                }
                Err(e) => {
                    self.state = AppState::Error(format!("Failed to parse PE: {e}"));
                }
            }
        }
    }

    fn open_file_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("PE files", &["exe", "dll", "sys", "ocx", "scr"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.load_file(path);
        }
    }
}

impl eframe::App for ReadpeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle dropped files
        ctx.input(|i| {
            if let Some(dropped) = i.raw.dropped_files.first() {
                if let Some(path) = &dropped.path {
                    let path = path.clone();
                    // Defer loading to avoid borrow conflict
                    return Some(path);
                }
                None
            } else {
                None
            }
        }).and_then(|p| { self.load_file(p); Some(()) });

        // Menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open...").clicked() {
                        ui.close_menu();
                        self.open_file_dialog();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
        });

        // Left sidebar: options
        egui::SidePanel::left("options_panel")
            .default_width(200.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading("Analysis Options");
                ui.add_space(8.0);
                ui.checkbox(&mut self.options.show_headers, "Headers");
                ui.checkbox(&mut self.options.show_sections, "Sections");
                ui.checkbox(&mut self.options.show_imports, "Imports");
                ui.checkbox(&mut self.options.show_exports, "Exports");
                ui.checkbox(&mut self.options.show_strings, "Strings");
                ui.checkbox(&mut self.options.show_hashes, "Hashes");
                ui.checkbox(&mut self.options.show_overlay, "Overlay");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("Min string len:");
                    ui.add(egui::DragValue::new(&mut self.options.min_str_len).range(1..=32));
                });
                ui.add_space(8.0);
                if ui.button("Re-analyze").clicked() {
                    self.reanalyze();
                }

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(4.0);

                // File status
                match &self.state {
                    AppState::NoFile => {
                        ui.label("No file loaded");
                        ui.label("Use File > Open or drag & drop");
                    }
                    AppState::Loaded { file_name, data, .. } => {
                        ui.strong("Loaded:");
                        ui.label(file_name.as_str());
                        ui.label(format!("{} bytes", data.len()));
                    }
                    AppState::Error(msg) => {
                        ui.colored_label(egui::Color32::RED, "Error:");
                        ui.label(msg.as_str());
                    }
                }
            });

        // Central panel: tabs + content
        egui::CentralPanel::default().show(ctx, |ui| {
            match &self.state {
                AppState::NoFile => {
                    ui.centered_and_justified(|ui| {
                        ui.heading("Drop a PE file here or use File > Open");
                    });
                }
                AppState::Error(msg) => {
                    ui.colored_label(egui::Color32::RED, format!("Error: {msg}"));
                }
                AppState::Loaded { result, .. } => {
                    // Tab bar
                    ui.horizontal(|ui| {
                        for tab in Tab::ALL {
                            if ui.selectable_label(self.current_tab == *tab, tab.label()).clicked() {
                                self.current_tab = *tab;
                            }
                        }
                    });
                    ui.separator();

                    // Clone result for panels that need mutable self
                    let result = result.clone();

                    egui::ScrollArea::both()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            match self.current_tab {
                                Tab::FileInfo => panels::file_info::show(ui, &result),
                                Tab::Headers => panels::headers::show(ui, &result),
                                Tab::Sections => panels::sections::show(ui, &result),
                                Tab::Imports => panels::imports::show(ui, &result, &mut self.imports_state),
                                Tab::Exports => panels::exports::show(ui, &result),
                                Tab::Strings => panels::strings::show(ui, &result, &mut self.strings_state),
                                Tab::Overlay => panels::overlay::show(ui, &result),
                            }
                        });
                }
            }
        });
    }
}
