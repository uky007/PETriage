mod app_state;
mod panels;

use std::path::PathBuf;

use eframe::egui;
use egui::{Color32, ColorImage, CornerRadius, FontId, Margin, Stroke, TextureHandle, Vec2};

use crate::analysis::{self, AnalysisOptions};
use app_state::{AppState, OptionsPanel, Tab};
use panels::imports::ImportsState;
use panels::strings::StringsState;

// Color palette — cyber/security tool aesthetic
const BG_DARK: Color32 = Color32::from_rgb(12, 12, 24);
const BG_PANEL: Color32 = Color32::from_rgb(18, 18, 36);
const BG_HEADER: Color32 = Color32::from_rgb(22, 22, 44);
const ACCENT: Color32 = Color32::from_rgb(0, 210, 255);
const ACCENT_DIM: Color32 = Color32::from_rgb(0, 120, 150);
const TEXT_PRIMARY: Color32 = Color32::from_rgb(220, 225, 235);
const TEXT_DIM: Color32 = Color32::from_rgb(120, 130, 150);
const BORDER: Color32 = Color32::from_rgb(40, 45, 65);
const TAB_HOVER: Color32 = Color32::from_rgb(30, 30, 60);
const SUCCESS: Color32 = Color32::from_rgb(80, 200, 120);
const ERROR_RED: Color32 = Color32::from_rgb(255, 70, 70);

pub fn run(file: Option<PathBuf>) {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };

    let _ = eframe::run_native(
        "petriage",
        options,
        Box::new(move |cc| {
            setup_style(&cc.egui_ctx);
            let mut app = ReadpeApp::default();
            if let Some(path) = file {
                app.load_file(path);
            }
            Ok(Box::new(app))
        }),
    );
}

fn setup_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.override_font_id = Some(FontId::monospace(13.0));
    style.spacing.item_spacing = Vec2::new(8.0, 4.0);
    style.spacing.button_padding = Vec2::new(8.0, 4.0);

    let mut visuals = egui::Visuals::dark();

    // Window / panel backgrounds
    visuals.panel_fill = BG_DARK;
    visuals.window_fill = BG_PANEL;
    visuals.faint_bg_color = BG_HEADER;
    visuals.extreme_bg_color = Color32::from_rgb(8, 8, 16);

    // Strokes & borders
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(0.5, BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);

    // Inactive widgets
    visuals.widgets.inactive.bg_fill = BG_PANEL;
    visuals.widgets.inactive.bg_stroke = Stroke::new(0.5, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(4);

    // Hovered
    visuals.widgets.hovered.bg_fill = TAB_HOVER;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT_DIM);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(4);

    // Active (pressed)
    visuals.widgets.active.bg_fill = Color32::from_rgb(0, 60, 80);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.corner_radius = CornerRadius::same(4);

    // Open (e.g. combo box)
    visuals.widgets.open.bg_fill = BG_HEADER;
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, ACCENT);

    // Selection
    visuals.selection.bg_fill = Color32::from_rgb(0, 60, 90);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);

    // Separator
    visuals.widgets.noninteractive.bg_fill = BG_PANEL;

    // Hyperlink
    visuals.hyperlink_color = ACCENT;

    // Scrollbar
    visuals.handle_shape = egui::style::HandleShape::Circle;

    // Striped table bg
    visuals.striped = true;

    ctx.set_visuals(visuals);
    ctx.set_style(style);
}

struct IconCache {
    primary_icon: Option<TextureHandle>,
    all_icons: Vec<(String, Vec<(String, TextureHandle)>)>,
    populated: bool,
}

impl Default for IconCache {
    fn default() -> Self {
        Self {
            primary_icon: None,
            all_icons: Vec::new(),
            populated: false,
        }
    }
}

fn decode_ico_to_textures(
    ctx: &egui::Context,
    ico_bytes: &[u8],
    prefix: &str,
) -> Vec<(String, TextureHandle)> {
    use image::ImageReader;
    use std::io::Cursor;

    let reader = match ImageReader::new(Cursor::new(ico_bytes)).with_guessed_format() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let dyn_img = match reader.decode() {
        Ok(img) => img,
        Err(_) => return Vec::new(),
    };

    let rgba = dyn_img.to_rgba8();
    let (w, h) = (rgba.width() as usize, rgba.height() as usize);
    let label = format!("{prefix}_{w}x{h}");
    let color_image = ColorImage::from_rgba_unmultiplied([w, h], &rgba);
    let texture = ctx.load_texture(&label, color_image, egui::TextureOptions::LINEAR);
    vec![(format!("{w}x{h}"), texture)]
}

struct ReadpeApp {
    state: AppState,
    options: OptionsPanel,
    current_tab: Tab,
    imports_state: ImportsState,
    strings_state: StringsState,
    icon_cache: IconCache,
}

impl Default for ReadpeApp {
    fn default() -> Self {
        Self {
            state: AppState::NoFile,
            options: OptionsPanel::default(),
            current_tab: Tab::FileInfo,
            imports_state: ImportsState::default(),
            strings_state: StringsState::default(),
            icon_cache: IconCache::default(),
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
                            show_resources: self.options.show_resources,
                            show_authenticode: self.options.show_authenticode,
                            min_str_len: self.options.min_str_len,
                            file_name: file_name.clone(),
                        };
                        let result = analysis::analyze(&data, &pe, &opts);
                        self.imports_state = ImportsState::default();
                        self.strings_state = StringsState::default();
                        self.icon_cache = IconCache::default();
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
                        show_resources: self.options.show_resources,
                        show_authenticode: self.options.show_authenticode,
                        min_str_len: self.options.min_str_len,
                        file_name: file_name.clone(),
                    };
                    let result = analysis::analyze(&data, &pe, &opts);
                    self.imports_state = ImportsState::default();
                    self.strings_state = StringsState::default();
                    self.icon_cache = IconCache::default();
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
                    return Some(path);
                }
                None
            } else {
                None
            }
        }).and_then(|p| { self.load_file(p); Some(()) });

        // Menu bar
        egui::TopBottomPanel::top("menu_bar")
            .frame(egui::Frame::new()
                .fill(BG_HEADER)
                .inner_margin(Margin::symmetric(8, 2))
                .stroke(Stroke::new(1.0, BORDER)))
            .show(ctx, |ui| {
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
                    ui.separator();
                    ui.colored_label(ACCENT, "petriage");
                    ui.colored_label(TEXT_DIM, format!("v{}", env!("CARGO_PKG_VERSION")));
                });
            });

        // Status bar at bottom
        egui::TopBottomPanel::bottom("status_bar")
            .frame(egui::Frame::new()
                .fill(BG_HEADER)
                .inner_margin(Margin::symmetric(12, 4))
                .stroke(Stroke::new(1.0, BORDER)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    match &self.state {
                        AppState::NoFile => {
                            ui.colored_label(TEXT_DIM, "No file loaded");
                        }
                        AppState::Loaded { file_name, data, result } => {
                            ui.colored_label(SUCCESS, "\u{25cf}");
                            ui.colored_label(TEXT_PRIMARY, file_name.as_str());
                            ui.colored_label(TEXT_DIM, "|");
                            ui.colored_label(TEXT_DIM, format!("{} bytes", data.len()));
                            if let Some(ref info) = result.file_info {
                                ui.colored_label(TEXT_DIM, "|");
                                ui.colored_label(ACCENT_DIM, &info.pe_type);
                            }
                        }
                        AppState::Error(msg) => {
                            ui.colored_label(ERROR_RED, "\u{25cf}");
                            ui.colored_label(ERROR_RED, msg.as_str());
                        }
                    }
                });
            });

        // Left sidebar: options
        egui::SidePanel::left("options_panel")
            .default_width(200.0)
            .resizable(true)
            .frame(egui::Frame::new()
                .fill(BG_PANEL)
                .inner_margin(Margin::same(12))
                .stroke(Stroke::new(1.0, BORDER)))
            .show(ctx, |ui| {
                // Logo area
                ui.vertical_centered(|ui| {
                    ui.colored_label(ACCENT, "\u{2588}\u{2588} petriage");
                    ui.colored_label(TEXT_DIM, "PE Surface Analysis");
                });
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);

                // Analysis options group
                ui.colored_label(ACCENT_DIM, "ANALYSIS OPTIONS");
                ui.add_space(4.0);
                egui::Frame::new()
                    .fill(BG_DARK)
                    .corner_radius(CornerRadius::same(6))
                    .inner_margin(Margin::same(8))
                    .stroke(Stroke::new(0.5, BORDER))
                    .show(ui, |ui| {
                        ui.checkbox(&mut self.options.show_headers, "Headers");
                        ui.checkbox(&mut self.options.show_sections, "Sections");
                        ui.checkbox(&mut self.options.show_imports, "Imports");
                        ui.checkbox(&mut self.options.show_exports, "Exports");
                        ui.checkbox(&mut self.options.show_strings, "Strings");
                        ui.checkbox(&mut self.options.show_hashes, "Hashes");
                        ui.checkbox(&mut self.options.show_overlay, "Overlay");
                        ui.checkbox(&mut self.options.show_resources, "Resources");
                        ui.checkbox(&mut self.options.show_authenticode, "Authenticode");
                    });
                ui.add_space(8.0);

                // String length
                ui.colored_label(ACCENT_DIM, "STRING EXTRACTION");
                ui.add_space(4.0);
                egui::Frame::new()
                    .fill(BG_DARK)
                    .corner_radius(CornerRadius::same(6))
                    .inner_margin(Margin::same(8))
                    .stroke(Stroke::new(0.5, BORDER))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Min length:");
                            ui.add(egui::DragValue::new(&mut self.options.min_str_len).range(1..=32));
                        });
                    });
                ui.add_space(12.0);

                // Re-analyze button (full width, accent styled)
                let btn = egui::Button::new(
                    egui::RichText::new("\u{27f3} Re-analyze")
                        .color(Color32::WHITE)
                )
                .fill(Color32::from_rgb(0, 80, 110))
                .stroke(Stroke::new(1.0, ACCENT_DIM))
                .corner_radius(CornerRadius::same(6))
                .min_size(Vec2::new(ui.available_width(), 28.0));
                if ui.add(btn).clicked() {
                    self.reanalyze();
                }
            });

        // Central panel: tabs + content
        egui::CentralPanel::default()
            .frame(egui::Frame::new()
                .fill(BG_DARK)
                .inner_margin(Margin::same(0)))
            .show(ctx, |ui| {
                match &self.state {
                    AppState::NoFile => {
                        // Welcome screen
                        ui.vertical_centered(|ui| {
                            ui.add_space(ui.available_height() / 3.0);
                            ui.colored_label(
                                ACCENT,
                                egui::RichText::new("\u{2588}\u{2588} petriage").size(28.0),
                            );
                            ui.add_space(8.0);
                            ui.colored_label(
                                TEXT_DIM,
                                egui::RichText::new("Drop a PE file here or use File > Open").size(16.0),
                            );
                            ui.add_space(24.0);
                            ui.colored_label(
                                Color32::from_rgb(50, 55, 75),
                                "Supported: .exe .dll .sys .ocx .scr",
                            );
                        });
                    }
                    AppState::Error(msg) => {
                        ui.add_space(20.0);
                        ui.horizontal(|ui| {
                            ui.add_space(20.0);
                            ui.colored_label(ERROR_RED, format!("Error: {msg}"));
                        });
                    }
                    AppState::Loaded { result, .. } => {
                        // Populate icon cache on first frame after load
                        if !self.icon_cache.populated {
                            self.icon_cache.populated = true;
                            if let Some(ref resources) = result.resources {
                                for (gi, group) in resources.icon_data.iter().enumerate() {
                                    let prefix = format!("icon_g{gi}");
                                    let textures = decode_ico_to_textures(
                                        ctx,
                                        &group.ico_bytes,
                                        &prefix,
                                    );
                                    if !textures.is_empty() {
                                        if self.icon_cache.primary_icon.is_none() {
                                            self.icon_cache.primary_icon =
                                                Some(textures[0].1.clone());
                                        }
                                        self.icon_cache.all_icons.push((
                                            group.name.clone(),
                                            textures,
                                        ));
                                    }
                                }
                            }
                        }

                        // Tab bar
                        egui::Frame::new()
                            .fill(BG_HEADER)
                            .inner_margin(Margin::symmetric(8, 0))
                            .stroke(Stroke::new(1.0, BORDER))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_space(4.0);
                                    for tab in Tab::ALL {
                                        let selected = self.current_tab == *tab;
                                        let text = egui::RichText::new(tab.label())
                                            .color(if selected { ACCENT } else { TEXT_DIM });
                                        let btn = egui::Button::new(text)
                                            .fill(if selected { BG_DARK } else { Color32::TRANSPARENT })
                                            .stroke(if selected {
                                                Stroke::new(1.0, ACCENT_DIM)
                                            } else {
                                                Stroke::NONE
                                            })
                                            .corner_radius(CornerRadius {
                                                nw: 4, ne: 4, sw: 0, se: 0,
                                            });
                                        if ui.add(btn).clicked() {
                                            self.current_tab = *tab;
                                        }
                                    }
                                });
                            });

                        // Clone result for panels that need mutable self
                        let result = result.clone();

                        egui::Frame::new()
                            .fill(BG_DARK)
                            .inner_margin(Margin::same(12))
                            .show(ui, |ui| {
                                egui::ScrollArea::both()
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        match self.current_tab {
                                            Tab::FileInfo => panels::file_info::show(ui, &result, self.icon_cache.primary_icon.as_ref()),
                                            Tab::Headers => panels::headers::show(ui, &result),
                                            Tab::Sections => panels::sections::show(ui, &result),
                                            Tab::Imports => panels::imports::show(ui, &result, &mut self.imports_state),
                                            Tab::Exports => panels::exports::show(ui, &result),
                                            Tab::Strings => panels::strings::show(ui, &result, &mut self.strings_state),
                                            Tab::Overlay => panels::overlay::show(ui, &result),
                                            Tab::Resources => panels::resources::show(ui, &result, &self.icon_cache.all_icons),
                                            Tab::Authenticode => panels::authenticode::show(ui, &result),
                                        }
                                    });
                            });
                    }
                }
            });
    }
}
