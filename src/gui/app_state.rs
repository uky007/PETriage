use crate::analysis::AnalysisResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    FileInfo,
    Headers,
    Sections,
    Imports,
    Exports,
    Strings,
    Overlay,
    Resources,
}

impl Tab {
    pub const ALL: &[Tab] = &[
        Tab::FileInfo,
        Tab::Headers,
        Tab::Sections,
        Tab::Imports,
        Tab::Exports,
        Tab::Strings,
        Tab::Overlay,
        Tab::Resources,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Tab::FileInfo => "File Info",
            Tab::Headers => "Headers",
            Tab::Sections => "Sections",
            Tab::Imports => "Imports",
            Tab::Exports => "Exports",
            Tab::Strings => "Strings",
            Tab::Overlay => "Overlay",
            Tab::Resources => "Resources",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OptionsPanel {
    pub show_headers: bool,
    pub show_sections: bool,
    pub show_imports: bool,
    pub show_exports: bool,
    pub show_strings: bool,
    pub show_hashes: bool,
    pub show_overlay: bool,
    pub show_resources: bool,
    pub min_str_len: usize,
}

impl Default for OptionsPanel {
    fn default() -> Self {
        Self {
            show_headers: true,
            show_sections: true,
            show_imports: true,
            show_exports: true,
            show_strings: true,
            show_hashes: true,
            show_overlay: true,
            show_resources: true,
            min_str_len: 4,
        }
    }
}

#[derive(Debug)]
pub enum AppState {
    NoFile,
    Loaded {
        file_name: String,
        data: Vec<u8>,
        result: AnalysisResult,
    },
    Error(String),
}
