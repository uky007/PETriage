mod analysis;
#[cfg(feature = "gui")]
mod gui;
mod output;

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::Parser;

#[derive(Parser)]
#[command(name = "readpe", version, about = "Cross-platform PE file surface analysis tool")]
struct Cli {
    /// PE file to analyze
    file: Option<PathBuf>,

    /// Show all information (default if no flags specified)
    #[arg(short = 'a', long)]
    all: bool,

    /// Show DOS/PE/COFF/Optional headers
    #[arg(short = 'H', long)]
    headers: bool,

    /// Show section headers
    #[arg(short = 's', long)]
    sections: bool,

    /// Show import table
    #[arg(short = 'i', long)]
    imports: bool,

    /// Show export table
    #[arg(short = 'e', long)]
    exports: bool,

    /// Show strings (ASCII and Unicode)
    #[arg(short = 'S', long)]
    strings: bool,

    /// Minimum string length for extraction
    #[arg(long, default_value_t = 4)]
    min_str_len: usize,

    /// Show file hashes (MD5, SHA1, SHA256)
    #[arg(long)]
    hashes: bool,

    /// Show overlay information
    #[arg(long)]
    overlay: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Write output to file
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Launch GUI mode
    #[cfg(feature = "gui")]
    #[arg(long)]
    gui: bool,
}

fn main() {
    let cli = Cli::parse();

    #[cfg(feature = "gui")]
    if cli.gui {
        gui::run(cli.file);
        return;
    }

    let file = match cli.file {
        Some(f) => f,
        None => {
            eprintln!("Error: PE file path is required for CLI mode");
            eprintln!("Usage: readpe <FILE>");
            process::exit(1);
        }
    };

    let data = match fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: Failed to read '{}': {}", file.display(), e);
            process::exit(1);
        }
    };

    let pe = match goblin::pe::PE::parse(&data) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("Error: Failed to parse PE file: {}", e);
            process::exit(1);
        }
    };

    // If no specific flags, show all
    let show_all = cli.all
        || !(cli.headers || cli.sections || cli.imports || cli.exports
            || cli.strings || cli.hashes || cli.overlay);

    let result = analysis::analyze(&data, &pe, &analysis::AnalysisOptions {
        show_headers: show_all || cli.headers,
        show_sections: show_all || cli.sections,
        show_imports: show_all || cli.imports,
        show_exports: show_all || cli.exports,
        show_strings: show_all || cli.strings,
        show_hashes: show_all || cli.hashes,
        show_overlay: show_all || cli.overlay,
        min_str_len: cli.min_str_len,
        file_name: file.display().to_string(),
    });

    let output_text = if cli.json {
        output::format_json(&result)
    } else {
        output::format_text(&result)
    };

    if let Some(path) = &cli.output {
        if let Err(e) = fs::write(path, &output_text) {
            eprintln!("Error: Failed to write output to '{}': {}", path.display(), e);
            process::exit(1);
        }
        println!("Output written to: {}", path.display());
    } else {
        print!("{}", output_text);
    }
}
