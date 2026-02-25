use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "petriage-gui", version, about = "Cross-platform PE file surface analysis tool (GUI)")]
struct Cli {
    /// PE file to open on launch
    file: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    petriage::gui::run(cli.file);
}
