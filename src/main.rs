#[cfg(feature = "tui")]
mod tui;

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::Parser;
use petriage::{analysis, output, parse_pe_lenient};

#[derive(Parser)]
#[command(name = "petriage", version, about = "Cross-platform PE file surface analysis tool")]
struct Cli {
    /// PE file to analyze
    file: Option<PathBuf>,

    /// Show all information including strings (default shows all except strings)
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

    /// Show file hashes (MD5, SHA1, SHA256, imphash)
    #[arg(long)]
    hashes: bool,

    /// Show overlay information
    #[arg(long)]
    overlay: bool,

    /// Show PE resources (version info, manifest, resource entries)
    #[arg(short = 'r', long)]
    resources: bool,

    /// Show Authenticode/code signing information
    #[arg(short = 'c', long)]
    authenticode: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Output as newline-delimited JSON (one JSON object per line)
    #[arg(long, conflicts_with = "json")]
    ndjson: bool,

    /// Batch-analyze all PE files in a directory
    #[arg(long, value_name = "DIR")]
    batch: Option<PathBuf>,

    /// Exit with code 3 if any anomaly meets or exceeds the given severity
    #[arg(long, value_name = "SEVERITY", value_parser = parse_severity)]
    fail_on: Option<String>,

    /// Enable strict OPSEC analysis (credential and endpoint scanning via strings)
    #[arg(long)]
    opsec_strict: bool,

    /// Write output to file
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Save overlay data to a file (carve)
    #[arg(long, value_name = "FILE")]
    carve_overlay: Option<PathBuf>,

    /// Save PE without overlay data (strip)
    #[arg(long, value_name = "FILE")]
    strip_overlay: Option<PathBuf>,

    /// Launch interactive TUI hex viewer
    #[cfg(feature = "tui")]
    #[arg(short = 'x', long = "view")]
    view: bool,
}

fn parse_severity(s: &str) -> Result<String, String> {
    match s {
        "critical" | "warning" | "info" => Ok(s.to_string()),
        _ => Err(format!("invalid severity '{}': must be critical, warning, or info", s)),
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 3,
        "warning" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn check_fail_on(result: &analysis::AnalysisResult, threshold: &str) -> bool {
    let threshold_rank = severity_rank(threshold);
    if let Some(ref anomalies) = result.anomalies {
        anomalies.iter().any(|a| severity_rank(&a.severity) >= threshold_rank)
    } else {
        false
    }
}

fn is_pe_file(path: &std::path::Path) -> bool {
    if let Ok(f) = fs::File::open(path) {
        use std::io::Read;
        let mut buf = [0u8; 2];
        let mut f = f;
        if f.read_exact(&mut buf).is_ok() {
            return buf == [b'M', b'Z'];
        }
    }
    false
}

fn emit_warning(warning: &str, json_mode: bool) {
    if json_mode {
        eprintln!("{}", serde_json::json!({ "warning": format!("Warning: {}", warning) }));
    } else {
        use colored::Colorize;
        eprintln!("{}", format!("Warning: {}", warning).yellow());
    }
}

fn analyze_file(
    path: &std::path::Path,
    show_all: bool,
    cli: &Cli,
) -> Result<analysis::AnalysisResult, String> {
    let data = fs::read(path)
        .map_err(|e| format!("Failed to read '{}': {}", path.display(), e))?;
    let json_mode = cli.json || cli.ndjson;
    let (pe, warning) = parse_pe_lenient(&data, &path.display().to_string())?;
    if let Some(w) = warning {
        emit_warning(&w, json_mode);
    }
    Ok(analysis::analyze(&data, &pe, &analysis::AnalysisOptions {
        show_headers: show_all || cli.headers,
        show_sections: show_all || cli.sections,
        show_imports: show_all || cli.imports,
        show_exports: show_all || cli.exports,
        show_strings: cli.all || cli.strings,
        show_hashes: show_all || cli.hashes,
        show_overlay: show_all || cli.overlay,
        show_resources: show_all || cli.resources,
        show_authenticode: show_all || cli.authenticode,
        show_all,
        min_str_len: cli.min_str_len,
        file_name: path.display().to_string(),
        opsec_strict: cli.opsec_strict,
    }))
}

// Exit codes:
//   0 — success
//   1 — input error (file not found, read failure, invalid PE)
//   2 — output error (write failure)
//   3 — anomaly threshold exceeded (--fail-on)
fn main() {
    let cli = Cli::parse();

    let json_mode = cli.json || cli.ndjson;

    #[cfg(feature = "tui")]
    let want_tui = cli.view;
    #[cfg(not(feature = "tui"))]
    let want_tui = false;

    if !want_tui && !json_mode {
        output::print_banner();
    }

    // --batch mode
    if let Some(ref dir) = cli.batch {
        if cli.file.is_some() {
            exit_error("Cannot specify both a file and --batch", json_mode, 1);
        }
        if !dir.is_dir() {
            exit_error(&format!("'{}' is not a directory", dir.display()), json_mode, 1);
        }

        let show_all = cli.all
            || !(cli.headers || cli.sections || cli.imports || cli.exports
                || cli.strings || cli.hashes || cli.overlay || cli.resources
                || cli.authenticode);

        let mut entries: Vec<PathBuf> = match fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_file() && is_pe_file(p))
                .collect(),
            Err(e) => {
                exit_error(&format!("Failed to read directory '{}': {}", dir.display(), e), json_mode, 1);
            }
        };
        entries.sort();

        let mut results: Vec<analysis::AnalysisResult> = Vec::new();
        let mut ndjson_buf = String::new();
        let mut any_fail_on = false;

        for path in &entries {
            match analyze_file(path, show_all, &cli) {
                Ok(result) => {
                    if let Some(ref threshold) = cli.fail_on
                        && check_fail_on(&result, threshold) {
                            any_fail_on = true;
                        }
                    if cli.ndjson {
                        ndjson_buf.push_str(&output::format_ndjson(&result));
                    } else {
                        results.push(result);
                    }
                }
                Err(msg) => {
                    if cli.ndjson || cli.json {
                        let err = serde_json::json!({ "error": msg });
                        if cli.ndjson {
                            ndjson_buf.push_str(&format!("{}\n", err));
                        } else {
                            eprintln!("{}", err);
                        }
                    } else {
                        eprintln!("Error: {}", msg);
                    }
                }
            }
        }

        let output_text = if cli.json {
            serde_json::to_string_pretty(&results)
                .unwrap_or_else(|e| format!("JSON error: {}", e))
        } else if cli.ndjson {
            ndjson_buf
        } else {
            let mut buf = String::new();
            for result in &results {
                buf.push_str(&output::format_text(result));
            }
            buf
        };

        if let Some(ref path) = cli.output {
            if let Err(e) = fs::write(path, &output_text) {
                exit_error(
                    &format!("Failed to write output to '{}': {}", path.display(), e),
                    json_mode, 2,
                );
            }
            println!("Output written to: {}", path.display());
        } else {
            print!("{}", output_text);
        }

        if any_fail_on {
            process::exit(3);
        }
        return;
    }

    // Single-file mode
    let file = match cli.file {
        Some(f) => f,
        None => {
            exit_error("PE file path is required for CLI mode", json_mode, 1);
        }
    };

    let data = match fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            exit_error(&format!("Failed to read '{}': {}", file.display(), e), json_mode, 1);
        }
    };

    let pe = match parse_pe_lenient(&data, &file.display().to_string()) {
        Ok((pe, warning)) => {
            if let Some(w) = warning {
                emit_warning(&w, json_mode);
            }
            pe
        }
        Err(msg) => {
            exit_error(&msg, json_mode, 1);
        }
    };

    #[cfg(feature = "tui")]
    if want_tui {
        let file_name = file.display().to_string();
        if let Err(e) = tui::run(&data, &pe, &file_name) {
            exit_error(&format!("TUI failed: {}", e), json_mode, 1);
        }
        return;
    }

    // Overlay carve / strip operations
    if cli.carve_overlay.is_some() || cli.strip_overlay.is_some() {
        let overlay_info = analysis::detect_overlay_public(&data, &pe);
        if !overlay_info.present {
            exit_error("No overlay data found in this PE file", json_mode, 1);
        }
        let input_canonical = fs::canonicalize(&file).unwrap_or_else(|_| file.clone());
        // Validate output paths don't collide with input or each other
        for out_path in [&cli.carve_overlay, &cli.strip_overlay].into_iter().flatten() {
            if let Ok(canon) = fs::canonicalize(out_path) {
                if canon == input_canonical {
                    exit_error(&format!("Output path '{}' is the same as input file — refusing to overwrite", out_path.display()), json_mode, 1);
                }
            }
        }
        if let (Some(a), Some(b)) = (&cli.carve_overlay, &cli.strip_overlay) {
            if resolve_path(a) == resolve_path(b) {
                exit_error("--carve-overlay and --strip-overlay point to the same file", json_mode, 1);
            }
        }
        if let Some(ref path) = cli.carve_overlay {
            let overlay_bytes = &data[overlay_info.offset..overlay_info.offset + overlay_info.size];
            if let Err(e) = fs::write(path, overlay_bytes) {
                exit_error(&format!("Failed to write overlay to '{}': {}", path.display(), e), json_mode, 2);
            }
            if !json_mode {
                println!("Overlay carved: {} bytes written to {}", overlay_info.size, path.display());
            }
        }
        if let Some(ref path) = cli.strip_overlay {
            let stripped = &data[..overlay_info.offset];
            if let Err(e) = fs::write(path, stripped) {
                exit_error(&format!("Failed to write stripped PE to '{}': {}", path.display(), e), json_mode, 2);
            }
            if !json_mode {
                println!("PE stripped: {} bytes written to {} (removed {} bytes overlay)",
                    overlay_info.offset, path.display(), overlay_info.size);
            }
        }
        return;
    }

    // If no specific flags, show all
    let show_all = cli.all
        || !(cli.headers || cli.sections || cli.imports || cli.exports
            || cli.strings || cli.hashes || cli.overlay || cli.resources
            || cli.authenticode);

    let result = analysis::analyze(&data, &pe, &analysis::AnalysisOptions {
        show_headers: show_all || cli.headers,
        show_sections: show_all || cli.sections,
        show_imports: show_all || cli.imports,
        show_exports: show_all || cli.exports,
        show_strings: cli.all || cli.strings,
        show_hashes: show_all || cli.hashes,
        show_overlay: show_all || cli.overlay,
        show_resources: show_all || cli.resources,
        show_authenticode: show_all || cli.authenticode,
        show_all,
        min_str_len: cli.min_str_len,
        file_name: file.display().to_string(),
        opsec_strict: cli.opsec_strict,
    });

    let output_text = if cli.ndjson {
        output::format_ndjson(&result)
    } else if cli.json {
        output::format_json(&result)
    } else {
        output::format_text(&result)
    };

    if let Some(path) = &cli.output {
        if let Err(e) = fs::write(path, &output_text) {
            exit_error(
                &format!("Failed to write output to '{}': {}", path.display(), e),
                json_mode, 2,
            );
        }
        println!("Output written to: {}", path.display());
    } else {
        print!("{}", output_text);
    }

    if let Some(ref threshold) = cli.fail_on
        && check_fail_on(&result, threshold) {
            process::exit(3);
        }
}

/// Resolve a path to an absolute, lexically normalized form.
/// For existing files, uses canonicalize(). For new files, makes the path
/// absolute and then removes `.` and `..` components lexically, so that
/// `./out.bin`, `out.bin`, and `foo/../out.bin` all resolve identically.
fn resolve_path(p: &PathBuf) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(p) {
        return canon;
    }
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.clone());
    normalize_lexical(&abs)
}

/// Lexically normalize an absolute path by resolving `.` and `..` components.
/// RootDir and Prefix components are never popped, so `..` cannot escape the root.
fn normalize_lexical(p: &std::path::Path) -> PathBuf {
    use std::path::Component;
    let mut parts: Vec<Component> = Vec::new();
    for component in p.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                // Only pop Normal components; never pop RootDir or Prefix
                if let Some(Component::Normal(_)) = parts.last() {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }
    parts.iter().collect()
}

fn exit_error(message: &str, json_mode: bool, code: i32) -> ! {
    if json_mode {
        let err = serde_json::json!({ "error": message });
        eprintln!("{}", err);
    } else {
        eprintln!("Error: {}", message);
    }
    process::exit(code);
}
