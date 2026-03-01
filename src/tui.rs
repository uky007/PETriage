use std::io::{self, stdout};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    ExecutableCommand,
};
use goblin::pe::PE;
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

struct Region {
    name: String,
    offset: usize,
    size: usize,
}

struct App {
    regions: Vec<Region>,
    list_state: ListState,
    hex_scroll: usize,
    quit: bool,
}

impl App {
    fn new(regions: Vec<Region>) -> Self {
        let mut list_state = ListState::default();
        if !regions.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            regions,
            list_state,
            hex_scroll: 0,
            quit: false,
        }
    }

    fn selected_region(&self) -> Option<&Region> {
        self.list_state.selected().and_then(|i| self.regions.get(i))
    }

    fn select_prev(&mut self) {
        if let Some(i) = self.list_state.selected()
            && i > 0 {
                self.list_state.select(Some(i - 1));
                self.hex_scroll = 0;
            }
    }

    fn select_next(&mut self) {
        if let Some(i) = self.list_state.selected()
            && i + 1 < self.regions.len() {
                self.list_state.select(Some(i + 1));
                self.hex_scroll = 0;
            }
    }

    fn hex_lines_count(&self) -> usize {
        self.selected_region()
            .map(|r| r.size.div_ceil(16))
            .unwrap_or(0)
    }

    fn scroll_down(&mut self, n: usize) {
        let max = self.hex_lines_count().saturating_sub(1);
        self.hex_scroll = (self.hex_scroll + n).min(max);
    }

    fn scroll_up(&mut self, n: usize) {
        self.hex_scroll = self.hex_scroll.saturating_sub(n);
    }

    fn scroll_home(&mut self) {
        self.hex_scroll = 0;
    }

    fn scroll_end(&mut self) {
        self.hex_scroll = self.hex_lines_count().saturating_sub(1);
    }
}

fn build_regions(data: &[u8], pe: &PE) -> Vec<Region> {
    let mut regions = Vec::new();

    // DOS Header
    let e_lfanew = pe.header.dos_header.pe_pointer as usize;
    if e_lfanew > 0 && e_lfanew <= data.len() {
        regions.push(Region {
            name: "DOS Header".to_string(),
            offset: 0,
            size: e_lfanew,
        });
    }

    // PE Signature
    if e_lfanew + 4 <= data.len() {
        regions.push(Region {
            name: "PE Signature".to_string(),
            offset: e_lfanew,
            size: 4,
        });
    }

    // COFF Header
    let coff_offset = e_lfanew + 4;
    if coff_offset + 20 <= data.len() {
        regions.push(Region {
            name: "COFF Header".to_string(),
            offset: coff_offset,
            size: 20,
        });
    }

    // Optional Header
    let opt_offset = coff_offset + 20;
    let opt_size = pe.header.coff_header.size_of_optional_header as usize;
    if opt_size > 0 && opt_offset + opt_size <= data.len() {
        regions.push(Region {
            name: "Optional Header".to_string(),
            offset: opt_offset,
            size: opt_size,
        });
    }

    // Section Headers
    let sec_hdr_offset = opt_offset + opt_size;
    let num_sections = pe.header.coff_header.number_of_sections as usize;
    let sec_hdr_size = num_sections * 40;
    if num_sections > 0 && sec_hdr_offset + sec_hdr_size <= data.len() {
        regions.push(Region {
            name: format!("Sec Hdrs ({})", num_sections),
            offset: sec_hdr_offset,
            size: sec_hdr_size,
        });
    }

    // Individual Sections
    let mut end_of_pe: usize = 0;
    for section in &pe.sections {
        let raw_addr = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        if raw_size == 0 || raw_addr + raw_size > data.len() {
            continue;
        }
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        regions.push(Region {
            name: format!("Section: {}", name),
            offset: raw_addr,
            size: raw_size,
        });
        end_of_pe = end_of_pe.max(raw_addr + raw_size);
    }

    // Overlay
    if end_of_pe > 0 && end_of_pe < data.len() {
        regions.push(Region {
            name: "Overlay".to_string(),
            offset: end_of_pe,
            size: data.len() - end_of_pe,
        });
    }

    regions
}

fn format_size(size: usize) -> String {
    if size >= 1024 * 1024 {
        format!("{:.1}M", size as f64 / (1024.0 * 1024.0))
    } else if size >= 1024 {
        format!("{:.1}K", size as f64 / 1024.0)
    } else {
        format!("{}B", size)
    }
}

fn render_hex_lines<'a>(data: &'a [u8], region: &Region, scroll: usize, max_lines: usize) -> Vec<Line<'a>> {
    let offset_style = Style::default().fg(Color::Cyan);
    let ascii_style = Style::default().fg(Color::DarkGray);
    let default_style = Style::default();

    let total_lines = region.size.div_ceil(16);
    let start_line = scroll.min(total_lines);
    let end_line = (start_line + max_lines).min(total_lines);

    let mut lines = Vec::with_capacity(end_line - start_line);

    for line_idx in start_line..end_line {
        let line_offset = line_idx * 16;
        let abs_offset = region.offset + line_offset;
        let remaining = region.size - line_offset;
        let count = remaining.min(16);

        let bytes = if abs_offset + count <= data.len() {
            &data[abs_offset..abs_offset + count]
        } else {
            let end = data.len().min(abs_offset + count);
            if abs_offset >= end {
                continue;
            }
            &data[abs_offset..end]
        };

        // Offset
        let mut spans = vec![Span::styled(format!("{:08x}  ", abs_offset), offset_style)];

        // Hex bytes
        let mut hex = String::with_capacity(49);
        for (i, &b) in bytes.iter().enumerate() {
            hex.push_str(&format!("{:02x} ", b));
            if i == 7 {
                hex.push(' ');
            }
        }
        // Pad if less than 16 bytes
        for i in bytes.len()..16 {
            hex.push_str("   ");
            if i == 7 {
                hex.push(' ');
            }
        }
        spans.push(Span::styled(hex, default_style));

        // ASCII sidebar
        let mut ascii = String::with_capacity(18);
        ascii.push('|');
        for &b in bytes {
            if b.is_ascii_graphic() || b == b' ' {
                ascii.push(b as char);
            } else {
                ascii.push('.');
            }
        }
        for _ in bytes.len()..16 {
            ascii.push(' ');
        }
        ascii.push('|');
        spans.push(Span::styled(ascii, ascii_style));

        lines.push(Line::from(spans));
    }

    lines
}

fn draw(f: &mut Frame, app: &App, data: &[u8], file_name: &str) {
    let area = f.area();

    // Title bar
    let title = format!(
        " petriage  {}  [Up/Down: select] [j/k/PgUp/PgDn: scroll] [q: quit] ",
        file_name
    );
    let outer = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    // Split into left and right panes
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(1)])
        .split(inner);

    draw_region_list(f, app, chunks[0]);
    draw_hex_pane(f, app, data, chunks[1]);
}

fn draw_region_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .regions
        .iter()
        .map(|r| {
            let size_str = format_size(r.size);
            let label = format!("{:<17} {:>6}", truncate(&r.name, 17), size_str);
            ListItem::new(label)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Regions ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    let mut state = app.list_state.clone();
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_hex_pane(f: &mut Frame, app: &App, data: &[u8], area: Rect) {
    let header_title = if let Some(r) = app.selected_region() {
        format!(" {} @ 0x{:x} ({} bytes) ", r.name, r.offset, r.size)
    } else {
        " No region selected ".to_string()
    };

    let block = Block::default()
        .title(header_title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let hex_area = block.inner(area);
    f.render_widget(block, area);

    if let Some(region) = app.selected_region() {
        let max_lines = hex_area.height as usize;
        let lines = render_hex_lines(data, region, app.hex_scroll, max_lines);

        // Scrollbar indicator
        let total = app.hex_lines_count();
        let scroll_info = if total > max_lines {
            format!(
                " [{}-{}/{}] ",
                app.hex_scroll + 1,
                (app.hex_scroll + max_lines).min(total),
                total
            )
        } else {
            String::new()
        };

        if !scroll_info.is_empty() {
            let info_span = Span::styled(scroll_info, Style::default().fg(Color::DarkGray));
            let info_para = Paragraph::new(Line::from(info_span));
            let info_area = Rect {
                x: hex_area.x,
                y: hex_area.y + hex_area.height.saturating_sub(1),
                width: hex_area.width,
                height: 1,
            };
            // Only show if there's enough room
            if hex_area.height > 2 {
                let content_lines = render_hex_lines(data, region, app.hex_scroll, max_lines.saturating_sub(1));
                let content = Paragraph::new(content_lines);
                f.render_widget(content, Rect {
                    x: hex_area.x,
                    y: hex_area.y,
                    width: hex_area.width,
                    height: hex_area.height.saturating_sub(1),
                });
                f.render_widget(info_para, info_area);
                return;
            }
        }

        let paragraph = Paragraph::new(lines);
        f.render_widget(paragraph, hex_area);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}~", &s[..max - 1])
    }
}

pub fn run(data: &[u8], pe: &PE, file_name: &str) -> io::Result<()> {
    let regions = build_regions(data, pe);
    if regions.is_empty() {
        eprintln!("Error: No PE regions found — file may be corrupted");
        return Ok(());
    }

    // Install panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new(regions);

    while !app.quit {
        terminal.draw(|f| draw(f, &app, data, file_name))?;

        if event::poll(std::time::Duration::from_millis(100))?
            && let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                let page_size = terminal.size().map(|s| s.height as usize).unwrap_or(24).saturating_sub(4);
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.quit = true;
                    }
                    KeyCode::Up => app.select_prev(),
                    KeyCode::Down => app.select_next(),
                    KeyCode::Char('j') => app.scroll_down(1),
                    KeyCode::Char('k') => app.scroll_up(1),
                    KeyCode::PageDown => app.scroll_down(page_size),
                    KeyCode::PageUp => app.scroll_up(page_size),
                    KeyCode::Home => app.scroll_home(),
                    KeyCode::End => app.scroll_end(),
                    _ => {}
                }
            }
    }

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    Ok(())
}
