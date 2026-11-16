//! Talus configurator — the full-screen TUI behind `talus-config`.
//!
//! `talus config set` is fine for a script; this is what an operator runs
//! interactively. It draws with the same kernel (FrankenTUI) and the same
//! palette as the dashboard, so the background choice is previewed on the whole
//! screen rather than described in prose: pressing `←`/`→` on `background`
//! repaints every panel in the candidate theme.
//!
//! Nothing is written until `s` is pressed, and nothing reaches the running
//! agent until it is restarted: the file is read at start-up, not polled.

use std::cell::Cell;
use std::path::PathBuf;

use anyhow::anyhow;
use ftui_core::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, Modifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ftui_core::geometry::Rect;
use ftui_layout::{Constraint, Flex};
use ftui_render::budget::FrameBudgetConfig;
use ftui_render::frame::Frame;
use ftui_runtime::program::{App, Cmd, Model};
use ftui_runtime::terminal_writer::ScreenMode;
use ftui_style::{Style, StyleFlags};
use ftui_text::{Line, Span, Text};
use ftui_widgets::block::Block;
use ftui_widgets::borders::{BorderType, Borders};
use ftui_widgets::paragraph::Paragraph;
use ftui_widgets::Widget;

use crate::config::{Config, Entry, OutputMode, KEYS};
use crate::theme::{Background, Theme};

/// Run the configurator until the operator quits.
pub fn run() -> anyhow::Result<()> {
    App::new(ConfigApp::new())
        .screen_mode(ScreenMode::AltScreen)
        .with_mouse()
        .with_budget(FrameBudgetConfig::relaxed())
        .run()
        .map_err(|e| anyhow!("configurator: {e}"))
}

/// One-line message shown above the key hints.
struct Notice {
    text: String,
    level: Level,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Info,
    Good,
    Warn,
    Bad,
}

impl Notice {
    fn new(text: impl Into<String>, level: Level) -> Self {
        Self {
            text: text.into(),
            level,
        }
    }

    fn info(text: impl Into<String>) -> Self {
        Self::new(text, Level::Info)
    }

    fn good(text: impl Into<String>) -> Self {
        Self::new(text, Level::Good)
    }

    fn warn(text: impl Into<String>) -> Self {
        Self::new(text, Level::Warn)
    }

    fn bad(text: impl Into<String>) -> Self {
        Self::new(text, Level::Bad)
    }
}

/// Inline value editor for one key.
struct Editor {
    key: &'static str,
    buffer: String,
    /// Cursor position in `char`s, not bytes.
    cursor: usize,
}

impl Editor {
    fn new(key: &'static str, initial: String) -> Self {
        let cursor = initial.chars().count();
        Self {
            key,
            buffer: initial,
            cursor,
        }
    }

    fn chars(&self) -> Vec<char> {
        self.buffer.chars().collect()
    }

    fn insert(&mut self, c: char) {
        let mut chars = self.chars();
        chars.insert(self.cursor.min(chars.len()), c);
        self.cursor = self.cursor.min(chars.len() - 1) + 1;
        self.buffer = chars.into_iter().collect();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let mut chars = self.chars();
        chars.remove(self.cursor - 1);
        self.cursor -= 1;
        self.buffer = chars.into_iter().collect();
    }

    fn delete(&mut self) {
        let mut chars = self.chars();
        if self.cursor < chars.len() {
            chars.remove(self.cursor);
            self.buffer = chars.into_iter().collect();
        }
    }

    fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.chars().len());
    }

    /// The buffer with a cursor marker drawn after the cursor position.
    fn display(&self) -> String {
        let chars = self.chars();
        let mut out: String = chars.iter().take(self.cursor).collect();
        out.push('▏');
        out.extend(chars.iter().skip(self.cursor));
        out
    }
}

/// The configurator application.
struct ConfigApp {
    /// Working copy — edits live here until saved.
    config: Config,
    /// Last saved state, to tell whether there is anything to save.
    saved: Config,
    selected: usize,
    editing: Option<Editor>,
    palette: Theme,
    notice: Notice,
    help: bool,
    confirm_reset: bool,
    quit_armed: bool,
    path: Option<PathBuf>,
    /// Rows of the settings list, for mouse hit-testing.
    list_area: Cell<Rect>,
    /// Inner area of the list, where entry rows start (below the header row).
    list_rows: Cell<Rect>,
}

/// Messages the runtime feeds to the model.
enum Msg {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Noop,
}

impl From<Event> for Msg {
    fn from(e: Event) -> Self {
        match e {
            Event::Key(k) => Msg::Key(k),
            Event::Mouse(m) => Msg::Mouse(m),
            _ => Msg::Noop,
        }
    }
}

impl ConfigApp {
    fn new() -> Self {
        let path = Config::path();
        let (config, notice) = match Config::load() {
            Ok(config) => {
                let count = KEYS
                    .iter()
                    .filter(|key| key != &&"background" && config.entry_value(key).is_some())
                    .count();
                let text = match &path {
                    Some(p) if p.exists() => {
                        format!("{} saved option(s) in {}", count, p.display())
                    }
                    _ => "no config file yet — Talus runs on built-in defaults".to_string(),
                };
                (config, Notice::info(text))
            }
            Err(e) => (
                Config::default(),
                Notice::bad(format!("{e:#} — saving will replace it")),
            ),
        };
        Self::from_config(config, notice, path)
    }

    fn from_config(config: Config, notice: Notice, path: Option<PathBuf>) -> Self {
        let palette = Theme::for_background(config.background);
        let saved = config.clone();
        Self {
            config,
            saved,
            selected: 0,
            editing: None,
            palette,
            notice,
            help: false,
            confirm_reset: false,
            quit_armed: false,
            path,
            list_area: Cell::new(Rect::new(0, 0, 0, 0)),
            list_rows: Cell::new(Rect::new(0, 0, 0, 0)),
        }
    }

    fn entries(&self) -> Vec<Entry> {
        self.config.entries()
    }

    fn entry(&self, key: &str) -> Option<Entry> {
        self.entries().into_iter().find(|e| e.key == key)
    }

    fn selected_key(&self) -> &'static str {
        KEYS[self.selected.min(KEYS.len() - 1)]
    }

    fn dirty(&self) -> bool {
        self.config != self.saved
    }

    fn apply_palette(&mut self) {
        self.palette = Theme::for_background(self.config.background);
    }

    fn move_selection(&mut self, delta: isize) {
        let last = KEYS.len().saturating_sub(1) as isize;
        self.selected = (self.selected as isize + delta).clamp(0, last) as usize;
    }

    /// Enter: open the editor, toggle a boolean, or step through a fixed list.
    fn activate(&mut self) {
        let key = self.selected_key();
        match key {
            "background" | "output" => self.cycle(1),
            "show_ignored" | "memlp" | "auto_kill" => self.toggle(key),
            _ => {
                let initial = self
                    .config
                    .entry_value(key)
                    .filter(|v| v != "—")
                    .unwrap_or_default();
                self.editing = Some(Editor::new(key, initial));
                self.notice =
                    Notice::info(format!("editing {key} — enter to apply, esc to cancel"));
            }
        }
    }

    fn toggle(&mut self, key: &'static str) {
        let current = match key {
            "show_ignored" => self.config.show_ignored.unwrap_or(false),
            "memlp" => self.config.memlp.unwrap_or(false),
            _ => self.config.auto_kill.unwrap_or(false),
        };
        let next = if current { "false" } else { "true" };
        match self.config.set(key, next) {
            Ok(()) => self.notice = Notice::good(format!("{key} = {next}")),
            Err(e) => self.notice = Notice::bad(format!("{e:#}")),
        }
    }

    /// Step a fixed-list option. `background` repaints immediately.
    fn cycle(&mut self, dir: isize) {
        let key = self.selected_key();
        match key {
            "background" => {
                let all = Background::ALL;
                let index = all
                    .iter()
                    .position(|b| *b == self.config.background)
                    .unwrap_or(0) as isize;
                let next = all[(index + dir).rem_euclid(all.len() as isize) as usize];
                if self.config.set("background", next.as_str()).is_ok() {
                    self.apply_palette();
                    self.notice = Notice::good(format!("background = {next}"));
                }
            }
            "output" => {
                let all = [OutputMode::Tui, OutputMode::Json, OutputMode::Plain];
                let index = all
                    .iter()
                    .position(|m| Some(*m) == self.config.output)
                    .unwrap_or(0) as isize;
                let next = all[(index + dir).rem_euclid(all.len() as isize) as usize];
                if self.config.set("output", next.as_str()).is_ok() {
                    self.notice = Notice::good(format!("output = {next}"));
                }
            }
            _ => {}
        }
    }

    fn commit_edit(&mut self) {
        let Some(editor) = self.editing.take() else {
            return;
        };
        let value = editor.buffer.trim().to_string();
        if value.is_empty() {
            self.notice = Notice::info(format!("{} left unchanged", editor.key));
            return;
        }
        // Validate on a clone so a rejected value does not half-apply.
        let mut candidate = self.config.clone();
        match candidate.set(editor.key, &value) {
            Ok(()) => {
                self.config = candidate;
                self.apply_palette();
                let shown = self
                    .config
                    .entry_value(editor.key)
                    .unwrap_or_else(|| value.clone());
                self.notice = Notice::good(format!("{} = {shown}", editor.key));
            }
            Err(e) => {
                // Keep the editor open so the value can be corrected.
                self.notice = Notice::bad(format!("{e:#}"));
                self.editing = Some(editor);
            }
        }
    }

    fn unset_selected(&mut self) {
        let key = self.selected_key();
        match self.config.unset(key) {
            Ok(()) => {
                self.apply_palette();
                self.notice = Notice::good(format!("{key} returned to the Talus default"));
            }
            Err(e) => self.notice = Notice::bad(format!("{e:#}")),
        }
    }

    fn save(&mut self) {
        match self.config.save() {
            Ok(path) => {
                self.path = Some(path.clone());
                self.saved = self.config.clone();
                self.notice = Notice::good(format!(
                    "saved to {} — restart talus (or the service) to apply",
                    path.display()
                ));
            }
            Err(e) => self.notice = Notice::bad(format!("{e:#}")),
        }
    }

    fn reset(&mut self) {
        match Config::remove() {
            Ok(removed) => {
                self.config = Config::default();
                self.saved = self.config.clone();
                self.apply_palette();
                self.notice = Notice::good(if removed {
                    "config file removed — Talus is back to built-in defaults"
                } else {
                    "there was no config file to remove"
                });
            }
            Err(e) => self.notice = Notice::bad(format!("{e:#}")),
        }
    }

    fn status_color(&self) -> ftui_render::cell::PackedRgba {
        match self.notice.level {
            Level::Info => self.palette.dim,
            Level::Good => self.palette.green,
            Level::Warn => self.palette.amber,
            Level::Bad => self.palette.red,
        }
    }

    // ── Input ─────────────────────────────────────────────────────────────

    fn on_key(&mut self, k: KeyEvent) -> Cmd<Msg> {
        if k.kind != KeyEventKind::Press {
            return Cmd::None;
        }
        if k.modifiers.contains(Modifiers::CTRL) && k.code == KeyCode::Char('c') {
            return Cmd::Quit;
        }
        if self.help {
            self.help = false;
            return Cmd::None;
        }
        if self.confirm_reset {
            self.confirm_reset = false;
            match k.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.reset(),
                _ => self.notice = Notice::info("reset cancelled"),
            }
            return Cmd::None;
        }
        if self.editing.is_some() {
            match k.code {
                KeyCode::Enter => self.commit_edit(),
                KeyCode::Escape => {
                    self.editing = None;
                    self.notice = Notice::info("edit cancelled");
                }
                code => {
                    if let Some(editor) = self.editing.as_mut() {
                        match code {
                            KeyCode::Backspace => editor.backspace(),
                            KeyCode::Delete => editor.delete(),
                            KeyCode::Left => editor.left(),
                            KeyCode::Right => editor.right(),
                            KeyCode::Home => editor.cursor = 0,
                            KeyCode::End => editor.cursor = editor.chars().len(),
                            KeyCode::Char(c) => editor.insert(c),
                            _ => {}
                        }
                    }
                }
            }
            return Cmd::None;
        }

        let armed = std::mem::take(&mut self.quit_armed);
        match k.code {
            KeyCode::Char('q') | KeyCode::Escape => {
                if self.dirty() && !armed {
                    self.quit_armed = true;
                    self.notice =
                        Notice::warn("unsaved changes — press q again to quit, s to save");
                } else {
                    return Cmd::Quit;
                }
            }
            KeyCode::Char('s') => self.save(),
            KeyCode::Char('?') | KeyCode::Char('h') => self.help = true,
            KeyCode::Char('r') => {
                self.confirm_reset = true;
                self.notice = Notice::warn("delete the config file? press y to confirm");
            }
            KeyCode::Char('u') | KeyCode::Delete => self.unset_selected(),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::Home => self.selected = 0,
            KeyCode::End => self.selected = KEYS.len() - 1,
            KeyCode::Left => self.cycle(-1),
            KeyCode::Right => self.cycle(1),
            KeyCode::Enter | KeyCode::Char(' ') => self.activate(),
            _ => {}
        }
        Cmd::None
    }

    fn on_mouse(&mut self, m: MouseEvent) {
        let rows = self.list_rows.get();
        match m.kind {
            MouseEventKind::ScrollUp => self.move_selection(-1),
            MouseEventKind::ScrollDown => self.move_selection(1),
            MouseEventKind::Down(MouseButton::Left) if rows.contains(m.x, m.y) => {
                let index = (m.y - rows.y) as usize + self.offset();
                if index < KEYS.len() {
                    self.selected = index;
                }
            }
            _ => {}
        }
    }

    // ── Drawing ───────────────────────────────────────────────────────────

    fn block(&self, title: &'static str, focused: bool) -> Block<'static> {
        let border = if focused {
            self.palette.border_hi
        } else {
            self.palette.border
        };
        Block::new()
            .title(title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(border))
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let path = self
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(no config directory)".to_string());
        let state = if self.dirty() { "● unsaved" } else { "saved" };
        let state_color = if self.dirty() {
            self.palette.amber
        } else {
            self.palette.dim
        };

        Paragraph::new(Line::from_spans(vec![
            Span::styled(
                "talus",
                Style::new().fg(self.palette.accent).attrs(StyleFlags::BOLD),
            ),
            Span::styled("  configurator", Style::new().fg(self.palette.bright)),
            Span::styled(
                "   —   values are saved once, Talus reads them at start-up",
                Style::new().fg(self.palette.dim),
            ),
        ]))
        .render(Rect::new(area.x, area.y, area.width, 1), f);

        Paragraph::new(Line::from_spans(vec![
            Span::styled(format!("  {path}"), Style::new().fg(self.palette.dim)),
            Span::styled(format!("   {state}"), Style::new().fg(state_color)),
        ]))
        .render(Rect::new(area.x, area.y + 1, area.width, 1), f);
    }

    fn draw_body(&self, f: &mut Frame, area: Rect) {
        let cols = Flex::horizontal()
            .constraints([Constraint::Percentage(58.0), Constraint::Percentage(42.0)])
            .split(area);
        self.draw_list(f, cols[0]);
        self.draw_right(f, cols[1]);
    }

    /// First visible entry index. Scrolling is stateless: the list only moves
    /// once the selection would fall off the bottom.
    fn offset(&self) -> usize {
        let visible = self.list_rows.get().height as usize;
        if visible == 0 {
            return 0;
        }
        self.selected.saturating_sub(visible.saturating_sub(1))
    }

    fn draw_list(&self, f: &mut Frame, area: Rect) {
        let block = self.block(" SETTINGS ", self.editing.is_none());
        let inner = block.inner(area);
        block.render(area, f);
        self.list_area.set(inner);
        if inner.height == 0 {
            return;
        }

        // Column header.
        Paragraph::new(Line::from_spans(vec![Span::styled(
            format!("  {:<17} {:<20} {}", "KEY", "VALUE", "SCOPE"),
            Style::new().fg(self.palette.dim),
        )]))
        .render(Rect::new(inner.x, inner.y, inner.width, 1), f);

        let rows = Rect::new(
            inner.x,
            inner.y + 1,
            inner.width,
            inner.height.saturating_sub(1),
        );
        self.list_rows.set(rows);
        let entries = self.entries();
        let offset = self.offset();
        let visible = rows.height as usize;

        for (line, entry) in entries.iter().skip(offset).take(visible).enumerate() {
            let index = offset + line;
            let selected = index == self.selected;
            let y = rows.y + line as u16;
            let rect = Rect::new(rows.x, y, rows.width, 1);
            if selected {
                let mut cell = ftui_render::cell::Cell::from_char(' ');
                cell.bg = self.palette.select_bg;
                f.buffer.fill(rect, cell);
            }
            let (key_style, value_style, marker_style) = if selected {
                (
                    Style::new().fg(self.palette.bright).attrs(StyleFlags::BOLD),
                    Style::new().fg(self.palette.accent2),
                    Style::new().fg(self.palette.accent),
                )
            } else {
                (
                    Style::new().fg(self.palette.fg),
                    Style::new().fg(self.palette.fg),
                    Style::new().fg(self.palette.border),
                )
            };
            let marker = if selected { "› " } else { "  " };
            Paragraph::new(Line::from_spans(vec![
                Span::styled(marker, marker_style),
                Span::styled(format!("{:<17} ", entry.key), key_style),
                Span::styled(format!("{:<20}", truncate(&entry.value, 20)), value_style),
                Span::styled(entry.scope, Style::new().fg(self.palette.dim)),
            ]))
            .render(rect, f);
        }

        if entries.len() > visible && visible > 0 {
            let more = entries.len() - offset - visible.min(entries.len() - offset);
            if more > 0 {
                Paragraph::new(Line::from_spans(vec![Span::styled(
                    format!("  ↓ {more} more"),
                    Style::new().fg(self.palette.dim),
                )]))
                .render(Rect::new(inner.x, inner.bottom() - 1, inner.width, 1), f);
            }
        }
    }

    fn draw_right(&self, f: &mut Frame, area: Rect) {
        let rows = Flex::vertical()
            .constraints([Constraint::Min(6), Constraint::Fixed(9)])
            .split(area);
        self.draw_preview(f, rows[0]);
        self.draw_details(f, rows[1]);
    }

    fn draw_preview(&self, f: &mut Frame, area: Rect) {
        let block = self.block(" PREVIEW ", false);
        let inner = block.inner(area);
        block.render(area, f);
        if inner.height == 0 || inner.width < 8 {
            return;
        }

        let mut lines: Vec<Line> = Vec::new();
        let span = |text: String, color| Span::styled(text, Style::new().fg(color));
        lines.push(Line::from_spans(vec![
            span("  talus ".to_string(), self.palette.accent),
            span(
                format!("— {} background", self.config.background),
                self.palette.dim,
            ),
        ]));
        lines.push(Line::from_spans(vec![
            span("  1 284 events/s".to_string(), self.palette.bright),
            span("   up 12m".to_string(), self.palette.dim),
        ]));
        lines.push(Line::from_spans(vec![span(String::new(), self.palette.fg)]));
        lines.push(Line::from_spans(vec![
            span("  cargo    ".to_string(), self.palette.fg),
            span("/src/main.rs".to_string(), self.palette.green),
        ]));
        lines.push(Line::from_spans(vec![
            span("  firefox  ".to_string(), self.palette.fg),
            span("/home/x/.cache/…".to_string(), self.palette.accent2),
        ]));
        lines.push(Line::from_spans(vec![
            span("  rsync    ".to_string(), self.palette.fg),
            span("/data/backup.tar".to_string(), self.palette.amber),
        ]));
        lines.push(Line::from_spans(vec![span(String::new(), self.palette.fg)]));
        // Selected-row sample, so the selection colour is visible too.
        lines.push(Line::from_spans(vec![
            Span::styled(
                "  python3  ",
                Style::new()
                    .fg(self.palette.bright)
                    .bg(self.palette.select_bg)
                    .attrs(StyleFlags::BOLD),
            ),
            Span::styled(
                "/etc/passwd                        ",
                Style::new().fg(self.palette.red).bg(self.palette.select_bg),
            ),
        ]));
        lines.push(Line::from_spans(vec![span(String::new(), self.palette.fg)]));
        lines.push(Line::from_spans(vec![
            span("  ████ ".to_string(), self.palette.green),
            span("███ ".to_string(), self.palette.amber),
            span("███ ".to_string(), self.palette.red),
            span("███ ".to_string(), self.palette.purple),
            span("███ ".to_string(), self.palette.accent),
            span("███".to_string(), self.palette.accent2),
        ]));
        lines.push(Line::from_spans(vec![span(
            "  ok     warn   alert  media  focus  info".to_string(),
            self.palette.dim,
        )]));

        Paragraph::new(Text::from_lines(lines)).render(inner, f);
    }

    fn draw_details(&self, f: &mut Frame, area: Rect) {
        let key = self.selected_key();
        let block = self.block(" SELECTED ", false);
        let inner = block.inner(area);
        block.render(area, f);
        if inner.height == 0 {
            return;
        }
        let entry = self.entry(key);
        let width = inner.width.saturating_sub(4) as usize;
        let value = entry
            .as_ref()
            .map(|e| e.value.clone())
            .unwrap_or_else(|| "—".to_string());

        let mut lines: Vec<Line> = Vec::new();
        let span = |text: String, color| Span::styled(text, Style::new().fg(color));
        lines.push(Line::from_spans(vec![
            span(format!("  {key}"), self.palette.accent),
            span(
                format!("   [{}]", entry.as_ref().map(|e| e.scope).unwrap_or("")),
                self.palette.dim,
            ),
        ]));
        if let Some(entry) = entry {
            for piece in wrap(entry.description, width) {
                lines.push(Line::from_spans(vec![span(
                    format!("  {piece}"),
                    self.palette.fg,
                )]));
            }
        }
        lines.push(Line::from_spans(vec![span(String::new(), self.palette.fg)]));
        lines.push(Line::from_spans(vec![
            span("  value: ".to_string(), self.palette.dim),
            span(value, self.palette.bright),
        ]));
        if let Some(allowed) = allowed_values(key) {
            for piece in wrap(&format!("allowed: {allowed}"), width) {
                lines.push(Line::from_spans(vec![span(
                    format!("  {piece}"),
                    self.palette.dim,
                )]));
            }
        }
        Paragraph::new(Text::from_lines(lines)).render(inner, f);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let hint = if self.editing.is_some() {
            "  enter apply   esc cancel   ←/→ move cursor"
        } else {
            "  ↑/↓ select   enter edit   ←/→ change   u default   s save   r reset   ? keys   q quit"
        };
        Paragraph::new(Line::from_spans(vec![Span::styled(
            hint.to_string(),
            Style::new().fg(self.palette.dim),
        )]))
        .render(Rect::new(area.x, area.y + 1, area.width, 1), f);

        let (text, color) = if let Some(editor) = &self.editing {
            (
                format!("  {} = {}", editor.key, editor.display()),
                self.palette.bright,
            )
        } else {
            (format!("  {}", self.notice.text), self.status_color())
        };
        Paragraph::new(Line::from_spans(vec![Span::styled(
            text,
            Style::new().fg(color),
        )]))
        .render(Rect::new(area.x, area.y, area.width, 1), f);
    }

    fn draw_help(&self, f: &mut Frame, area: Rect) {
        let w = area.width.min(78);
        let h = area.height.min(22);
        let rect = Rect::new(
            area.x + (area.width - w) / 2,
            area.y + (area.height - h) / 2,
            w,
            h,
        );
        let block = Block::new()
            .title(" keys ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(self.palette.accent));
        let inner = block.inner(rect);
        block.render(rect, f);

        let rows = [
            ("↑ ↓  /  k j", "move between options"),
            ("enter", "edit a value, toggle a switch, next theme"),
            ("← →", "previous / next value (background previews live)"),
            ("u  /  delete", "return the option to the Talus default"),
            ("s", "write the config file"),
            ("r", "delete the config file (asks for y)"),
            ("q  /  esc", "leave; unsaved changes need a second q"),
            ("ctrl-c", "leave immediately"),
        ];
        let mut lines = Vec::new();
        for (key, text) in rows {
            lines.push(Line::from_spans(vec![
                Span::styled(
                    format!("  {key:<14}"),
                    Style::new()
                        .fg(self.palette.accent2)
                        .attrs(StyleFlags::BOLD),
                ),
                Span::styled(text.to_string(), Style::new().fg(self.palette.fg)),
            ]));
        }
        lines.push(Line::from_spans(vec![Span::styled(
            String::new(),
            Style::new().fg(self.palette.fg),
        )]));
        lines.push(Line::from_spans(vec![Span::styled(
            "  Saved values are defaults: a flag typed on the command line still wins.",
            Style::new().fg(self.palette.dim),
        )]));
        lines.push(Line::from_spans(vec![Span::styled(
            format!(
                "  Config file: {}",
                self.path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(none)".to_string())
            ),
            Style::new().fg(self.palette.dim),
        )]));
        Paragraph::new(Text::from_lines(lines)).render(inner, f);
    }
}

impl Model for ConfigApp {
    type Message = Msg;

    fn init(&mut self) -> Cmd<Msg> {
        Cmd::None
    }

    fn update(&mut self, msg: Msg) -> Cmd<Msg> {
        match msg {
            Msg::Key(k) => self.on_key(k),
            Msg::Mouse(m) => {
                self.on_mouse(m);
                Cmd::None
            }
            Msg::Noop => Cmd::None,
        }
    }

    fn view(&self, frame: &mut Frame) {
        let area = Rect::from_size(frame.buffer.width(), frame.buffer.height());
        let mut bg = ftui_render::cell::Cell::from_char(' ');
        bg.bg = self.palette.bg;
        frame.buffer.fill(area, bg);

        let rows = Flex::vertical()
            .constraints([
                Constraint::Fixed(2), // title
                Constraint::Min(0),   // settings + preview
                Constraint::Fixed(2), // notice + hints
            ])
            .split(area);

        self.draw_header(frame, rows[0]);
        self.draw_body(frame, rows[1]);
        self.draw_footer(frame, rows[2]);
        if self.help {
            self.draw_help(frame, area);
        }
    }
}

/// Values a key accepts, for the details pane.
fn allowed_values(key: &str) -> Option<String> {
    let text = match key {
        "background" => "black, gray, white, navy",
        "output" => "tui, json, plain",
        "show_ignored" | "memlp" | "auto_kill" => "true, false",
        "alert_threshold" => "0 – 1000000 (0 never alerts)",
        "top_files" => "1 – 64",
        "ignore_comm" => "comma-separated process names",
        "filter_ext" => "a file extension, e.g. pdf",
        "memlp_checkpoint" | "bpf" => "a path",
        "web" => "HOST:PORT, e.g. 127.0.0.1:8080",
        "kafka_brokers" => "host:port[,host:port]",
        "kafka_topic" | "clickhouse" | "memgraph" => "an address or URL",
        _ => return None,
    };
    Some(text.to_string())
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let mut out: String = value.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Greedy word wrap at `width` columns (at least 20).
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(20);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(current.clone());
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use ftui_render::grapheme_pool::GraphemePool;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code)
    }

    fn app() -> ConfigApp {
        ConfigApp::from_config(
            Config::default(),
            Notice::info("test"),
            Some(PathBuf::from("/tmp/talus-test/config.conf")),
        )
    }

    fn render(app: &ConfigApp, w: u16, h: u16) -> String {
        let mut pool = GraphemePool::new();
        let mut frame = Frame::new(w, h, &mut pool);
        app.view(&mut frame);
        let mut out = String::with_capacity((w as usize + 1) * h as usize);
        for y in 0..h {
            for x in 0..w {
                let c = frame
                    .buffer
                    .get(x, y)
                    .and_then(|c| c.content.as_char())
                    .unwrap_or(' ');
                out.push(c);
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn shows_both_panes_and_every_key_is_listed() {
        let app = app();
        let screen = render(&app, 120, 40);
        assert!(screen.contains("SETTINGS"), "{screen}");
        assert!(screen.contains("PREVIEW"), "{screen}");
        assert!(screen.contains("SELECTED"), "{screen}");
        for key in KEYS {
            assert!(screen.contains(key), "missing {key}\n{screen}");
        }
    }

    #[test]
    fn arrow_keys_cycle_the_background_and_repaint() {
        let mut app = app();
        assert_eq!(app.config.background, Background::Navy);
        app.on_key(key(KeyCode::Right));
        assert_eq!(app.config.background, Background::Black);
        assert_eq!(app.palette.bg, Theme::black().bg);
        app.on_key(key(KeyCode::Left));
        assert_eq!(app.config.background, Background::Navy);
        // Wraps around in both directions.
        app.on_key(key(KeyCode::Left));
        assert_eq!(app.config.background, Background::White);
    }

    #[test]
    fn editing_rejects_a_bad_value_and_keeps_the_editor_open() {
        let mut app = app();
        app.selected = KEYS.iter().position(|k| *k == "alert_threshold").unwrap();
        app.on_key(key(KeyCode::Enter));
        assert!(app.editing.is_some());
        for c in "fifty".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        assert!(
            app.editing.is_some(),
            "editor should stay open on a bad value"
        );
        assert_eq!(app.notice.level, Level::Bad);
        assert_eq!(app.config.alert_threshold, None);

        // A valid value applies and closes the editor.
        app.editing.as_mut().unwrap().buffer = "120".into();
        app.on_key(key(KeyCode::Enter));
        assert!(app.editing.is_none());
        assert_eq!(app.config.alert_threshold, Some(120));
        assert!(app.dirty());
    }

    #[test]
    fn toggles_and_unset_work_from_the_keyboard() {
        let mut app = app();
        app.selected = KEYS.iter().position(|k| *k == "memlp").unwrap();
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.config.memlp, Some(true));
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.config.memlp, Some(false));
        app.on_key(key(KeyCode::Char('u')));
        assert_eq!(app.config.memlp, None);
    }

    #[test]
    fn quitting_with_unsaved_changes_needs_a_second_press() {
        let mut app = app();
        app.config.set("memlp", "true").unwrap();
        assert!(matches!(app.on_key(key(KeyCode::Char('q'))), Cmd::None));
        assert!(app.quit_armed);
        assert!(matches!(app.on_key(key(KeyCode::Char('q'))), Cmd::Quit));
    }

    #[test]
    fn wrapping_never_loses_words() {
        let text = "Comma-separated process names whose alerts are suppressed";
        let lines = wrap(text, 24);
        assert!(lines.iter().all(|l| l.chars().count() <= 24));
        assert_eq!(lines.join(" "), text);
    }

    #[test]
    fn saving_writes_only_what_was_changed() {
        let dir = std::env::temp_dir().join(format!("talus-tui-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.conf");
        let mut app = app();
        app.config.set("background", "gray").unwrap();
        app.config.set("memlp", "true").unwrap();
        std::fs::write(&path, app.config.render()).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.background, Background::Gray);
        assert_eq!(loaded.memlp, Some(true));
        assert!(loaded.render().contains("background = gray"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
