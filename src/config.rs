//! Persistent configuration for Talus and Talus Enterprise.
//!
//! Talus is configured with command-line flags, and a flag typed once lasts
//! exactly until the shell closes. The systemd unit then has to repeat every
//! flag forever, and the TUI background has no flag at all.
//!
//! `talus-config` closes that gap: it writes the same options to
//! `$XDG_CONFIG_HOME/talus/config.conf` (or `$TALUS_CONFIG_DIR/talus/…`), and
//! the agent reads that file at start-up and uses it as the default for
//! anything not typed on the command line. The configurator runs once, not on
//! every boot — a service restart picks the saved values up on its own.
//!
//! The file is a flat `key = value` list with `#` comments, deliberately
//! smaller than TOML so it stays readable and hand-editable:
//!
//! ```text
//! # Written by `talus-config`
//! background = navy
//! alert_threshold = 50
//! ignore_comm = rsync, cc1plus
//! ```
//!
//! Unknown keys and malformed values are hard errors: silently ignoring a typo
//! in a security agent's configuration would leave the operator believing an
//! option is in force when it is not.

use std::fmt::Write as _;
use std::io::{self, IsTerminal};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, os::unix::fs::PermissionsExt};

use anyhow::{anyhow, bail, Context, Result};

use crate::theme::Background;

/// File name inside the Talus config directory.
pub const CONFIG_FILE: &str = "config.conf";

/// Longest alert threshold accepted. A threshold in the millions can never
/// fire, which is a valid way to disable alerts, but past this it is a typo.
const MAX_THRESHOLD: u64 = 1_000_000;

/// Largest TOP FILES value that fits any terminal.
const MAX_TOP_FILES: usize = 64;

/// How monitor output is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Interactive dashboard (default when stdout is a terminal).
    Tui,
    /// Newline-delimited JSON.
    Json,
    /// Plain text log lines.
    Plain,
}

impl OutputMode {
    /// Lower-case identifier used in the config file.
    pub const fn as_str(self) -> &'static str {
        match self {
            OutputMode::Tui => "tui",
            OutputMode::Json => "json",
            OutputMode::Plain => "plain",
        }
    }
}

impl std::fmt::Display for OutputMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OutputMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tui" => Ok(OutputMode::Tui),
            "json" | "ndjson" => Ok(OutputMode::Json),
            "plain" | "text" => Ok(OutputMode::Plain),
            other => Err(format!(
                "unknown output mode '{other}' (expected one of: tui, json, plain)"
            )),
        }
    }
}

/// Saved defaults, applied under the flags typed on the command line.
///
/// Every monitor option is optional: "not set" means "let Talus decide", which
/// is exactly how the flags behaved before the file existed. `background` is
/// the exception because the TUI always needs a palette.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// TUI background palette.
    pub background: Background,
    /// Alert at N opens per second (0 disables).
    pub alert_threshold: Option<u64>,
    /// Output mode when no output flag is passed.
    pub output: Option<OutputMode>,
    /// Extension filter for file events.
    pub filter_ext: Option<String>,
    /// Rows in the TOP FILES panel.
    pub top_files: Option<usize>,
    /// Process names whose burst alerts are suppressed.
    pub ignore_comm: Vec<String>,
    /// Show suppressed processes in the process tree.
    pub show_ignored: Option<bool>,
    /// Enable the MeMLP neural engine.
    pub memlp: Option<bool>,
    /// MeMLP checkpoint location.
    pub memlp_checkpoint: Option<PathBuf>,
    /// eBPF object path.
    pub bpf: Option<PathBuf>,
    /// Dashboard bind address (Enterprise).
    pub web: Option<String>,
    /// Kill on verdict (Enterprise).
    pub auto_kill: Option<bool>,
    /// Kafka brokers (Enterprise).
    pub kafka_brokers: Option<String>,
    /// Kafka topic (Enterprise).
    pub kafka_topic: Option<String>,
    /// ClickHouse endpoint (Enterprise).
    pub clickhouse: Option<String>,
    /// MemGraph endpoint (Enterprise).
    pub memgraph: Option<String>,
}

/// One configurable option, as listed by the configurator.
pub struct Entry {
    /// Key name used with `talus config set`.
    pub key: &'static str,
    /// Value currently saved (`—` when Talus uses its own default).
    pub value: String,
    /// One-line explanation.
    pub description: &'static str,
    /// Where the option takes effect.
    pub scope: &'static str,
}

/// Names accepted by [`Config::set`], in configurator order.
pub const KEYS: &[&str] = &[
    "background",
    "alert_threshold",
    "output",
    "filter_ext",
    "top_files",
    "ignore_comm",
    "show_ignored",
    "memlp",
    "memlp_checkpoint",
    "bpf",
    "web",
    "auto_kill",
    "kafka_brokers",
    "kafka_topic",
    "clickhouse",
    "memgraph",
];

impl Config {
    /// Path of the config file, honouring `TALUS_CONFIG_DIR`.
    ///
    /// `TALUS_CONFIG_DIR` is a *base* directory, so the file lands in its
    /// `talus/` subdirectory — the same placement the licence and audit log use.
    pub fn path() -> Option<PathBuf> {
        if let Ok(dir) = std::env::var("TALUS_CONFIG_DIR") {
            if !dir.is_empty() {
                return Some(PathBuf::from(dir).join("talus").join(CONFIG_FILE));
            }
        }
        dirs::config_dir().map(|d| d.join("talus").join(CONFIG_FILE))
    }

    /// Read the saved configuration.
    ///
    /// A missing file is not an error — it means "no saved defaults". A file
    /// that exists but cannot be parsed is an error, and the caller is expected
    /// to surface it rather than start with settings nobody chose.
    pub fn load() -> Result<Self> {
        match Self::path() {
            Some(path) => Self::load_from(&path),
            None => Ok(Self::default()),
        }
    }

    /// Read a configuration from an explicit path (used by tests).
    pub fn load_from(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text)
                .with_context(|| format!("invalid configuration in {}", path.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    /// Parse the `key = value` format.
    pub fn parse(text: &str) -> Result<Self> {
        let mut config = Self::default();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                anyhow!("line {}: expected `key = value`, found `{line}`", index + 1)
            })?;
            config
                .set(key.trim(), value.trim())
                .with_context(|| format!("line {}", index + 1))?;
        }
        Ok(config)
    }

    /// Apply one `key = value` pair, validating the value.
    ///
    /// # Errors
    ///
    /// Fails on an unknown key or a value outside the accepted range.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let key = key.trim();
        let value = value.trim();
        match key {
            "background" => {
                self.background = value
                    .parse()
                    .map_err(|e: String| anyhow!(e))
                    .context("background")?;
            }
            "alert_threshold" => {
                let n = parse_u64(key, value)?;
                if n > MAX_THRESHOLD {
                    bail!("alert_threshold: {n} is above the maximum of {MAX_THRESHOLD}");
                }
                self.alert_threshold = Some(n);
            }
            "output" => {
                self.output = Some(
                    value
                        .parse::<OutputMode>()
                        .map_err(|e| anyhow!(e))
                        .context("output")?,
                );
            }
            "filter_ext" => {
                let ext = value.trim_start_matches('.').to_string();
                if ext.is_empty() {
                    bail!("filter_ext: an extension is required (for example `pdf`)");
                }
                if !ext
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    bail!("filter_ext: `{ext}` is not a plausible file extension");
                }
                self.filter_ext = Some(ext);
            }
            "top_files" => {
                let n = parse_u64(key, value)?;
                if n == 0 || n as usize > MAX_TOP_FILES {
                    bail!("top_files: expected 1..={MAX_TOP_FILES}, got {n}");
                }
                self.top_files = Some(n as usize);
            }
            "ignore_comm" => {
                self.ignore_comm = parse_list(value);
            }
            "show_ignored" => self.show_ignored = Some(parse_bool(key, value)?),
            "memlp" => self.memlp = Some(parse_bool(key, value)?),
            "auto_kill" => self.auto_kill = Some(parse_bool(key, value)?),
            "memlp_checkpoint" => self.memlp_checkpoint = Some(parse_path(key, value)?),
            "bpf" => self.bpf = Some(parse_path(key, value)?),
            "web" => {
                let addr: SocketAddr = value.parse().map_err(|_| {
                    anyhow!("web: expected HOST:PORT (for example 127.0.0.1:8080), got `{value}`")
                })?;
                self.web = Some(addr.to_string());
            }
            "kafka_brokers" => self.kafka_brokers = Some(non_empty(key, value)?),
            "kafka_topic" => self.kafka_topic = Some(non_empty(key, value)?),
            "clickhouse" => self.clickhouse = Some(non_empty(key, value)?),
            "memgraph" => self.memgraph = Some(non_empty(key, value)?),
            other => bail!("unknown key `{other}` (known keys: {})", KEYS.join(", ")),
        }
        Ok(())
    }

    /// Remove one saved option, returning it to Talus's built-in default.
    ///
    /// # Errors
    ///
    /// Fails on an unknown key.
    pub fn unset(&mut self, key: &str) -> Result<()> {
        match key.trim() {
            "background" => self.background = Background::default(),
            "alert_threshold" => self.alert_threshold = None,
            "output" => self.output = None,
            "filter_ext" => self.filter_ext = None,
            "top_files" => self.top_files = None,
            "ignore_comm" => self.ignore_comm.clear(),
            "show_ignored" => self.show_ignored = None,
            "memlp" => self.memlp = None,
            "memlp_checkpoint" => self.memlp_checkpoint = None,
            "bpf" => self.bpf = None,
            "web" => self.web = None,
            "auto_kill" => self.auto_kill = None,
            "kafka_brokers" => self.kafka_brokers = None,
            "kafka_topic" => self.kafka_topic = None,
            "clickhouse" => self.clickhouse = None,
            "memgraph" => self.memgraph = None,
            other => bail!("unknown key `{other}` (known keys: {})", KEYS.join(", ")),
        }
        Ok(())
    }

    /// Serialise to the `key = value` format, with a short header.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# Talus configuration — written by `talus-config`.\n");
        out.push_str("# Read at start-up; command-line flags override these values.\n");
        out.push_str("# Delete this file (or run `talus config reset`) to return to defaults.\n");
        if let Some(value) = self.entry_value("background") {
            let _ = writeln!(out, "background = {value}");
        }
        for key in KEYS.iter().skip(1) {
            if let Some(value) = self.entry_value(key) {
                let _ = writeln!(out, "{key} = {value}");
            }
        }
        out
    }

    /// Write the configuration atomically, creating the directory if needed.
    ///
    /// # Errors
    ///
    /// Fails when no config directory can be determined or when the file cannot
    /// be written.
    pub fn save(&self) -> Result<PathBuf> {
        let path = Self::path()
            .context("cannot determine a config directory (set TALUS_CONFIG_DIR or HOME)")?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
            // Matches the licence directory: the file names internal
            // endpoints, so it is not world-readable.
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        let tmp = path.with_extension("conf.tmp");
        fs::write(&tmp, self.render())
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        fs::rename(&tmp, &path).with_context(|| format!("cannot replace {}", path.display()))?;
        Ok(path)
    }

    /// Delete the config file, if any. Returns whether one existed.
    ///
    /// # Errors
    ///
    /// Fails when the file exists but cannot be removed.
    pub fn remove() -> Result<bool> {
        let Some(path) = Self::path() else {
            return Ok(false);
        };
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("cannot remove {}", path.display())),
        }
    }

    /// Every option with its saved value, in a stable order.
    pub fn entries(&self) -> Vec<Entry> {
        let descriptions: &[(&str, &str, &str)] = &[
            (
                "background",
                "TUI background (black, gray, white, navy)",
                "ui",
            ),
            (
                "alert_threshold",
                "Alert at N opens/second, 0 disables alerts",
                "monitor",
            ),
            ("output", "Output mode (tui, json, plain)", "monitor"),
            (
                "filter_ext",
                "Only show events with this extension",
                "monitor",
            ),
            ("top_files", "Rows in the TOP FILES panel", "monitor"),
            (
                "ignore_comm",
                "Comma-separated process names whose alerts are suppressed",
                "monitor",
            ),
            (
                "show_ignored",
                "Show ignored processes in the process tree",
                "monitor",
            ),
            ("memlp", "Enable the MeMLP neural engine", "monitor"),
            ("memlp_checkpoint", "MeMLP checkpoint path", "monitor"),
            ("bpf", "eBPF object path (default: embedded)", "monitor"),
            ("web", "Dashboard bind address", "enterprise"),
            ("auto_kill", "SIGKILL on a verdict", "enterprise"),
            ("kafka_brokers", "Kafka brokers", "enterprise"),
            ("kafka_topic", "Kafka topic", "enterprise"),
            ("clickhouse", "ClickHouse endpoint", "enterprise"),
            ("memgraph", "MemGraph endpoint", "enterprise"),
        ];
        descriptions
            .iter()
            .map(|(key, description, scope)| Entry {
                key,
                value: self.entry_value(key).unwrap_or_else(|| "—".to_string()),
                description,
                scope,
            })
            .collect()
    }

    /// Saved value of one key (`None` means "Talus default").
    pub fn entry_value(&self, key: &str) -> Option<String> {
        match key {
            "background" => Some(self.background.to_string()),
            "alert_threshold" => self.alert_threshold.map(|v| v.to_string()),
            "output" => self.output.map(|v| v.to_string()),
            "filter_ext" => self.filter_ext.clone(),
            "top_files" => self.top_files.map(|v| v.to_string()),
            "ignore_comm" if !self.ignore_comm.is_empty() => Some(self.ignore_comm.join(", ")),
            "ignore_comm" => None,
            "show_ignored" => self.show_ignored.map(|v| v.to_string()),
            "memlp" => self.memlp.map(|v| v.to_string()),
            "memlp_checkpoint" => self
                .memlp_checkpoint
                .as_ref()
                .map(|p| p.display().to_string()),
            "bpf" => self.bpf.as_ref().map(|p| p.display().to_string()),
            "web" => self.web.clone(),
            "auto_kill" => self.auto_kill.map(|v| v.to_string()),
            "kafka_brokers" => self.kafka_brokers.clone(),
            "kafka_topic" => self.kafka_topic.clone(),
            "clickhouse" => self.clickhouse.clone(),
            "memgraph" => self.memgraph.clone(),
            _ => None,
        }
    }

    /// Print the saved configuration and where it lives.
    pub fn print(&self) {
        match Self::path() {
            Some(path) => println!("Config file: {}", path.display()),
            None => println!("Config file: (no config directory found)"),
        }
        println!();
        println!("{:<18} {:<24} {:<11} DESCRIPTION", "KEY", "VALUE", "SCOPE");
        for entry in self.entries() {
            println!(
                "{:<18} {:<24} {:<11} {}",
                entry.key,
                truncate(&entry.value, 24),
                entry.scope,
                entry.description
            );
        }
        println!();
        println!("Change one:  talus config set background=black alert_threshold=100");
        println!("Interactive: talus-config");
    }
}

/// Whether an interactive configurator makes sense on this terminal.
pub fn stdin_is_interactive() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
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

fn parse_u64(key: &str, value: &str) -> Result<u64> {
    value
        .replace('_', "")
        .parse()
        .map_err(|_| anyhow!("{key}: `{value}` is not a whole number"))
}

fn parse_bool(key: &str, value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => bail!("{key}: expected true/false, got `{value}`"),
    }
}

fn parse_path(key: &str, value: &str) -> Result<PathBuf> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() {
        bail!("{key}: a path is required");
    }
    Ok(PathBuf::from(value))
}

fn non_empty(key: &str, value: &str) -> Result<String> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() {
        bail!("{key}: a value is required");
    }
    Ok(value.to_string())
}

fn parse_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim().trim_matches('"'))
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_no_monitor_overrides() {
        let config = Config::default();
        assert_eq!(config.background, Background::Navy);
        assert!(config.alert_threshold.is_none());
        assert!(config.output.is_none());
        assert!(config.ignore_comm.is_empty());
        assert_eq!(config.entry_value("alert_threshold"), None);
        // The background is always resolvable, so it never prints as unset.
        assert_eq!(config.entry_value("background").as_deref(), Some("navy"));
    }

    #[test]
    fn round_trips_through_the_file_format() {
        let mut config = Config::default();
        config.set("background", "black").unwrap();
        config.set("alert_threshold", "120").unwrap();
        config.set("output", "json").unwrap();
        config.set("top_files", "12").unwrap();
        config.set("ignore_comm", "rsync, cc1plus").unwrap();
        config.set("memlp", "true").unwrap();
        config.set("web", "127.0.0.1:8080").unwrap();
        config.set("clickhouse", "http://localhost:8123").unwrap();

        let text = config.render();
        assert!(text.contains("background = black"));
        assert!(text.contains("ignore_comm = rsync, cc1plus"));
        assert_eq!(Config::parse(&text).unwrap(), config);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let config = Config::parse("# a comment\n\n  background = white  \n").unwrap();
        assert_eq!(config.background, Background::White);
    }

    #[test]
    fn unknown_keys_are_rejected_with_the_key_list() {
        let err = Config::parse("backgrund = black").unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("unknown key `backgrund`"), "{text}");
        assert!(text.contains("background"), "{text}");
    }

    #[test]
    fn malformed_values_are_rejected() {
        for bad in [
            "background = blue",
            "alert_threshold = fifty",
            "alert_threshold = 2000000",
            "output = xml",
            "top_files = 0",
            "memlp = maybe",
            "web = localhost",
            "filter_ext = ../etc/passwd",
        ] {
            assert!(
                Config::parse(bad).is_err(),
                "`{bad}` should have been rejected"
            );
        }
    }

    #[test]
    fn values_are_normalised() {
        let mut config = Config::default();
        config.set("background", " GREY ").unwrap();
        config.set("filter_ext", ".PDF").unwrap();
        config.set("web", "0.0.0.0:443").unwrap();
        config.set("ignore_comm", " rsync ,, cc1plus , ").unwrap();
        assert_eq!(config.background, Background::Gray);
        assert_eq!(config.filter_ext.as_deref(), Some("PDF"));
        assert_eq!(config.web.as_deref(), Some("0.0.0.0:443"));
        assert_eq!(config.ignore_comm, vec!["rsync", "cc1plus"]);
    }

    #[test]
    fn unset_restores_defaults() {
        let mut config = Config::parse(
            "background = white\nalert_threshold = 5\nignore_comm = rsync\nmemlp = true\n",
        )
        .unwrap();
        for key in KEYS {
            config.unset(key).unwrap();
        }
        assert_eq!(config, Config::default());
        assert!(config.unset("nope").is_err());
    }

    #[test]
    fn a_missing_file_is_defaults_not_an_error() {
        let dir = std::env::temp_dir().join(format!("talus-cfg-test-{}", std::process::id()));
        let path = dir.join("does-not-exist.conf");
        assert_eq!(Config::load_from(&path).unwrap(), Config::default());
    }

    #[test]
    fn entries_cover_every_key() {
        let config = Config::default();
        let entries = config.entries();
        let listed: Vec<&str> = entries.iter().map(|e| e.key).collect();
        assert_eq!(listed, KEYS);
        assert!(entries.iter().all(|e| !e.description.is_empty()));
        assert_eq!(
            entries.iter().filter(|e| e.scope == "enterprise").count(),
            6
        );
    }
}
