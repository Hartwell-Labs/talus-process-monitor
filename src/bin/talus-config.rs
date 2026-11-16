//! `talus-config` — the interactive Talus configurator.
//!
//! A separate binary on purpose: the monitor is installed setuid-free and
//! normally started by systemd, while the configurator is what a human runs
//! once. Keeping it out of `talus-monitor` means the dashboard binary never
//! carries an editor, and `talus-config` can be shipped (or absent) on its own.
//!
//! It writes the same `config.conf` that `talus config set` writes, so the two
//! can be mixed freely.

fn main() -> anyhow::Result<()> {
    talus_process_monitor::config_tui::run()
}
