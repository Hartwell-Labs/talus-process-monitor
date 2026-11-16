//! TUI colour themes.
//!
//! Talus ships four backgrounds: black, gray, white and navy. A theme is more
//! than the fill colour — text, borders and selection all have to stay legible
//! against it — so the whole palette travels together.
//!
//! The dashboard is a single-screen, single-process TUI, so the active theme is
//! held in a process-wide cell rather than threaded through every draw call.
//! `install` is called once by `tui::run` before the first frame; every accessor
//! falls back to the default navy theme when nothing was installed (tests, or a
//! caller that renders before the UI starts).

use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

use ftui_render::cell::PackedRgba;

/// Background choices offered by `talus config` and `--theme`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Background {
    /// Pure black — maximum contrast on OLED panels.
    Black,
    /// Neutral dark gray.
    Gray,
    /// Light background with dark text.
    White,
    /// Deep matte navy — the default Talus look.
    #[default]
    Navy,
}

impl Background {
    /// Every valid value, in the order the configurator lists them.
    pub const ALL: [Background; 4] = [
        Background::Black,
        Background::Gray,
        Background::White,
        Background::Navy,
    ];

    /// Lower-case identifier used in the config file and on the command line.
    pub const fn as_str(self) -> &'static str {
        match self {
            Background::Black => "black",
            Background::Gray => "gray",
            Background::White => "white",
            Background::Navy => "navy",
        }
    }

    /// Short human-readable label for the configurator.
    pub const fn label(self) -> &'static str {
        match self {
            Background::Black => "black (#000000)",
            Background::Gray => "gray (#2b2b2b)",
            Background::White => "white (#fafafa)",
            Background::Navy => "navy (#1a1b26)",
        }
    }
}

impl fmt::Display for Background {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Background {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "black" => Ok(Background::Black),
            "gray" | "grey" => Ok(Background::Gray),
            "white" => Ok(Background::White),
            "navy" => Ok(Background::Navy),
            other => Err(format!(
                "unknown background '{other}' (expected one of: black, gray, white, navy)"
            )),
        }
    }
}

/// clap value parser, so `--theme` shares the config file's vocabulary.
pub fn parse_background(s: &str) -> Result<Background, String> {
    s.parse()
}

/// A complete palette. Colours are RGB triples so they render identically over
/// SSH as on a local terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Background identifier (also shown in `talus config show`).
    pub name: Background,
    /// Screen and panel fill.
    pub bg: PackedRgba,
    /// Body text.
    pub fg: PackedRgba,
    /// Values that must stand out (counters, titles).
    pub bright: PackedRgba,
    /// Secondary text and inactive markers.
    pub dim: PackedRgba,
    /// Inactive panel borders.
    pub border: PackedRgba,
    /// Border of the focused panel.
    pub border_hi: PackedRgba,
    /// Background of the selected process row.
    pub select_bg: PackedRgba,
    /// Primary accent (title wave, charts, links).
    pub accent: PackedRgba,
    /// Secondary accent (highlights, network event tags).
    pub accent2: PackedRgba,
    /// Healthy / benign semantic colour.
    pub green: PackedRgba,
    /// Alert / threat semantic colour.
    pub red: PackedRgba,
    /// Warning semantic colour.
    pub amber: PackedRgba,
    /// Media / misc semantic colour.
    pub purple: PackedRgba,
}

impl Theme {
    /// Deep matte navy — the original Talus palette.
    pub const fn navy() -> Self {
        Self {
            name: Background::Navy,
            bg: PackedRgba::rgb(26, 27, 38),
            fg: PackedRgba::rgb(169, 177, 214),
            bright: PackedRgba::rgb(192, 202, 245),
            dim: PackedRgba::rgb(86, 95, 137),
            border: PackedRgba::rgb(41, 46, 66),
            border_hi: PackedRgba::rgb(122, 162, 247),
            select_bg: PackedRgba::rgb(48, 56, 92),
            accent: PackedRgba::rgb(122, 162, 247),
            accent2: PackedRgba::rgb(100, 210, 245),
            green: PackedRgba::rgb(80, 200, 120),
            red: PackedRgba::rgb(220, 20, 45),
            amber: PackedRgba::rgb(250, 180, 50),
            purple: PackedRgba::rgb(160, 120, 240),
        }
    }

    /// Pure black with high-contrast text.
    pub const fn black() -> Self {
        Self {
            name: Background::Black,
            bg: PackedRgba::rgb(0, 0, 0),
            fg: PackedRgba::rgb(200, 200, 200),
            bright: PackedRgba::rgb(245, 245, 245),
            dim: PackedRgba::rgb(125, 125, 125),
            border: PackedRgba::rgb(48, 48, 48),
            border_hi: PackedRgba::rgb(110, 180, 255),
            select_bg: PackedRgba::rgb(38, 38, 38),
            accent: PackedRgba::rgb(110, 180, 255),
            accent2: PackedRgba::rgb(95, 215, 240),
            green: PackedRgba::rgb(90, 210, 130),
            red: PackedRgba::rgb(235, 60, 80),
            amber: PackedRgba::rgb(250, 190, 70),
            purple: PackedRgba::rgb(175, 140, 250),
        }
    }

    /// Neutral dark gray — softer than black, same contrast structure.
    pub const fn gray() -> Self {
        Self {
            name: Background::Gray,
            bg: PackedRgba::rgb(43, 43, 43),
            fg: PackedRgba::rgb(208, 208, 208),
            bright: PackedRgba::rgb(242, 242, 242),
            dim: PackedRgba::rgb(145, 145, 148),
            border: PackedRgba::rgb(72, 72, 74),
            border_hi: PackedRgba::rgb(135, 180, 255),
            select_bg: PackedRgba::rgb(64, 64, 68),
            accent: PackedRgba::rgb(135, 180, 255),
            accent2: PackedRgba::rgb(110, 210, 240),
            green: PackedRgba::rgb(95, 210, 135),
            red: PackedRgba::rgb(235, 70, 90),
            amber: PackedRgba::rgb(250, 195, 90),
            purple: PackedRgba::rgb(180, 145, 250),
        }
    }

    /// Light background with dark text — for bright offices and projectors.
    pub const fn white() -> Self {
        Self {
            name: Background::White,
            bg: PackedRgba::rgb(250, 250, 250),
            fg: PackedRgba::rgb(48, 48, 54),
            bright: PackedRgba::rgb(20, 20, 24),
            dim: PackedRgba::rgb(112, 112, 122),
            border: PackedRgba::rgb(200, 200, 206),
            border_hi: PackedRgba::rgb(40, 90, 200),
            select_bg: PackedRgba::rgb(216, 222, 238),
            accent: PackedRgba::rgb(40, 90, 200),
            accent2: PackedRgba::rgb(20, 125, 155),
            green: PackedRgba::rgb(15, 125, 65),
            red: PackedRgba::rgb(190, 20, 40),
            amber: PackedRgba::rgb(160, 105, 0),
            purple: PackedRgba::rgb(110, 65, 190),
        }
    }

    /// The palette for a background choice.
    pub const fn for_background(background: Background) -> Self {
        match background {
            Background::Black => Self::black(),
            Background::Gray => Self::gray(),
            Background::White => Self::white(),
            Background::Navy => Self::navy(),
        }
    }
}

static CURRENT: OnceLock<Theme> = OnceLock::new();

/// Select the palette for this process. Later calls are ignored: the theme is
/// fixed for the lifetime of the dashboard, which avoids repainting with a
/// half-applied palette.
pub fn install(background: Background) {
    let _ = CURRENT.set(Theme::for_background(background));
}

/// The active theme (navy until [`install`] runs).
pub fn current() -> &'static Theme {
    CURRENT.get_or_init(Theme::navy)
}

/// Active background.
pub fn background() -> Background {
    current().name
}

macro_rules! accessor {
    ($($fn_name:ident => $field:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Active theme's `", stringify!($field), "` colour.")]
            pub fn $fn_name() -> PackedRgba {
                current().$field
            }
        )+
    };
}

accessor! {
    bg => bg,
    fg => fg,
    bright => bright,
    dim => dim,
    border => border,
    border_hi => border_hi,
    select_bg => select_bg,
    accent => accent,
    accent2 => accent2,
    green => green,
    red => red,
    amber => amber,
    purple => purple,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_background_and_its_aliases() {
        for background in Background::ALL {
            assert_eq!(background.as_str().parse::<Background>(), Ok(background));
        }
        assert_eq!("grey".parse::<Background>(), Ok(Background::Gray));
        assert_eq!(" NAVY ".parse::<Background>(), Ok(Background::Navy));
        assert!("blue".parse::<Background>().is_err());
    }

    #[test]
    fn themes_are_distinct_and_keep_text_off_the_fill() {
        let mut fills = Vec::new();
        for background in Background::ALL {
            let theme = Theme::for_background(background);
            assert_eq!(theme.name, background);
            assert!(
                !fills.contains(&theme.bg),
                "{background} reuses another theme's fill colour"
            );
            fills.push(theme.bg);
            assert_ne!(theme.fg, theme.bg, "{background} text would be invisible");
            assert_ne!(theme.border, theme.bg, "{background} borders would vanish");
            assert_ne!(
                theme.select_bg, theme.bg,
                "{background} selection would be invisible"
            );
        }

        // The light palette is the one that inverts the default look.
        assert_eq!(Theme::white().bg, PackedRgba::rgb(250, 250, 250));
        assert_eq!(Theme::black().bg, PackedRgba::rgb(0, 0, 0));
    }

    #[test]
    fn accessors_default_to_navy() {
        assert_eq!(current().name, Background::Navy);
        assert_eq!(bg(), Theme::navy().bg);
        assert_eq!(accent(), Theme::navy().accent);
    }
}
