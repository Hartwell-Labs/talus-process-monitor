//! Embedded ransomware marker and ransom-note sets.
//!
//! The canonical database is `data/ransomware/knowledge.ext`, written in
//! Externum. Externum exports `knowledge.markers` and `knowledge.notes`: sorted,
//! one-entry-per-line artifacts containing only what the detector needs. The
//! full database (`knowledge.json`) stays outside the binary for analysts and
//! tools.
//!
//! This module deliberately uses only `std`: small `Vec<&str>` indexes are built
//! on first use and every lookup is a binary search. No JSON parser, no extra
//! crate, no per-event allocation.

use std::sync::OnceLock;

const MARKERS: &str = include_str!("../data/ransomware/knowledge.markers");
const NOTES: &str = include_str!("../data/ransomware/knowledge.notes");

static MARKER_INDEX: OnceLock<Vec<&'static str>> = OnceLock::new();
static NOTE_INDEX: OnceLock<Vec<&'static str>> = OnceLock::new();

fn index() -> &'static [&'static str] {
    MARKER_INDEX.get_or_init(|| {
        MARKERS
            .lines()
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
    })
}

fn note_index() -> &'static [&'static str] {
    NOTE_INDEX.get_or_init(|| {
        NOTES
            .lines()
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
    })
}

/// Number of family-specific marker extensions in the runtime artifact.
pub fn marker_count() -> usize {
    index().len()
}

/// Iterate over every marker extension in the runtime artifact.
pub fn markers() -> impl Iterator<Item = &'static str> {
    index().iter().copied()
}

/// Whether the basename of `path` is a distinctive known ransom note.
///
/// Generic names such as `README.txt` are excluded in the Externum export;
/// only family-specific notes reach this lookup.
pub fn is_ransom_note(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if name.is_empty() {
        return false;
    }
    let index = note_index();
    if index.binary_search(&name).is_ok() {
        return true;
    }
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        return index
            .binary_search(&name.to_ascii_lowercase().as_str())
            .is_ok();
    }
    false
}

/// Whether `ext` is a family-specific ransomware marker.
///
/// The monitor lowercases extensions before calling this, so the common path
/// is one borrowed binary search with no allocation. A leading dot and
/// mixed-case callers are accepted for API safety.
pub fn is_ransomware_extension(ext: &str) -> bool {
    let ext = ext.strip_prefix('.').unwrap_or(ext);
    if ext.is_empty() {
        return false;
    }
    let index = index();
    if index.binary_search(&ext).is_ok() {
        return true;
    }
    if ext.bytes().any(|b| b.is_ascii_uppercase()) {
        return index
            .binary_search(&ext.to_ascii_lowercase().as_str())
            .is_ok();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_artifact_is_sorted_and_unique() {
        let markers: Vec<_> = markers().collect();
        assert!(
            markers.len() >= 70,
            "expected >=70 markers, got {}",
            markers.len()
        );
        assert_eq!(markers.len(), marker_count());
        for pair in markers.windows(2) {
            assert!(pair[0] < pair[1], "unsorted or duplicate: {:?}", pair);
        }
    }

    #[test]
    fn marker_lookup_is_normalised_and_safe() {
        assert!(is_ransomware_extension("gandcrab"));
        assert!(is_ransomware_extension("GANDCRAB"));
        assert!(is_ransomware_extension(".GandCrab"));
        assert!(is_ransomware_extension("lockbitblack"));
        assert!(!is_ransomware_extension("pdf"));
        assert!(!is_ransomware_extension(""));
    }

    #[test]
    fn every_runtime_marker_is_recognised() {
        for marker in markers() {
            assert!(is_ransomware_extension(marker), "{marker}");
        }
    }

    #[test]
    fn ransom_note_lookup_is_basename_only_and_normalised() {
        assert!(is_ransom_note("/tmp/Restore-My-Files.txt"));
        assert!(is_ransom_note("C:\\tmp\\GANDCRAB.txt"));
        assert!(is_ransom_note("!!!READ_ME_MEDUSA!!!.txt"));
        assert!(!is_ransom_note("/tmp/README.txt"));
        assert!(!is_ransom_note("note.txt"));
        assert!(!is_ransom_note(""));
    }
}
