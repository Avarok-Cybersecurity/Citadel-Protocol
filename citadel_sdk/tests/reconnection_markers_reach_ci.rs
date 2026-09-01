//! Every phase marker in the reconnection suite must survive CI's log filter.
//!
//! `validate.yml` sets `RUST_LOG: "citadel=info"`. A bare `log::info!("...")`
//! goes to the default target and is dropped, so it never appears in a CI log.
//!
//! That is not cosmetic. This flake was observed six times across four tests as
//! a 240s timeout, and could not be localised for any of them, because all 134
//! markers were bare: the log showed a session tearing down and then four
//! minutes of silence, with nothing to say which phase was waiting. Once they
//! carried a target, the very next failure placed the hang precisely — both
//! peers finish phase one, and the disconnecting side never logs the line after
//! `conn.disconnect().await?`.
//!
//! A new marker added without a target puts that blindness back, one line at a
//! time, and nothing else would notice. Hence a test rather than a habit.

use std::fs;
use std::path::Path;

/// Both forms have to be caught. The first conversion pass used a regex that
/// required the format string to follow the paren directly, so it missed four
//  wrapped calls -- and one of them was `Phase 2 complete`, exactly where the
/// evidence was needed. This scans for the macro and then looks at whatever
/// comes next, whitespace and newlines included.
#[test]
fn every_reconnection_log_call_targets_citadel() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;

    let mut files: Vec<_> = fs::read_dir(&dir)
        .expect("read tests dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                // Not this file: its own prose quotes the bad form as an
                // example, and a guard that flags its own documentation is
                // reporting on nothing.
                n.starts_with("reconnection_")
                    && n.ends_with(".rs")
                    && n != "reconnection_markers_reach_ci.rs"
            })
        })
        .collect();
    files.sort();

    assert!(
        !files.is_empty(),
        "no reconnection tests found in {dir:?}; this guard would pass by \
         examining nothing"
    );

    for file in &files {
        let src = fs::read_to_string(file).expect("read source");
        let name = file.file_name().unwrap().to_string_lossy().to_string();

        for level in ["info", "warn", "error", "debug", "trace"] {
            let needle = format!("log::{level}!(");
            let mut from = 0usize;
            while let Some(at) = src[from..].find(&needle) {
                let start = from + at;
                let after = &src[start + needle.len()..];
                let rest = after.trim_start();
                checked += 1;
                if !rest.starts_with("target:") {
                    let line = src[..start].matches('\n').count() + 1;
                    offenders.push(format!("{name}:{line}  log::{level}!"));
                }
                from = start + needle.len();
            }
        }
    }

    assert!(
        checked > 100,
        "only {checked} log calls scanned across {} files; the suite has well \
         over a hundred markers, so this guard is not seeing them",
        files.len()
    );

    assert!(
        offenders.is_empty(),
        "these log calls go to the default target and are dropped by CI's \
         RUST_LOG=citadel=info, so a wedge here would report silence instead of \
         a phase. Add `target: \"citadel\",`:\n  {}",
        offenders.join("\n  ")
    );
}
