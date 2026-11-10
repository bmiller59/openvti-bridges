//! The kill switch: whether a link is paused, read fresh every time.
//!
//! `link pause` must stop a *running* bridge. The store is locked by the
//! running process (fjall), so a control record written by another process
//! would have to go through a side channel anyway; the config file is the one
//! place `link pause` / `link resume` already write (atomically: a temp file
//! renamed over the original), so the running link re-reads that file. This
//! is [`ConfigFilePause`]: on every check it reads and validates the config
//! and looks at the link's `enabled` flag. There is no cache, no mtime test
//! (a same-second edit of the same length would be missed) and no watcher
//! thread: a small file read per check is cheap against a relay round trip,
//! and "the check read it just now" is easy to reason about.
//!
//! **Fail-safe.** Anything but a clean read of `enabled = true` is PAUSED:
//! the file cannot be read or parsed, fails validation, no longer names the
//! link. A kill switch that fails open is not one. The cost is that a broken
//! config pauses a running bridge, which is the safe side of that trade, and
//! the log says why.
//!
//! The pump checks the gate at the start of a tick, before every outbound
//! post and before every write into the VTC room; the supervisor checks it
//! before starting a session and before every tick. A step that has already
//! begun finishes (a half-posted line is wasted work), so pause takes effect
//! at the next step: within one tick, and in practice at the next post.

use crate::config::Config;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Whether a link may act right now. Implementations answer from current
/// state and never cache a "running" verdict.
pub trait PauseSource: Send + Sync {
    /// `true` when the link must not send anything.
    fn is_paused(&self) -> bool;
}

/// No gate: never paused. The default of a pump built without one (tests, an
/// embedding that has no config file).
#[derive(Debug, Default, Clone, Copy)]
pub struct NeverPaused;

impl PauseSource for NeverPaused {
    fn is_paused(&self) -> bool {
        false
    }
}

/// An in-memory switch, for tests and embedders.
#[derive(Debug, Default)]
pub struct PauseSwitch(AtomicBool);

impl PauseSwitch {
    /// A switch, running or paused.
    pub fn new(paused: bool) -> Self {
        Self(AtomicBool::new(paused))
    }
    /// Pause or resume.
    pub fn set(&self, paused: bool) {
        self.0.store(paused, Ordering::SeqCst);
    }
}

impl PauseSource for PauseSwitch {
    fn is_paused(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What the last read found, kept only to log changes once.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Running,
    Paused,
    Unreadable(String),
}

/// The link's `enabled` flag, read from the config file on every check.
#[derive(Debug)]
pub struct ConfigFilePause {
    path: PathBuf,
    link_id: String,
    last: Mutex<Option<Seen>>,
}

impl ConfigFilePause {
    /// Gate for `link_id`, read from the config at `path`.
    pub fn new(path: impl Into<PathBuf>, link_id: &str) -> Self {
        Self {
            path: path.into(),
            link_id: link_id.into(),
            last: Mutex::new(None),
        }
    }

    fn read(&self) -> Seen {
        match Config::load(&self.path) {
            Err(e) => Seen::Unreadable(e.to_string()),
            Ok(cfg) => match cfg.links.iter().find(|l| l.id == self.link_id) {
                None => {
                    Seen::Unreadable(format!("the config no longer names link {}", self.link_id))
                }
                Some(l) if l.enabled => Seen::Running,
                Some(_) => Seen::Paused,
            },
        }
    }
}

impl PauseSource for ConfigFilePause {
    fn is_paused(&self) -> bool {
        let seen = self.read();
        let paused = !matches!(seen, Seen::Running);
        if let Ok(mut last) = self.last.lock()
            && last.as_ref() != Some(&seen)
        {
            match &seen {
                Seen::Running => tracing::info!(link = %self.link_id, "link resumed"),
                Seen::Paused => tracing::warn!(link = %self.link_id, "link paused (`link pause`)"),
                Seen::Unreadable(why) => tracing::error!(
                    link = %self.link_id,
                    reason = %why,
                    "the pause flag cannot be read; the link is treated as PAUSED until it can"
                ),
            }
            *last = Some(seen);
        }
        paused
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"
[vta]
did = "did:webvh:vta.example"

[[links]]
id = "l1"
vtc_room = "room-1"
host_did = "did:webvh:host.example"
persona = "did:key:z6Mkpersona"
kind = "loopback"
loopback = { room = "geb-1" }
tier = "open"
directions = "both"
tier_optin = true
enabled = true
"#;

    fn dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "geb-pause-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_flag_is_read_fresh_and_anything_unreadable_is_paused() {
        let d = dir();
        let p = d.join("c.toml");
        let gate = ConfigFilePause::new(&p, "l1");
        assert!(gate.is_paused(), "no file: paused");
        std::fs::write(&p, CFG).unwrap();
        assert!(!gate.is_paused());
        std::fs::write(&p, CFG.replace("enabled = true", "enabled = false")).unwrap();
        assert!(gate.is_paused(), "a same-size rewrite is seen at once");
        std::fs::write(&p, CFG).unwrap();
        assert!(!gate.is_paused());
        std::fs::write(&p, "this is { not toml").unwrap();
        assert!(gate.is_paused(), "unparsable: paused");
        std::fs::write(&p, CFG.replace("tier_optin = true", "tier_optin = false")).unwrap();
        assert!(gate.is_paused(), "fails validation: paused");
        std::fs::write(&p, CFG.replace("id = \"l1\"", "id = \"l2\"")).unwrap();
        assert!(gate.is_paused(), "link gone: paused");
        assert!(!ConfigFilePause::new(&p, "l2").is_paused());
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn the_switch_and_the_default() {
        assert!(!NeverPaused.is_paused());
        let s = PauseSwitch::new(true);
        assert!(s.is_paused());
        s.set(false);
        assert!(!s.is_paused());
    }
}
