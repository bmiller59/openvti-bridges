//! Supervision of one link's pump (feature `vtc`), after `vti-witness`:
//! graceful shutdown on every path out, a minimum healthy session before the
//! backoff resets, a halted link stays halted, and no latched health flag.
//!
//! - **Shutdown.** The stop signal is observed at every wait (the poll sleep and
//!   the backoff sleep); a tick in flight is allowed to finish, because the
//!   pump is crash-safe but a half-posted line is wasted work. Every way out of
//!   [`supervise`] (stop, halt, a panic of the tick task) runs `close`.
//! - **Backoff.** A failed start or tick ends the session and sleeps
//!   `backoff` (doubling to a cap, jittered). The backoff resets only when the
//!   session that just ended was healthy for at least `min_healthy` *and* made
//!   a successful tick; a session that dies at once keeps the backoff growing,
//!   so a flapping relay is not hammered.
//! - **Halted.** `Error::Refused` (seating refused, leaf removed, or a
//!   `permissionDenied` from the room side) and `Error::UndecidableCommit` end supervision for good with
//!   [`End::Halted`]. The pump persists the halt, so a restart of the process
//!   ends here too, on the first tick, without touching the foreign room.
//! - **Health is derived, not stored.** [`Health::read`] compares "now" with the
//!   time of the last successful tick; nothing is set to "connected" and left
//!   there (R6.2).

use crate::pump::TickReport;
use crate::{Error, Result};
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// What supervision needs from a link.
#[async_trait]
pub trait LinkTick: Send + Sync {
    /// Join the foreign room (idempotent). `Err(Refused)` halts the link.
    async fn start(&self) -> Result<crate::foreign::JoinState>;
    /// One pass of both directions.
    async fn tick(&self) -> Result<TickReport>;
    /// Release sockets and the like. Called exactly once on the way out.
    async fn close(&self) {}
}

#[async_trait]
impl LinkTick for crate::pump::Pump {
    async fn start(&self) -> Result<crate::foreign::JoinState> {
        crate::pump::Pump::start(self).await
    }
    async fn tick(&self) -> Result<TickReport> {
        crate::pump::Pump::tick(self).await
    }
}

/// Timing, in one place so tests can shrink it.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Pause between ticks.
    pub poll: Duration,
    /// First retry delay.
    pub backoff_min: Duration,
    /// Retry delay cap.
    pub backoff_max: Duration,
    /// A session shorter than this does not reset the backoff.
    pub min_healthy: Duration,
}

impl Timing {
    /// Production timing for a link polling every `poll_secs`.
    pub fn for_poll_secs(poll_secs: u64) -> Self {
        Self {
            poll: Duration::from_secs(poll_secs),
            backoff_min: Duration::from_secs(2),
            backoff_max: Duration::from_secs(300),
            min_healthy: Duration::from_secs(60),
        }
    }
}

/// Why supervision ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// Told to stop.
    Stopped,
    /// The link was refused or removed from; it stays stopped.
    Halted(String),
}

/// Timestamps of what happened, for the status line. Holds no verdict.
#[derive(Debug, Default)]
pub struct Health {
    inner: Mutex<HealthInner>,
}

#[derive(Debug, Default, Clone, Copy)]
struct HealthInner {
    last_ok: Option<Instant>,
    failures_since_ok: u32,
}

/// A reading of [`Health`] at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthReading {
    /// Seconds since the last successful tick, if there ever was one.
    pub since_ok_secs: Option<u64>,
    /// Failed starts and ticks since then.
    pub failures_since_ok: u32,
    /// Healthy means a success within three poll intervals.
    pub healthy: bool,
}

impl Health {
    fn ok(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.last_ok = Some(Instant::now());
            g.failures_since_ok = 0;
        }
    }
    fn failed(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.failures_since_ok = g.failures_since_ok.saturating_add(1);
        }
    }
    /// Read now. A link that stops ticking turns unhealthy by itself.
    pub fn read(&self, poll: Duration) -> HealthReading {
        let g = self.inner.lock().map(|g| *g).unwrap_or_default();
        let age = g.last_ok.map(|t| t.elapsed());
        HealthReading {
            since_ok_secs: age.map(|a| a.as_secs()),
            failures_since_ok: g.failures_since_ok,
            healthy: age.is_some_and(|a| a <= poll * 3),
        }
    }
}

fn jitter(d: Duration) -> Duration {
    let mut b = [0u8; 1];
    rand::fill(&mut b[..]);
    // +0..25 %
    d + d.mul_f64(f64::from(b[0]) / 255.0 * 0.25)
}

/// Sleep for `d` unless stopped first. `true` when stopped.
async fn sleep_or_stop(d: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    if *stop.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(d) => *stop.borrow(),
        _ = stop.changed() => true,
    }
}

/// The delay before the next session. The backoff resets only after a session
/// that made a successful tick and lasted `min_healthy`; otherwise it doubles
/// (to the cap) from what it was.
pub fn backoff_after(
    current: Duration,
    ticked_ok: bool,
    session: Duration,
    t: &Timing,
) -> Duration {
    if ticked_ok && session >= t.min_healthy {
        t.backoff_min
    } else {
        (current * 2).clamp(t.backoff_min, t.backoff_max)
    }
}

/// Run `link` until stopped or halted. Always calls `close` before returning.
pub async fn supervise(
    id: &str,
    link: Arc<dyn LinkTick>,
    timing: Timing,
    mut stop: watch::Receiver<bool>,
    health: Arc<Health>,
) -> End {
    let end = supervise_inner(id, &*link, timing, &mut stop, &health).await;
    link.close().await;
    end
}

async fn supervise_inner(
    id: &str,
    link: &dyn LinkTick,
    timing: Timing,
    stop: &mut watch::Receiver<bool>,
    health: &Health,
) -> End {
    let halt = |why: &Error| {
        tracing::error!(
            link = %id,
            security_alert = true,
            reason = %why,
            "link halted; it stays halted until an operator clears it"
        );
        End::Halted(why.to_string())
    };
    let mut backoff = timing.backoff_min;
    loop {
        if *stop.borrow() {
            return End::Stopped;
        }
        // One session: start, then tick until something fails.
        let began = Instant::now();
        let mut ticked_ok = false;
        let failure = match link.start().await {
            Err(e @ (Error::Refused(_) | Error::UndecidableCommit(_))) => return halt(&e),
            Err(e) => Some(e),
            Ok(_) => loop {
                match link.tick().await {
                    Ok(_) => {
                        ticked_ok = true;
                        health.ok();
                    }
                    Err(e @ (Error::Refused(_) | Error::UndecidableCommit(_))) => {
                        return halt(&e);
                    }
                    Err(e) => break Some(e),
                }
                if sleep_or_stop(timing.poll, stop).await {
                    return End::Stopped;
                }
            },
        };
        let Some(e) = failure else { continue };
        health.failed();
        backoff = backoff_after(backoff, ticked_ok, began.elapsed(), &timing);
        tracing::warn!(link = %id, error = %e, retry_in = ?backoff, "link session ended; retrying");
        if sleep_or_stop(jitter(backoff), stop).await {
            return End::Stopped;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foreign::JoinState;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Script {
        starts: Mutex<VecDeque<Result<JoinState>>>,
        ticks: Mutex<VecDeque<Result<TickReport>>>,
        n_start: AtomicUsize,
        n_tick: AtomicUsize,
        closed: AtomicUsize,
        stop_after: Option<(usize, watch::Sender<bool>)>,
    }
    impl Script {
        fn new(starts: Vec<Result<JoinState>>, ticks: Vec<Result<TickReport>>) -> Self {
            Self {
                starts: Mutex::new(starts.into()),
                ticks: Mutex::new(ticks.into()),
                n_start: 0.into(),
                n_tick: 0.into(),
                closed: 0.into(),
                stop_after: None,
            }
        }
    }
    #[async_trait]
    impl LinkTick for Script {
        async fn start(&self) -> Result<JoinState> {
            self.n_start.fetch_add(1, Ordering::SeqCst);
            self.starts
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(JoinState::Seated))
        }
        async fn tick(&self) -> Result<TickReport> {
            let n = self.n_tick.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some((at, tx)) = &self.stop_after
                && n >= *at
            {
                let _ = tx.send(true);
            }
            self.ticks
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(TickReport::default()))
        }
        async fn close(&self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fast() -> Timing {
        Timing {
            poll: Duration::from_millis(2),
            backoff_min: Duration::from_millis(2),
            backoff_max: Duration::from_millis(8),
            min_healthy: Duration::from_millis(50),
        }
    }

    fn io() -> Error {
        Error::Foreign("relay down".into())
    }

    #[tokio::test]
    async fn a_refusal_halts_and_closes_and_is_not_retried() {
        let (_tx, rx) = watch::channel(false);
        let s = Arc::new(Script::new(
            vec![],
            vec![Err(Error::Refused("removed".into()))],
        ));
        let end = supervise("l1", s.clone(), fast(), rx, Arc::new(Health::default())).await;
        assert!(matches!(end, End::Halted(ref w) if w.contains("removed")));
        assert_eq!(s.n_start.load(Ordering::SeqCst), 1);
        assert_eq!(s.closed.load(Ordering::SeqCst), 1);
        // A refusal while joining halts too, with no tick at all.
        let (_tx, rx) = watch::channel(false);
        let s = Arc::new(Script::new(vec![Err(Error::Refused("no".into()))], vec![]));
        let end = supervise("l1", s.clone(), fast(), rx, Arc::new(Health::default())).await;
        assert!(matches!(end, End::Halted(_)));
        assert_eq!(s.n_tick.load(Ordering::SeqCst), 0);
        assert_eq!(s.closed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_undecidable_commit_halts_and_is_not_retried() {
        let (_tx, rx) = watch::channel(false);
        let s = Arc::new(Script::new(
            vec![],
            vec![Err(Error::UndecidableCommit("epoch 3, commit ab".into()))],
        ));
        let end = supervise("l1", s.clone(), fast(), rx, Arc::new(Health::default())).await;
        assert!(
            matches!(end, End::Halted(ref w) if w.contains("epoch 3")),
            "{end:?}"
        );
        assert_eq!(s.n_start.load(Ordering::SeqCst), 1, "no second session");
        assert_eq!(s.n_tick.load(Ordering::SeqCst), 1);
        assert_eq!(s.closed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn errors_restart_the_session_and_stop_closes_gracefully() {
        let (tx, rx) = watch::channel(false);
        let mut s = Script::new(
            vec![],
            vec![Err(io()), Err(io()), Ok(TickReport::default())],
        );
        s.stop_after = Some((5, tx));
        let s = Arc::new(s);
        let health = Arc::new(Health::default());
        let end = supervise("l1", s.clone(), fast(), rx, health.clone()).await;
        assert_eq!(end, End::Stopped);
        assert!(
            s.n_start.load(Ordering::SeqCst) >= 3,
            "restarted after errors"
        );
        assert_eq!(s.closed.load(Ordering::SeqCst), 1);
        assert!(health.read(Duration::from_secs(1)).healthy);
    }

    #[tokio::test]
    async fn stop_before_start_and_during_backoff_returns_at_once() {
        let (tx, rx) = watch::channel(false);
        let _ = tx.send(true);
        let s = Arc::new(Script::new(vec![], vec![]));
        let end = supervise("l1", s.clone(), fast(), rx, Arc::new(Health::default())).await;
        assert_eq!(end, End::Stopped);
        assert_eq!(s.n_start.load(Ordering::SeqCst), 0);
        assert_eq!(s.closed.load(Ordering::SeqCst), 1);
        // A long backoff is interrupted by the stop.
        let (tx, rx) = watch::channel(false);
        let s = Arc::new(Script::new(vec![Err(io())], vec![]));
        let slow = Timing {
            backoff_min: Duration::from_secs(600),
            backoff_max: Duration::from_secs(600),
            ..fast()
        };
        let task = tokio::spawn({
            let s = s.clone();
            async move { supervise("l1", s, slow, rx, Arc::new(Health::default())).await }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        let _ = tx.send(true);
        let end = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("stop interrupts the backoff")
            .unwrap();
        assert_eq!(end, End::Stopped);
        assert_eq!(s.closed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backoff_resets_only_after_a_healthy_session() {
        let t = fast();
        let ms = Duration::from_millis;
        // Dies at once, or never ticked: keeps growing, up to the cap.
        assert_eq!(backoff_after(ms(2), false, ms(500), &t), ms(4));
        assert_eq!(backoff_after(ms(4), true, ms(10), &t), ms(8));
        assert_eq!(backoff_after(ms(8), true, ms(10), &t), ms(8));
        // Ticked and lasted: reset to the minimum.
        assert_eq!(backoff_after(ms(8), true, ms(60), &t), ms(2));
    }

    #[test]
    fn health_is_derived_from_time_and_turns_unhealthy_by_itself() {
        let h = Health::default();
        assert!(!h.read(Duration::from_secs(1)).healthy);
        h.ok();
        let r = h.read(Duration::from_secs(1));
        assert!(r.healthy && r.failures_since_ok == 0);
        h.failed();
        assert_eq!(h.read(Duration::from_secs(1)).failures_since_ok, 1);
        // The same success reads as unhealthy under a poll interval so short
        // that three of them have already passed.
        std::thread::sleep(Duration::from_millis(20));
        assert!(!h.read(Duration::from_millis(1)).healthy);
        let _ = AtomicBool::new(false);
    }
}
