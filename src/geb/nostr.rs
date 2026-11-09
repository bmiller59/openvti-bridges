//! The live Nostr relay client (feature `geb-live`): NIP-01 `REQ` / `EVENT` /
//! `EOSE` / `CLOSE` over one websocket per identity, kinds 4177 and 4178 with
//! `["v","1"]` and NIP-40 `expiration` tags (built by `geb::event`).
//!
//! Rules this module holds:
//! - `wss://` only (an `https://` URL is read as `wss://`); a plaintext
//!   `ws://` URL is accepted for the literal host `127.0.0.1` and nothing else
//!   (tests run a relay there). Nothing in this crate connects anywhere on its
//!   own; the caller supplies the URL.
//! - One socket per [`NostrRelay`] (create one per identity). A single owner
//!   task holds the socket; callers talk to it over a channel, so no lock is
//!   held across an await.
//! - The bridge owns retry for the relay domain only: when the socket drops it
//!   reconnects with capped exponential backoff and jitter, and re-sends the
//!   operations still in flight. Publishing the same signed event again and
//!   re-running a `REQ` are idempotent, which is why this is safe; every call
//!   has a deadline, after which it fails with [`Error::Foreign`].
//! - Every event a relay returns is checked (shape, size, id, signature, kind,
//!   author) before the caller sees it. An event we would POST over 120,000
//!   bytes is refused (an error, never truncated); one we would read over the
//!   relay's own 131,072-byte cap is dropped.
//! - Relay manners (round 3 section 7; the relay was overloaded on 2026-11-07
//!   by clients re-asking from `since: 0`): a catch-up read pages with
//!   `limit: 200` and `until` (one page per `REQ`, the next `until` being the
//!   oldest `created_at` just read), at most 8 catch-up `REQ`s are open at once
//!   (the rest wait; the relay allows 20 subscriptions per connection, and we
//!   never open more than 8), a reconnect continues the page it was on instead
//!   of starting over, and callers re-read from the newest event they have
//!   delivered minus 300 s (`since`). An event whose `created_at` is more than
//!   900 s in the future is refused locally (the relay refuses it too).
//! - Health is read from the live socket ([`NostrRelay::is_connected`]); there
//!   is no flag set once and left set.
//!
//! The TLS path (`wss://`) uses tokio-tungstenite's `rustls-tls-native-roots`
//! (native root certificates) and, like every rustls user in this workspace, needs the process to have
//! installed a default crypto provider. It is not exercised by any test (no
//! test may reach a real relay); only the plaintext 127.0.0.1 path is.

use super::traits::{GebRelay, RelayEvent};
use super::wire::{MAX_EVENT_BYTES, MAX_RECV_EVENT_BYTES};
use crate::{Error, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// Relay socket cap (Geb's relay accepts frames up to this size).
pub const MAX_MESSAGE_BYTES: usize = 262_144;
/// Most events one fetch will collect before it stops reading.
pub const MAX_FETCH_EVENTS: usize = 5_000;
/// Catch-up page size: `limit` of every `REQ` (Geb's client page size, round 3
/// section 7; the relay's own cap is 500).
pub const CATCHUP_PAGE: usize = 200;
/// Most catch-up `REQ`s open at once on one connection.
pub const MAX_CATCHUP_REQS: usize = 8;
/// Subscriptions the relay allows per connection.
pub const MAX_SUBSCRIPTIONS: usize = 20;
const _: () = assert!(MAX_CATCHUP_REQS <= MAX_SUBSCRIPTIONS);
/// An event dated further ahead than this (seconds) is refused by the relay,
/// so we never post one.
pub const MAX_FUTURE_SECS: u64 = 900;

/// Client settings.
#[derive(Debug, Clone)]
pub struct NostrConfig {
    /// `wss://host[/path]` (or `ws://127.0.0.1:port` in tests).
    pub url: String,
    /// Deadline for one publish or fetch, across reconnects.
    pub op_timeout: Duration,
    /// First reconnect delay.
    pub backoff_min: Duration,
    /// Reconnect delay cap.
    pub backoff_max: Duration,
}

impl NostrConfig {
    /// Defaults: 20 s per operation, backoff 0.5 s doubling to 30 s.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            op_timeout: Duration::from_secs(20),
            backoff_min: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
        }
    }
}

/// Check the URL and return the websocket URL to dial.
pub fn validate_url(url: &str) -> Result<String> {
    let u = url::Url::parse(url).map_err(|e| Error::Config(format!("relay url: {e}")))?;
    match u.scheme() {
        "wss" => Ok(u.to_string()),
        "https" => Ok(u.to_string().replacen("https", "wss", 1)),
        "ws" if u.host_str() == Some("127.0.0.1") => Ok(u.to_string()),
        "ws" => Err(Error::Config(
            "plaintext ws:// is allowed only for 127.0.0.1".into(),
        )),
        other => Err(Error::Config(format!(
            "relay url scheme {other} is not wss"
        ))),
    }
}

/// Capped exponential backoff with jitter: attempt `n` waits a random time in
/// `[d/2, d]` where `d = min(max, min * 2^n)`.
pub fn backoff_delay(cfg: &NostrConfig, attempt: u32) -> Duration {
    let exp = cfg
        .backoff_min
        .saturating_mul(1u32.checked_shl(attempt.min(20)).unwrap_or(u32::MAX));
    let d = exp.min(cfg.backoff_max);
    let mut r = [0u8; 2];
    rand::fill(&mut r);
    let frac = f64::from(u16::from_be_bytes(r)) / f64::from(u16::MAX);
    d.mul_f64(0.5 + 0.5 * frac)
}

enum Cmd {
    Publish {
        event: RelayEvent,
        reply: oneshot::Sender<Result<()>>,
    },
    Fetch {
        kind: u32,
        author: String,
        since: Option<u64>,
        reply: oneshot::Sender<Result<Vec<RelayEvent>>>,
    },
}

enum Op {
    Publish {
        event: RelayEvent,
        /// Whether the event has been sent on the current socket.
        sent: bool,
        reply: oneshot::Sender<Result<()>>,
        deadline: Instant,
    },
    Fetch {
        kind: u32,
        author: String,
        since: Option<u64>,
        /// The current page reads events at or before this `created_at`.
        until: Option<u64>,
        sub: String,
        /// Whether the current page's `REQ` is open (counts against
        /// [`MAX_CATCHUP_REQS`]).
        active: bool,
        /// Events of the current page, and how many of them were new.
        page_total: usize,
        page_new: usize,
        page_oldest: Option<u64>,
        events: Vec<RelayEvent>,
        seen: HashSet<String>,
        reply: oneshot::Sender<Result<Vec<RelayEvent>>>,
        deadline: Instant,
    },
}

impl Op {
    fn deadline(&self) -> Instant {
        match self {
            Op::Publish { deadline, .. } | Op::Fetch { deadline, .. } => *deadline,
        }
    }
    fn fail(self, why: &str) {
        match self {
            Op::Publish { reply, .. } => {
                let _ = reply.send(Err(Error::Foreign(why.into())));
            }
            Op::Fetch { reply, .. } => {
                let _ = reply.send(Err(Error::Foreign(why.into())));
            }
        }
    }
}

/// A Nostr relay client for one identity (one socket).
pub struct NostrRelay {
    tx: mpsc::Sender<Cmd>,
    connected: watch::Receiver<bool>,
    cfg: NostrConfig,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for NostrRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl NostrRelay {
    /// Validate the URL and start the owner task. The socket is opened on the
    /// first operation, not here.
    pub fn new(cfg: NostrConfig) -> Result<Self> {
        let dial = validate_url(&cfg.url)?;
        let (tx, rx) = mpsc::channel(256);
        let (ctx, connected) = watch::channel(false);
        let task = tokio::spawn(owner(dial, cfg.clone(), rx, ctx));
        Ok(Self {
            tx,
            connected,
            cfg,
            task,
        })
    }

    /// Whether the socket is up right now. Goes false the moment it drops.
    pub fn is_connected(&self) -> bool {
        *self.connected.borrow()
    }
}

#[async_trait]
impl GebRelay for NostrRelay {
    async fn publish(&self, event: RelayEvent) -> Result<()> {
        if event.json_len() > MAX_EVENT_BYTES {
            return Err(Error::Foreign(format!(
                "event over {MAX_EVENT_BYTES} bytes; refused, not truncated"
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if event.created_at > now.saturating_add(MAX_FUTURE_SECS) {
            return Err(Error::Foreign(format!(
                "event created_at is more than {MAX_FUTURE_SECS} s in the future; refused"
            )));
        }
        event.verify()?;
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Publish { event, reply })
            .await
            .map_err(|_| Error::Foreign("relay client stopped".into()))?;
        wait(rx, self.cfg.op_timeout).await
    }

    async fn fetch(&self, kind: u32, author: &str, since: Option<u64>) -> Result<Vec<RelayEvent>> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Fetch {
                kind,
                author: author.to_string(),
                since,
                reply,
            })
            .await
            .map_err(|_| Error::Foreign("relay client stopped".into()))?;
        wait(rx, self.cfg.op_timeout).await
    }
}

async fn wait<T>(rx: oneshot::Receiver<Result<T>>, op_timeout: Duration) -> Result<T> {
    match tokio::time::timeout(op_timeout + Duration::from_secs(2), rx).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => Err(Error::Foreign("relay client stopped".into())),
        Err(_) => Err(Error::Foreign("relay did not answer in time".into())),
    }
}

fn new_sub() -> String {
    let mut b = [0u8; 8];
    rand::fill(&mut b);
    hex::encode(b)
}

fn into_op(cmd: Cmd, op_timeout: Duration) -> Op {
    let deadline = Instant::now() + op_timeout;
    match cmd {
        Cmd::Publish { event, reply } => Op::Publish {
            event,
            sent: false,
            reply,
            deadline,
        },
        Cmd::Fetch {
            kind,
            author,
            since,
            reply,
        } => Op::Fetch {
            kind,
            author,
            since,
            until: None,
            sub: new_sub(),
            active: false,
            page_total: 0,
            page_new: 0,
            page_oldest: None,
            events: Vec::new(),
            seen: HashSet::new(),
            reply,
            deadline,
        },
    }
}

fn expire(ops: &mut Vec<Op>) {
    let now = Instant::now();
    let mut keep = Vec::with_capacity(ops.len());
    for op in ops.drain(..) {
        if op.deadline() <= now {
            op.fail("relay did not answer before the deadline");
        } else {
            keep.push(op);
        }
    }
    *ops = keep;
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn owner(
    dial: String,
    cfg: NostrConfig,
    mut rx: mpsc::Receiver<Cmd>,
    up: watch::Sender<bool>,
) {
    let mut ops: Vec<Op> = Vec::new();
    let mut attempt: u32 = 0;
    loop {
        if ops.is_empty() {
            // Connect lazily: wait for the first operation.
            match rx.recv().await {
                Some(c) => ops.push(into_op(c, cfg.op_timeout)),
                None => return,
            }
        }
        let wsc = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES));
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::connect_async_with_config(dial.as_str(), Some(wsc), false),
        )
        .await;
        match conn {
            Ok(Ok((ws, _))) => {
                let _ = up.send(true);
                let clean = session(ws, &mut ops, &mut rx, &cfg).await;
                let _ = up.send(false);
                match clean {
                    Session::OwnerGone => return,
                    Session::Lost(progressed) => {
                        attempt = if progressed {
                            0
                        } else {
                            attempt.saturating_add(1)
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "relay connect failed");
                attempt = attempt.saturating_add(1);
            }
            Err(_) => attempt = attempt.saturating_add(1),
        }
        // Back off, still accepting and expiring operations meanwhile.
        let until = Instant::now() + backoff_delay(&cfg, attempt);
        loop {
            expire(&mut ops);
            let tick = until.min(Instant::now() + Duration::from_millis(250));
            tokio::select! {
                c = rx.recv() => match c {
                    Some(c) => ops.push(into_op(c, cfg.op_timeout)),
                    None => return,
                },
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(tick)) => {}
            }
            if Instant::now() >= until {
                break;
            }
        }
        expire(&mut ops);
    }
}

enum Session {
    /// The socket was lost; `true` when it did useful work first.
    Lost(bool),
    /// Every handle to the client was dropped.
    OwnerGone,
}

/// Send what can be sent: every publish not yet sent on this socket, and as
/// many waiting catch-up pages as the [`MAX_CATCHUP_REQS`] limit allows.
async fn flush(ws: &mut Ws, ops: &mut [Op]) -> std::result::Result<(), ()> {
    let mut open = ops
        .iter()
        .filter(|o| matches!(o, Op::Fetch { active: true, .. }))
        .count();
    for op in ops.iter_mut() {
        let text = match op {
            Op::Publish { event, sent, .. } if !*sent => {
                *sent = true;
                json!(["EVENT", event.to_json()]).to_string()
            }
            Op::Fetch {
                kind,
                author,
                since,
                until,
                sub,
                active,
                page_total,
                page_new,
                page_oldest,
                ..
            } if !*active && open < MAX_CATCHUP_REQS => {
                open += 1;
                *active = true;
                *page_total = 0;
                *page_new = 0;
                *page_oldest = None;
                *sub = new_sub();
                let mut f = json!({"kinds": [kind], "authors": [author], "limit": CATCHUP_PAGE});
                if let Some(o) = f.as_object_mut() {
                    if let Some(s) = since {
                        o.insert("since".into(), json!(s));
                    }
                    if let Some(u) = until {
                        o.insert("until".into(), json!(u));
                    }
                }
                json!(["REQ", sub, f]).to_string()
            }
            _ => continue,
        };
        ws.send(Message::Text(text.into())).await.map_err(|_| ())?;
    }
    Ok(())
}

/// A new socket: nothing is sent or open on it yet. A catch-up keeps what it
/// has collected and continues from its current page.
fn reset_for_new_socket(ops: &mut [Op]) {
    for op in ops {
        match op {
            Op::Publish { sent, .. } => *sent = false,
            Op::Fetch { active, .. } => *active = false,
        }
    }
}

async fn session(
    mut ws: Ws,
    ops: &mut Vec<Op>,
    rx: &mut mpsc::Receiver<Cmd>,
    cfg: &NostrConfig,
) -> Session {
    let mut worked = false;
    reset_for_new_socket(ops);
    if flush(&mut ws, ops).await.is_err() {
        return Session::Lost(worked);
    }
    loop {
        expire(ops);
        let tick = tokio::time::Instant::now() + Duration::from_millis(250);
        tokio::select! {
            c = rx.recv() => {
                let Some(c) = c else { return Session::OwnerGone };
                ops.push(into_op(c, cfg.op_timeout));
                if flush(&mut ws, ops).await.is_err() { return Session::Lost(worked); }
            }
            m = ws.next() => {
                let Some(Ok(msg)) = m else { return Session::Lost(worked) };
                match msg {
                    Message::Text(t) => {
                        if handle(&mut ws, ops, t.as_str()).await.is_err() {
                            return Session::Lost(worked);
                        }
                        worked = true;
                    }
                    Message::Ping(p) => {
                        if ws.send(Message::Pong(p)).await.is_err() { return Session::Lost(worked); }
                    }
                    Message::Close(_) => return Session::Lost(worked),
                    // Binary and the rest are not NIP-01.
                    _ => {}
                }
            }
            () = tokio::time::sleep_until(tick) => {}
        }
    }
}

async fn handle(ws: &mut Ws, ops: &mut Vec<Op>, text: &str) -> std::result::Result<(), ()> {
    let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(text) else {
        tracing::warn!("ignoring a relay message that is not a JSON array");
        return Ok(());
    };
    let kind = msg.first().and_then(Value::as_str).unwrap_or("");
    match kind {
        "EVENT" => {
            let (Some(sub), Some(ev)) = (msg.get(1).and_then(Value::as_str), msg.get(2)) else {
                return Ok(());
            };
            for op in ops.iter_mut() {
                if let Op::Fetch {
                    kind,
                    author,
                    since,
                    until,
                    sub: s,
                    active: true,
                    page_total,
                    page_new,
                    page_oldest,
                    events,
                    seen,
                    ..
                } = op
                    && s == sub
                {
                    if events.len() >= MAX_FETCH_EVENTS {
                        break;
                    }
                    match RelayEvent::from_json(ev) {
                        Ok(e)
                            if e.kind == *kind
                                && e.pubkey == *author
                                && since.is_none_or(|s| e.created_at >= s)
                                && until.is_none_or(|u| e.created_at <= u)
                                && e.json_len() <= MAX_RECV_EVENT_BYTES
                                && e.verify().is_ok() =>
                        {
                            *page_total += 1;
                            *page_oldest =
                                Some(page_oldest.map_or(e.created_at, |o| o.min(e.created_at)));
                            if seen.insert(e.id.clone()) {
                                *page_new += 1;
                                events.push(e);
                            }
                        }
                        _ => tracing::warn!(
                            "dropping a relay event that is malformed, oversized, unrequested or does not verify"
                        ),
                    }
                }
            }
        }
        "EOSE" => {
            let Some(sub) = msg.get(1).and_then(Value::as_str) else {
                return Ok(());
            };
            let Some(i) = ops
                .iter()
                .position(|o| matches!(o, Op::Fetch { sub: s, active: true, .. } if s == sub))
            else {
                return Ok(());
            };
            let _ = ws
                .send(Message::Text(json!(["CLOSE", sub]).to_string().into()))
                .await;
            // Another page when this one was full, made progress and there is
            // more room; otherwise the catch-up is complete.
            let more = match &mut ops[i] {
                Op::Fetch {
                    since,
                    until,
                    active,
                    page_total,
                    page_new,
                    page_oldest,
                    events,
                    deadline,
                    ..
                } => {
                    let next = page_oldest.filter(|o| {
                        *page_total >= CATCHUP_PAGE
                            && *page_new > 0
                            && events.len() < MAX_FETCH_EVENTS
                            && since.is_none_or(|s| *o > s)
                    });
                    *active = false;
                    if let Some(o) = next {
                        *until = Some(o);
                        *deadline = Instant::now() + Duration::from_secs(20);
                        true
                    } else {
                        false
                    }
                }
                Op::Publish { .. } => false,
            };
            if !more && let Op::Fetch { events, reply, .. } = ops.remove(i) {
                let _ = reply.send(Ok(events));
            }
            // A slot is free (or a next page is due): send what is waiting.
            return flush(ws, ops).await;
        }
        "OK" => {
            let Some(id) = msg.get(1).and_then(Value::as_str) else {
                return Ok(());
            };
            let accepted = msg.get(2).and_then(Value::as_bool).unwrap_or(false);
            let why = msg.get(3).and_then(Value::as_str).unwrap_or("");
            if let Some(i) = ops
                .iter()
                .position(|o| matches!(o, Op::Publish { event, .. } if event.id == id))
                && let Op::Publish { reply, .. } = ops.remove(i)
            {
                // A "duplicate:" refusal means the relay already holds it.
                let r = if accepted || why.starts_with("duplicate:") {
                    Ok(())
                } else {
                    Err(Error::Foreign(format!("relay refused the event: {why}")))
                };
                let _ = reply.send(r);
            }
        }
        "CLOSED" => {
            let Some(sub) = msg.get(1).and_then(Value::as_str) else {
                return Ok(());
            };
            let why = msg.get(2).and_then(Value::as_str).unwrap_or("").to_string();
            if let Some(i) = ops
                .iter()
                .position(|o| matches!(o, Op::Fetch { sub: s, .. } if s == sub))
            {
                ops.remove(i)
                    .fail(&format!("relay closed the subscription: {why}"));
                return flush(ws, ops).await;
            }
        }
        "NOTICE" => tracing::debug!(notice = ?msg.get(1), "relay notice"),
        other => tracing::debug!(kind = other, "ignoring an unknown relay message"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_wss_and_loopback_ws_are_dialled() {
        assert!(validate_url("wss://relay.example/").is_ok());
        assert!(
            validate_url("https://relay.example/")
                .unwrap()
                .starts_with("wss://")
        );
        assert!(validate_url("ws://127.0.0.1:7777").is_ok());
        for bad in [
            "ws://relay.example",
            "ws://localhost:1",
            "ws://127.0.0.2:1",
            "ws://[::1]:1",
            "http://relay.example",
            "ftp://x",
            "not a url",
            "",
        ] {
            assert!(validate_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn backoff_is_capped_jittered_and_grows() {
        let cfg = NostrConfig::new("wss://x");
        for n in 0..40 {
            let d = backoff_delay(&cfg, n);
            let cap = cfg
                .backoff_min
                .saturating_mul(1 << n.min(20))
                .min(cfg.backoff_max);
            assert!(d <= cap && d >= cap / 2, "attempt {n}: {d:?} vs {cap:?}");
            assert!(d <= cfg.backoff_max);
        }
        let spread: HashSet<_> = (0..30)
            .map(|_| backoff_delay(&cfg, 6).as_micros())
            .collect();
        assert!(spread.len() > 1, "jittered");
    }
}
