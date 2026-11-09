//! A minimal in-process Nostr relay for tests (feature `geb-live`). It binds
//! `127.0.0.1` on an ephemeral port and nowhere else; nothing here can reach
//! a real relay. It speaks enough NIP-01 (`EVENT`, `REQ`, `CLOSE`) and NIP-40
//! for the dyad tests, and checks what a real relay checks: event id and
//! signature, the 65,536-byte cap, expiry. It has knobs to misbehave on
//! purpose: drop every connection, return events oldest first, repeat every
//! event on a fetch, and store events unchecked (a hostile relay).

use super::traits::RelayEvent;
use super::wire::MAX_EVENT_BYTES;
use crate::{Error, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

struct Shared {
    events: Mutex<Vec<RelayEvent>>,
    now: Arc<AtomicU64>,
    oldest_first: AtomicBool,
    repeat: AtomicBool,
    generation: watch::Sender<u64>,
    publishes: AtomicU64,
    drop_before_ok: AtomicU64,
}

/// The relay. Dropping it stops the listener.
pub struct TestRelay {
    addr: SocketAddr,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestRelay {
    /// Start on `127.0.0.1:0`. `now` is the relay's clock in seconds (for
    /// NIP-40 expiry), shared with the test so it can move time.
    pub async fn start(now: Arc<AtomicU64>) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| Error::Foreign(format!("bind: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| Error::Foreign(e.to_string()))?;
        let (generation, _) = watch::channel(0u64);
        let shared = Arc::new(Shared {
            events: Mutex::new(Vec::new()),
            now,
            oldest_first: AtomicBool::new(false),
            repeat: AtomicBool::new(false),
            generation,
            publishes: AtomicU64::new(0),
            drop_before_ok: AtomicU64::new(0),
        });
        let sh = shared.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    return;
                };
                if !peer.ip().is_loopback() {
                    continue;
                }
                tokio::spawn(serve(stream, sh.clone()));
            }
        });
        Ok(Self { addr, shared, task })
    }

    /// `ws://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }

    /// Everything stored.
    pub fn events(&self) -> Vec<RelayEvent> {
        self.shared
            .events
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// How many `EVENT` messages the relay has received (accepted or not).
    pub fn publishes_seen(&self) -> u64 {
        self.shared.publishes.load(Ordering::SeqCst)
    }

    /// Close every open connection abruptly (no close handshake). Clients may
    /// reconnect.
    pub fn drop_connections(&self) {
        self.shared.generation.send_modify(|g| *g += 1);
    }

    /// For the next `n` published events: store the event, then drop the
    /// connection without answering `OK` (the client cannot know whether it
    /// was stored).
    pub fn drop_connection_before_ok(&self, n: u64) {
        self.shared.drop_before_ok.store(n, Ordering::SeqCst);
    }

    /// Return fetched events oldest first instead of newest first.
    pub fn set_oldest_first(&self, on: bool) {
        self.shared.oldest_first.store(on, Ordering::SeqCst);
    }

    /// Send every matching event twice on a fetch.
    pub fn set_repeat_events(&self, on: bool) {
        self.shared.repeat.store(on, Ordering::SeqCst);
    }

    /// Store an event without any check, as a hostile or broken relay would
    /// serve it.
    pub fn inject_unchecked(&self, e: RelayEvent) {
        if let Ok(mut g) = self.shared.events.lock() {
            g.push(e);
        }
    }
}

fn matches(f: &Value, e: &RelayEvent) -> bool {
    let list = |k: &str| f.get(k).and_then(Value::as_array);
    if let Some(ks) = list("kinds")
        && !ks.iter().any(|k| k.as_u64() == Some(u64::from(e.kind)))
    {
        return false;
    }
    if let Some(a) = list("authors")
        && !a.iter().any(|x| x.as_str() == Some(e.pubkey.as_str()))
    {
        return false;
    }
    if let Some(s) = f.get("since").and_then(Value::as_u64)
        && e.created_at < s
    {
        return false;
    }
    if let Some(u) = f.get("until").and_then(Value::as_u64)
        && e.created_at > u
    {
        return false;
    }
    true
}

async fn serve(stream: tokio::net::TcpStream, sh: Arc<Shared>) {
    let cfg = WebSocketConfig::default()
        .max_message_size(Some(super::nostr::MAX_MESSAGE_BYTES))
        .max_frame_size(Some(super::nostr::MAX_MESSAGE_BYTES));
    let Ok(mut ws) = tokio_tungstenite::accept_async_with_config(stream, Some(cfg)).await else {
        return;
    };
    let mut gen_rx = sh.generation.subscribe();
    loop {
        tokio::select! {
            _ = gen_rx.changed() => return, // drop the socket without a close frame
            m = ws.next() => {
                let Some(Ok(Message::Text(t))) = m else { return };
                let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(t.as_str()) else { continue };
                let out: Vec<Value> = match msg.first().and_then(Value::as_str) {
                    Some("EVENT") => {
                        let ok = on_event(&sh, msg.get(1));
                        let drop_now = sh
                            .drop_before_ok
                            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                            .is_ok();
                        if drop_now {
                            return;
                        }
                        vec![ok]
                    }
                    Some("REQ") => on_req(&sh, &msg),
                    Some("CLOSE") => vec![],
                    _ => vec![json!(["NOTICE", "unsupported"])],
                };
                for o in out {
                    if ws.send(Message::Text(o.to_string().into())).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

fn on_event(sh: &Shared, ev: Option<&Value>) -> Value {
    sh.publishes.fetch_add(1, Ordering::SeqCst);
    let id = ev
        .and_then(|e| e.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let no = |why: &str| json!(["OK", id, false, why]);
    let Some(Ok(e)) = ev.map(RelayEvent::from_json) else {
        return no("invalid: malformed event");
    };
    if e.json_len() > MAX_EVENT_BYTES {
        return no("invalid: event too large");
    }
    if e.verify().is_err() {
        return no("invalid: bad id or signature");
    }
    if e.is_expired(sh.now.load(Ordering::SeqCst)) {
        return no("invalid: event expired");
    }
    let Ok(mut g) = sh.events.lock() else {
        return no("error: busy");
    };
    if g.iter().any(|x| x.id == e.id) {
        return json!(["OK", id, true, "duplicate: already have this event"]);
    }
    g.push(e);
    json!(["OK", id, true, ""])
}

fn on_req(sh: &Shared, msg: &[Value]) -> Vec<Value> {
    let Some(sub) = msg.get(1).and_then(Value::as_str) else {
        return vec![];
    };
    let now = sh.now.load(Ordering::SeqCst);
    let filters = &msg[2.min(msg.len())..];
    let mut hits: Vec<RelayEvent> = sh
        .events
        .lock()
        .map(|g| {
            g.iter()
                .filter(|e| !e.is_expired(now))
                .filter(|e| filters.iter().any(|f| matches(f, e)))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    hits.sort_by_key(|e| e.created_at);
    if !sh.oldest_first.load(Ordering::SeqCst) {
        hits.reverse();
    }
    let mut out = Vec::new();
    for e in hits {
        out.push(json!(["EVENT", sub, e.to_json()]));
        if sh.repeat.load(Ordering::SeqCst) {
            out.push(json!(["EVENT", sub, e.to_json()]));
        }
    }
    out.push(json!(["EOSE", sub]));
    out
}
