//! End to end over a real websocket to an in-process relay on 127.0.0.1
//! (feature `geb-live`). Nothing here reaches a real relay or a real Geb node:
//! the relay is `geb::test_relay::TestRelay`, started by each test on an
//! ephemeral loopback port.
#![cfg(feature = "geb-live")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use openvti_bridges::geb::dyad::{GebIdentity, Phase, StatefulDyad};
use openvti_bridges::geb::event::{KIND_INBOX, KIND_MAILBOX, standard_tags};
use openvti_bridges::geb::nostr::{NostrConfig, NostrRelay};
use openvti_bridges::geb::test_relay::TestRelay;
use openvti_bridges::geb::traits::{GebDyad, GebRelay, RelayEvent};
use openvti_bridges::geb::wire::Frame;
use openvti_bridges::store::MemoryStore;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

const T0: u64 = 1_700_000_000;

fn cfg(url: &str) -> NostrConfig {
    let mut c = NostrConfig::new(url);
    c.op_timeout = Duration::from_secs(8);
    c.backoff_min = Duration::from_millis(10);
    c.backoff_max = Duration::from_millis(80);
    c
}

fn ident(seed: u8) -> Arc<GebIdentity> {
    Arc::new(GebIdentity::new(SigningKey::from_bytes(&[seed; 32]), [seed + 100; 32]).unwrap())
}

fn msg(t: &str) -> Frame {
    Frame::Message {
        d: t.into(),
        id: "0123456789abcdef".into(),
        re: None,
        nr: None,
        o: None,
    }
}

fn text(f: &Frame) -> String {
    match f {
        Frame::Message { d, .. } => d.clone(),
        o => format!("{o:?}"),
    }
}

struct Net {
    relay: TestRelay,
    now: Arc<AtomicU64>,
    a: StatefulDyad,
    b: StatefulDyad,
    a_relay: Arc<NostrRelay>,
}

async fn net() -> Net {
    let now = Arc::new(AtomicU64::new(T0));
    let relay = TestRelay::start(now.clone()).await.unwrap();
    let mk = |seed: u8| {
        let n = now.clone();
        let r = Arc::new(NostrRelay::new(cfg(&relay.url())).unwrap());
        (
            r.clone(),
            StatefulDyad::new(
                ident(seed),
                r,
                Arc::new(MemoryStore::new()),
                Arc::new(move || n.load(Ordering::SeqCst) * 1000),
            ),
        )
    };
    let (a_relay, a) = mk(1);
    let (_b_relay, b) = mk(2);
    // Keep B's client alive for the test's duration through its dyad.
    Net {
        relay,
        now,
        a,
        b,
        a_relay,
    }
}

fn tick(n: &Net) {
    n.now.fetch_add(1, Ordering::SeqCst);
}

#[tokio::test]
async fn client_publish_fetch_and_every_refusal() {
    let now = Arc::new(AtomicU64::new(T0));
    let relay = TestRelay::start(now.clone()).await.unwrap();
    let c = NostrRelay::new(cfg(&relay.url())).unwrap();
    assert!(!c.is_connected(), "lazy: no socket before the first call");
    let sk = [7u8; 32];
    let ev = RelayEvent::sign(&sk, KIND_MAILBOX, T0, standard_tags(T0), "AAAA".into()).unwrap();
    c.publish(ev.clone()).await.unwrap();
    assert!(c.is_connected());
    c.publish(ev.clone()).await.unwrap(); // duplicate is fine
    assert_eq!(relay.events().len(), 1);
    let got = c
        .fetch(KIND_MAILBOX, &ev.pubkey, Some(T0 - 300))
        .await
        .unwrap();
    assert_eq!(got, vec![ev.clone()]);
    assert!(
        c.fetch(KIND_INBOX, &ev.pubkey, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        c.fetch(KIND_MAILBOX, &ev.pubkey, Some(T0 + 1))
            .await
            .unwrap()
            .is_empty()
    );

    // Refused before it leaves: forged, oversized.
    let mut forged = ev.clone();
    forged.sig = "22".repeat(64);
    assert!(c.publish(forged).await.is_err());
    let big = RelayEvent::sign(&sk, KIND_MAILBOX, T0, vec![], "A".repeat(121_000)).unwrap();
    assert!(c.publish(big).await.is_err());
    // Refused by the relay: expired (NIP-40).
    let old = RelayEvent::sign(
        &sk,
        KIND_MAILBOX,
        T0 - 100,
        vec![vec!["expiration".into(), (T0 - 1).to_string()]],
        "BBBB".into(),
    )
    .unwrap();
    let e = c.publish(old).await.unwrap_err().to_string();
    assert!(e.contains("expired"), "{e}");
    assert_eq!(relay.events().len(), 1);

    // The relay itself refuses an oversized or forged event sent raw.
    let (mut ws, _) = tokio_tungstenite::connect_async(relay.url().as_str())
        .await
        .unwrap();
    let big = RelayEvent::sign(&sk, KIND_MAILBOX, T0, vec![], "A".repeat(135_000)).unwrap();
    let mut bad = ev.clone();
    bad.sig = "33".repeat(64);
    for raw in [big, bad] {
        ws.send(Message::Text(
            serde_json::json!(["EVENT", raw.to_json()])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let Some(Ok(Message::Text(t))) = ws.next().await else {
            panic!("no reply")
        };
        let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
        assert_eq!(v[0], "OK");
        assert_eq!(v[2], false, "{v}");
    }
    assert_eq!(relay.events().len(), 1);
}

#[tokio::test]
async fn a_hostile_relay_cannot_feed_the_client_bad_events() {
    let now = Arc::new(AtomicU64::new(T0));
    let relay = TestRelay::start(now).await.unwrap();
    let c = NostrRelay::new(cfg(&relay.url())).unwrap();
    let sk = [7u8; 32];
    let good = RelayEvent::sign(&sk, KIND_MAILBOX, T0, vec![], "AAAA".into()).unwrap();
    let mut forged = good.clone();
    forged.content = "CCCC".into(); // id no longer matches
    let mut badsig = RelayEvent::sign(&sk, KIND_MAILBOX, T0 + 1, vec![], "DDDD".into()).unwrap();
    badsig.sig = "44".repeat(64);
    let other_author =
        RelayEvent::sign(&[8u8; 32], KIND_MAILBOX, T0, vec![], "EEEE".into()).unwrap();
    for e in [good.clone(), forged, badsig, other_author] {
        relay.inject_unchecked(e);
    }
    relay.set_repeat_events(true);
    let got = c.fetch(KIND_MAILBOX, &good.pubkey, None).await.unwrap();
    assert_eq!(got, vec![good], "one valid event, once");
}

#[tokio::test]
async fn connect_when_apart_and_acked_messages_over_a_real_socket() {
    let n = net().await;
    n.a.invite(n.b.did(), Some("alice")).await.unwrap();
    let inv = n.b.invitations().await.unwrap();
    assert_eq!(inv.len(), 1);
    n.b.accept(&inv[0]).await.unwrap();
    tick(&n);
    assert_eq!(
        n.a.sync(n.b.did()).await.unwrap().phase,
        Some(Phase::Connected)
    );
    tick(&n);
    assert_eq!(
        n.b.sync(n.a.did()).await.unwrap().phase,
        Some(Phase::Connected)
    );

    // Relays may return anything in any order, with repeats.
    n.relay.set_oldest_first(true);
    n.relay.set_repeat_events(true);
    for t in ["one", "two", "three"] {
        n.a.send(n.b.did(), &msg(t)).await.unwrap();
    }
    tick(&n);
    let got: Vec<_> = take(&n.b, n.a.did())
        .await
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(got, ["one", "two", "three"]);
    tick(&n);
    let r = n.a.sync(n.b.did()).await.unwrap();
    assert!(r.acked >= 3);
    assert_eq!(n.a.unacked(n.b.did()).await.unwrap(), 0);

    // A dropped connection mid-publish: the relay stored the event but never
    // said OK. The client reconnects, re-sends, hears "duplicate", succeeds.
    let before = n.relay.events().len();
    n.relay.drop_connection_before_ok(1);
    n.a.send(n.b.did(), &msg("across the drop")).await.unwrap();
    assert_eq!(n.relay.events().len(), before + 1, "stored once");
    assert!(n.relay.publishes_seen() >= 2);

    // A dropped connection between operations: the next call dials again.
    n.relay.drop_connections();
    for _ in 0..100 {
        if !n.a_relay.is_connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!n.a_relay.is_connected(), "health follows the socket down");
    n.a.send(n.b.did(), &msg("after reconnect")).await.unwrap();
    assert!(n.a_relay.is_connected(), "and back up");
    tick(&n);
    let got: Vec<_> = take(&n.b, n.a.did())
        .await
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(got, ["across the drop", "after reconnect"]);

    // Our own `d` is dropped; an expired event is dropped.
    tick(&n);
    let r = n.a.sync(n.b.did()).await.unwrap();
    assert_eq!(r.frames, 0);
    n.a.send(n.b.did(), &msg("never read")).await.unwrap();
    n.now.fetch_add(8 * 86_400, Ordering::SeqCst);
    assert!(take(&n.b, n.a.did()).await.unwrap().is_empty());
}

/// Read and consume, as a consumer that has persisted its own state does.
async fn take(
    d: &openvti_bridges::geb::dyad::StatefulDyad,
    peer: &str,
) -> openvti_bridges::Result<Vec<openvti_bridges::geb::wire::Frame>> {
    use openvti_bridges::geb::traits::GebDyad;
    let got = d.recv_counted(peer).await?;
    let counters: Vec<u32> = got.iter().map(|(n, _)| *n).collect();
    d.commit_recv(peer, &counters).await?;
    Ok(got.into_iter().map(|(_, f)| f).collect())
}

// ---- relay manners (round 3 section 7 and 6) --------------------------------

fn sk() -> [u8; 32] {
    [7u8; 32]
}

fn event_at(secs: u64, content: &str) -> RelayEvent {
    RelayEvent::sign(&sk(), KIND_MAILBOX, secs, vec![], content.into()).unwrap()
}

fn author() -> String {
    event_at(T0, "x").pubkey
}

#[tokio::test]
async fn a_catch_up_pages_with_limit_200_and_until_and_never_asks_from_zero() {
    let now = Arc::new(AtomicU64::new(T0 + 10_000));
    let relay = TestRelay::start(now).await.unwrap();
    for i in 0..450u64 {
        relay.inject_unchecked(event_at(T0 + i, &format!("e{i}")));
    }
    let c = NostrRelay::new(cfg(&relay.url())).unwrap();
    let got = c
        .fetch(KIND_MAILBOX, &author(), Some(T0 - 300))
        .await
        .unwrap();
    assert_eq!(got.len(), 450, "every event, once, across three pages");
    let reqs = relay.req_filters();
    assert_eq!(reqs.len(), 3, "{reqs:?}");
    for r in &reqs {
        assert_eq!(r["limit"], 200, "every page asks limit 200");
        assert_eq!(r["since"], T0 - 300);
        assert_ne!(r["since"], 0);
    }
    assert!(
        reqs[0].get("until").is_none(),
        "the first page has no until"
    );
    // `until` is inclusive: the oldest of the page just read (T0+250), then
    // of the next (T0+51); the overlap is dropped by id.
    assert_eq!(reqs[1]["until"], T0 + 250);
    assert_eq!(reqs[2]["until"], T0 + 51);
}

#[tokio::test]
async fn a_page_that_adds_nothing_new_ends_the_catch_up() {
    let now = Arc::new(AtomicU64::new(T0 + 10_000));
    let relay = TestRelay::start(now).await.unwrap();
    // 250 events in one second: `until` cannot move past them.
    for i in 0..250 {
        relay.inject_unchecked(event_at(T0, &format!("same{i}")));
    }
    let c = NostrRelay::new(cfg(&relay.url())).unwrap();
    let got = c
        .fetch(KIND_MAILBOX, &author(), Some(T0 - 300))
        .await
        .unwrap();
    assert!(got.len() >= 200 && got.len() <= 250);
    assert!(relay.req_filters().len() <= 3, "it stops, it does not spin");
}

#[tokio::test]
async fn at_most_eight_catch_up_reqs_are_open_at_once() {
    let now = Arc::new(AtomicU64::new(T0 + 10));
    let relay = TestRelay::start(now).await.unwrap();
    relay.inject_unchecked(event_at(T0, "one"));
    relay.set_eose_delay_ms(60);
    let c = Arc::new(NostrRelay::new(cfg(&relay.url())).unwrap());
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let c = c.clone();
        let a = author();
        tasks.push(tokio::spawn(async move {
            c.fetch(KIND_MAILBOX, &a, Some(T0 - 300))
                .await
                .unwrap()
                .len()
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 1, "every waiting fetch is answered");
    }
    let open = relay.max_open_subscriptions();
    assert!(open >= 2, "they did overlap ({open})");
    assert!(open <= 8, "never more than 8 open at once ({open})");
    assert!(open <= 20);
}

#[tokio::test]
async fn a_reconnect_continues_the_page_instead_of_starting_over() {
    let now = Arc::new(AtomicU64::new(T0 + 10_000));
    let relay = TestRelay::start(now).await.unwrap();
    for i in 0..250u64 {
        relay.inject_unchecked(event_at(T0 + i, &format!("e{i}")));
    }
    relay.set_eose_delay_ms(150);
    let c = Arc::new(NostrRelay::new(cfg(&relay.url())).unwrap());
    let a = author();
    let c2 = c.clone();
    let f = tokio::spawn(async move { c2.fetch(KIND_MAILBOX, &a, Some(T0 - 300)).await });
    tokio::time::sleep(Duration::from_millis(400)).await; // into page 2
    relay.drop_connections();
    let got = f.await.unwrap().unwrap();
    assert_eq!(got.len(), 250);
    for r in relay.req_filters() {
        assert_eq!(r["limit"], 200);
        assert_ne!(r["since"], 0);
    }
}

#[tokio::test]
async fn an_event_dated_over_900_seconds_ahead_is_not_posted() {
    let sys = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now = Arc::new(AtomicU64::new(sys));
    let relay = TestRelay::start(now).await.unwrap();
    let c = NostrRelay::new(cfg(&relay.url())).unwrap();
    let e = c
        .publish(event_at(sys + 1_000, "future"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("900"), "{e}");
    assert_eq!(relay.publishes_seen(), 0, "it never left");
    // 800 s ahead is inside the relay's tolerance.
    c.publish(event_at(sys + 800, "soon")).await.unwrap();
    assert_eq!(relay.events().len(), 1);
    // And the relay refuses one that gets past a client with a skewed clock.
    let (mut ws, _) = tokio_tungstenite::connect_async(relay.url().as_str())
        .await
        .unwrap();
    ws.send(Message::Text(
        serde_json::json!(["EVENT", event_at(sys + 2_000, "x").to_json()])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let Some(Ok(Message::Text(t))) = ws.next().await else {
        panic!("no reply")
    };
    let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
    assert_eq!(v[2], false, "{v}");
}

#[tokio::test]
async fn posting_stops_at_120_000_bytes_without_truncating() {
    let now = Arc::new(AtomicU64::new(T0));
    let relay = TestRelay::start(now).await.unwrap();
    let c = NostrRelay::new(cfg(&relay.url())).unwrap();
    // Find the content length that makes the event exactly 120,000 bytes.
    let base = event_at(T0, "").json_len();
    let fit = event_at(T0, &"A".repeat(120_000 - base));
    assert_eq!(fit.json_len(), 120_000);
    c.publish(fit).await.unwrap();
    let over = event_at(T0, &"A".repeat(120_001 - base));
    assert_eq!(over.json_len(), 120_001);
    let e = c.publish(over).await.unwrap_err().to_string();
    assert!(e.contains("120000") && e.contains("not truncated"), "{e}");
    assert_eq!(relay.events().len(), 1);
}

// ---- P1-9: CLOSE on every exit path, and no silent truncation ----------------

async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f()
}

#[tokio::test]
async fn a_fetch_that_times_out_closes_its_subscription() {
    let now = Arc::new(AtomicU64::new(T0 + 10_000));
    let relay = TestRelay::start(now).await.unwrap();
    relay.set_withhold_eose(true);
    let mut c = cfg(&relay.url());
    c.op_timeout = Duration::from_millis(600);
    let client = NostrRelay::new(c).unwrap();
    let err = client
        .fetch(KIND_MAILBOX, &author(), Some(T0 - 300))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("deadline") || err.to_string().contains("answer"));
    assert!(
        eventually(|| relay.open_subscriptions() == 0).await,
        "the timed-out REQ was left open: {} open, closes {:?}",
        relay.open_subscriptions(),
        relay.closes_seen()
    );
    assert_eq!(relay.closes_seen().len(), 1);
}

#[tokio::test]
async fn an_eose_for_an_unknown_subscription_is_answered_with_close() {
    let now = Arc::new(AtomicU64::new(T0 + 10_000));
    let relay = TestRelay::start(now).await.unwrap();
    relay.set_stray_eose(true);
    relay.inject_unchecked(event_at(T0, "x"));
    let client = NostrRelay::new(cfg(&relay.url())).unwrap();
    let got = client
        .fetch(KIND_MAILBOX, &author(), Some(T0 - 300))
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert!(
        eventually(|| relay.closes_seen().iter().any(|s| s.starts_with("stray-"))).await,
        "{:?}",
        relay.closes_seen()
    );
}

#[tokio::test]
async fn more_than_5000_events_are_paged_with_until_not_silently_cut() {
    let now = Arc::new(AtomicU64::new(T0 + 100_000));
    let relay = TestRelay::start(now).await.unwrap();
    let total = 5_300u64;
    for i in 0..total {
        relay.inject_unchecked(event_at(T0 + i, &format!("e{i}")));
    }
    let client = NostrRelay::new(cfg(&relay.url())).unwrap();
    let got = client
        .fetch(KIND_MAILBOX, &author(), Some(T0 - 300))
        .await
        .unwrap();
    assert_eq!(got.len() as u64, total, "every event, none lost");
    let ids: std::collections::HashSet<_> = got.iter().map(|e| e.id.clone()).collect();
    assert_eq!(ids.len() as u64, total, "once each");
    // The oldest are there: the cut used to drop them.
    assert!(got.iter().any(|e| e.created_at == T0));
    // Every REQ kept the relay manners: limit 200, never from zero.
    for r in relay.req_filters() {
        assert_eq!(r["limit"], 200);
        assert_eq!(r["since"], T0 - 300);
    }
    assert!(relay.max_open_subscriptions() <= 8);
    assert!(eventually(|| relay.open_subscriptions() == 0).await);
}

#[tokio::test]
async fn one_read_reports_that_more_is_available() {
    let now = Arc::new(AtomicU64::new(T0 + 100_000));
    let relay = TestRelay::start(now).await.unwrap();
    for i in 0..5_300u64 {
        relay.inject_unchecked(event_at(T0 + i, &format!("e{i}")));
    }
    let client = NostrRelay::new(cfg(&relay.url())).unwrap();
    let page = client
        .fetch_page(KIND_MAILBOX, &author(), Some(T0 - 300), None)
        .await
        .unwrap();
    assert_eq!(page.events.len(), 5_000);
    let until = page.more_until.expect("the read says there is more");
    let rest = client
        .fetch_page(KIND_MAILBOX, &author(), Some(T0 - 300), Some(until))
        .await
        .unwrap();
    assert_eq!(rest.more_until, None, "the window is complete");
    let all: std::collections::HashSet<_> = page
        .events
        .iter()
        .chain(&rest.events)
        .map(|e| e.id.clone())
        .collect();
    assert_eq!(all.len(), 5_300);
}
