//! End to end over a real websocket to an in-process relay on 127.0.0.1
//! (feature `geb-live`). Nothing here reaches a real relay or a real Geb node:
//! the relay is `geb::test_relay::TestRelay`, started by each test on an
//! ephemeral loopback port.
#![cfg(feature = "geb-live")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use vti_geb_bridge::geb::dyad::{GebIdentity, Phase, StatefulDyad};
use vti_geb_bridge::geb::event::{KIND_INBOX, KIND_MAILBOX, standard_tags};
use vti_geb_bridge::geb::nostr::{NostrConfig, NostrRelay};
use vti_geb_bridge::geb::test_relay::TestRelay;
use vti_geb_bridge::geb::traits::{GebDyad, GebRelay, RelayEvent};
use vti_geb_bridge::geb::wire::Frame;
use vti_geb_bridge::store::MemoryStore;

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
    let big = RelayEvent::sign(&sk, KIND_MAILBOX, T0, vec![], "A".repeat(70_000)).unwrap();
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
    let big = RelayEvent::sign(&sk, KIND_MAILBOX, T0, vec![], "A".repeat(70_000)).unwrap();
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
    let got: Vec<_> =
        n.b.recv(n.a.did())
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
    let got: Vec<_> =
        n.b.recv(n.a.did())
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
    assert!(n.b.recv(n.a.did()).await.unwrap().is_empty());
}
