//! `GebRoom`: the Geb adapter as a [`ForeignRoom`], composed from the
//! trait seams in `traits`.
//!
//! What works against the doubles: building and signing a line, sealing it
//! into a room envelope and a mailbox event, reading the relay back as the
//! delivery evidence (`Relayed`, never `Delivered`), and the inbound path with
//! the 7-day dedup rule, own-leaf skipping and signature checking.
//!
//! What is not built, and fails closed: the real MLS group (`UnsupportedGroup`);
//! the dyad is `geb::dyad::StatefulDyad`; a commit (`mc`) envelope in the room is an
//! error because applying the settle rule is M3 and skipping it would fork the
//! epoch silently.

use super::crypto::{b64_decode, b64_encode, did_peer, pair, sign};
use super::traits::{
    GebCodec, GebGroup, GebRelay, GebSigner, OpenedMessage, RelayEvent, SettleReport,
};
use super::wire::{Envelope, LineBody, MAX_EVENT_BYTES, MAX_LINE_CHARS, signing_doc, utf16_len};
use crate::foreign::{
    Cursor, ForeignIdentity, ForeignRoom, JoinState, Polled, Posted, Receipt, RoomCapabilities,
    Verifiability,
};
use crate::geb::crypto::line_id::line_id;
use crate::geb::crypto::rendezvous::RelayKeys;
use crate::mapping::{DedupWindow, msg_hash};
use crate::model::{AuthorCheck, BridgeEvent, EventKind, Origin, Provenance};
use crate::{Error, Result};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// Mailbox kind for pair and room envelopes.
pub const KIND_MAILBOX: u32 = 4177;
/// Events expire after 7 days.
pub const EXPIRY_SECS: u64 = 7 * 24 * 3600;
/// Re-read this far behind the newest event, as the guide's readers do.
pub const SINCE_SLACK_SECS: u64 = 300;

/// Most epoch changes followed in one poll.
pub const MAX_EPOCH_HOPS: usize = 8;

/// Clock in milliseconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The MLS group is M3: Geb's answers settle the policy and capabilities, but
/// the commit check needs persona cards and signed leaves the bridge lacks.
pub struct UnsupportedGroup;

const M3: &str = "Geb MLS group (M3): needs OpenMLS, persona cards and signed leaves before any commit can be applied";

#[async_trait]
impl GebGroup for UnsupportedGroup {
    async fn ensure_seated(&self) -> Result<JoinState> {
        Err(Error::Unsupported(M3))
    }
    async fn leave(&self) -> Result<()> {
        Err(Error::Unsupported(M3))
    }
    fn relay_keys(&self) -> Result<RelayKeys> {
        Err(Error::Unsupported(M3))
    }
    fn seal(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Unsupported(M3))
    }
    fn open(&self, _message: &[u8]) -> Result<OpenedMessage> {
        Err(Error::Unsupported(M3))
    }
}

/// Geb room as a foreign room.
pub struct GebRoom {
    room_id: String,
    relay: Arc<dyn GebRelay>,
    group: Arc<dyn GebGroup>,
    signer: Arc<dyn GebSigner>,
    codec: Arc<dyn GebCodec>,
    clock: Clock,
    seen: Mutex<DedupWindow>,
}

impl GebRoom {
    /// Compose the adapter.
    pub fn new(
        room_id: String,
        relay: Arc<dyn GebRelay>,
        group: Arc<dyn GebGroup>,
        signer: Arc<dyn GebSigner>,
        codec: Arc<dyn GebCodec>,
        clock: Clock,
    ) -> Self {
        Self {
            room_id,
            relay,
            group,
            signer,
            codec,
            clock,
            seen: Mutex::new(DedupWindow::default()),
        }
    }

    /// One pass under the current epoch's relay keys.
    async fn poll_epoch(&self, after: Option<&Cursor>) -> Result<(Vec<Polled>, SettleReport)> {
        let keys = self.group.relay_keys()?;
        let mailbox = keys.pubkey_hex()?;
        // Never an unbounded read: from the cursor minus 300 s, or on the first
        // read from the start of the relay's 7-day retention (events carry a
        // NIP-40 expiration of 7 days), so no read repeats from `since: 0`.
        let since = after
            .and_then(|c| <[u8; 8]>::try_from(c.0.as_slice()).ok())
            .map(u64::from_be_bytes)
            .map(|t| t.saturating_sub(SINCE_SLACK_SECS))
            .unwrap_or_else(|| ((self.clock)() / 1000).saturating_sub(EXPIRY_SECS));
        let since = Some(since);
        let mut events = self.relay.fetch(KIND_MAILBOX, &mailbox, since).await?;
        // A relay's word is not enough: drop anything that does not verify,
        // or that is not the mailbox's own.
        events.retain(|e| {
            let ok = e.pubkey == mailbox && e.kind == KIND_MAILBOX && e.verify().is_ok();
            if !ok {
                tracing::warn!(event = %e.id, "dropping a relay event that does not verify");
            }
            ok
        });
        // Relays return newest first.
        events.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let now = (self.clock)();
        let mut out = Vec::new();
        for ev in events {
            let cursor = Cursor(ev.created_at.to_be_bytes().to_vec());
            // Anything we cannot open or understand is dropped, never acted on.
            let Some(envelope) = pair::open(&keys, KIND_MAILBOX, &ev.content)
                .and_then(|b| self.codec.decode_envelope(&b))
                .map_err(|e| tracing::warn!(event = %ev.id, error = %e, "dropping unreadable mailbox event"))
                .ok()
            else {
                continue;
            };
            let m = match envelope {
                Envelope::Ml { m } => m,
                // A commit is held, never applied at once: the group runs the
                // settle rule. A group that cannot refuses (the default),
                // which stops the poll rather than fork the epoch silently.
                Envelope::Mc { e, m } => {
                    let Ok(bytes) = b64_decode(&m) else {
                        tracing::warn!(event = %ev.id, "dropping a commit that is not base64");
                        continue;
                    };
                    self.group
                        .hold_commit(e, &bytes, ev.created_at, now)
                        .await?;
                    continue;
                }
                // Dyad envelopes and receipts do not belong in a room mailbox.
                Envelope::Frame { .. }
                | Envelope::Ack { .. }
                | Envelope::Response { .. }
                | Envelope::Completion { .. } => continue,
            };
            let Ok(bytes) = b64_decode(&m) else {
                tracing::warn!(event = %ev.id, "dropping a room message that is not base64");
                continue;
            };
            let hash = msg_hash(&bytes);
            let fresh = self
                .seen
                .lock()
                .map_err(|_| Error::Foreign("poisoned".into()))?
                .check_and_insert(&hash, now);
            if !fresh {
                continue;
            }
            let opened = match self.group.open(&bytes) {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(error = %e, "dropping message the group could not open");
                    continue;
                }
            };
            if opened.sender_did == self.signer.did() {
                continue; // our own leaf
            }
            let Ok(line) = self.codec.decode_line(&opened.plaintext) else {
                tracing::warn!("dropping a non-line room message");
                continue;
            };
            let check = self.check_author(&opened.sender_did, &line);
            out.push(Polled {
                event: BridgeEvent {
                    origin: Origin::Foreign,
                    origin_id: hash.clone(),
                    link: String::new(),
                    author: opened.sender_did.clone(),
                    at: line.at,
                    title: None,
                    text: line.text,
                    kind: EventKind::Post,
                    reply_to: line.re.clone(),
                    record_key: None,
                    provenance: Some(Provenance {
                        foreign_room: self.room_id.clone(),
                        author_device: opened.sender_did,
                        check,
                        original_at: line.at,
                        msg_hash: hash,
                    }),
                },
                cursor,
            });
        }
        let report = self.group.settle((self.clock)()).await?;
        Ok((out, report))
    }

    fn check_author(&self, sender: &str, line: &LineBody) -> AuthorCheck {
        let Some(sg) = line.sg.as_deref() else {
            return AuthorCheck::Unsigned;
        };
        let verified = signing_doc(&self.room_id, sender, line)
            .and_then(|doc| {
                let key = did_peer::decode(sender)?.verifying_key()?;
                sign::verify_json(&key, &doc, sg)
            })
            .is_ok();
        if verified {
            AuthorCheck::Verified
        } else {
            AuthorCheck::Unverified
        }
    }
}

#[async_trait]
impl ForeignRoom for GebRoom {
    async fn join(&self) -> Result<JoinState> {
        self.group.ensure_seated().await
    }

    async fn leave(&self) -> Result<()> {
        self.group.leave().await
    }

    async fn poll(&self, after: Option<&Cursor>) -> Result<Vec<Polled>> {
        let mut out = Vec::new();
        // A merged commit changes the relay keys: read again under the new
        // ones (bounded, so a flood of commits cannot spin us).
        for _ in 0..MAX_EPOCH_HOPS {
            let (mut got, report) = self.poll_epoch(after).await?;
            // The read cursor stays before a held or failed commit.
            if let Some(barrier) = report.cursor_barrier_secs {
                for p in &mut got {
                    let at = <[u8; 8]>::try_from(p.cursor.0.as_slice())
                        .map(u64::from_be_bytes)
                        .unwrap_or(u64::MAX);
                    if at > barrier {
                        p.cursor = Cursor(barrier.to_be_bytes().to_vec());
                    }
                }
            }
            out.extend(got);
            if !report.epoch_changed {
                break;
            }
        }
        Ok(out)
    }

    async fn post(&self, event: &BridgeEvent) -> Result<Posted> {
        // Geb has no visible edit or delete: mapping must already have turned
        // those into plain posts. Refuse rather than guess.
        if event.kind != EventKind::Post {
            return Err(Error::Foreign(
                "Geb accepts only plain posts; mapping must flatten edits and retractions".into(),
            ));
        }
        // Geb counts a line's text in UTF-16 code units (JavaScript string
        // length) and every receiver drops a longer one (round 3 section 6):
        // refuse, never truncate. The mapping layer already cuts text to the
        // byte cap in `capabilities()`, which is never more than 20,000 units.
        let units = utf16_len(&event.text);
        if units > MAX_LINE_CHARS {
            return Err(Error::Foreign(format!(
                "line is {units} UTF-16 code units; the limit is {MAX_LINE_CHARS}; refused, not truncated"
            )));
        }
        // A retraction (or a supersede, where edit is unsupported) is an
        // ordinary signed line whose `re` is the original line's derived id:
        // never a new message kind (answer 11).
        let mut line = match &event.reply_to {
            Some(re) => LineBody::reply(event.at, event.text.clone(), re.clone()),
            None => LineBody::new(event.at, event.text.clone()),
        };
        let foreign_ref = line_id(&self.room_id, self.signer.did(), line.at, &line.text)?;
        let doc = signing_doc(&self.room_id, self.signer.did(), &line)?;
        line.sg = Some(self.signer.sign_json(&doc)?);
        let m = self.group.seal(&self.codec.encode_line(&line)?)?;
        let envelope = self
            .codec
            .encode_envelope(&Envelope::Ml { m: b64_encode(&m) })?;
        let keys = self.group.relay_keys()?;
        let mailbox = keys.pubkey_hex()?;
        let content = pair::seal(&keys, KIND_MAILBOX, &envelope)?;
        let created_at = (self.clock)() / 1000;
        let ev = RelayEvent::sign(
            &keys.nostr_secret,
            KIND_MAILBOX,
            created_at,
            super::event::standard_tags(created_at),
            content,
        )?;
        if ev.json_len() > MAX_EVENT_BYTES {
            return Err(Error::Foreign(format!(
                "event is {} bytes; the limit is {MAX_EVENT_BYTES}; refused, not truncated",
                ev.json_len()
            )));
        }
        let id = ev.id.clone();
        self.relay.publish(ev).await?;
        // R1.1: an Ok from publish is not delivery. Reading our own event back
        // is the strongest evidence available, and it is Relayed at most.
        let back = self
            .relay
            .fetch(KIND_MAILBOX, &mailbox, Some(created_at.saturating_sub(1)))
            .await?;
        let receipt = if back.iter().any(|e| e.id == id) {
            Receipt::Relayed
        } else {
            Receipt::Accepted
        };
        Ok(Posted {
            receipt,
            foreign_ref: Some(foreign_ref),
        })
    }

    fn identity(&self) -> ForeignIdentity {
        ForeignIdentity {
            id: self.signer.did().to_string(),
        }
    }

    fn capabilities(&self) -> RoomCapabilities {
        RoomCapabilities {
            // Geb caps a line at 20,000 UTF-16 code units; a byte cap of
            // 20,000 satisfies that for any UTF-8 text (a unit is at least
            // one byte), at the price of cutting multi-byte text early.
            // `post` itself counts units.
            max_message_bytes: MAX_LINE_CHARS,
            supports_edit: false,
            supports_delete: false,
            // `re` is the derived id of the line answered (answer 10).
            supports_replies: true,
            authors_verifiable: Verifiability::PerMessage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Directions;
    use crate::geb::codec::GuideCodec;
    use crate::geb::crypto::sign::LocalSigner;
    use crate::geb::fake::{FakeGroup, FakeRelay};
    use crate::pump::{LinkRuntime, Pump};
    use crate::room::MemoryRoom;
    use crate::store::MemoryStore;
    use ed25519_dalek::SigningKey;

    fn device(seed: u8) -> (String, SigningKey) {
        let k = SigningKey::from_bytes(&[seed; 32]);
        let did = did_peer::encode(&k.verifying_key().to_bytes(), &[seed; 32], None).unwrap();
        (did, k)
    }

    fn room_for(relay: &Arc<FakeRelay>, seed: u8, now: u64) -> (GebRoom, String, SigningKey) {
        let (did, key) = device(seed);
        let r = GebRoom::new(
            "room-1".into(),
            relay.clone(),
            Arc::new(FakeGroup::new(&did)),
            Arc::new(LocalSigner::new(did.clone(), key.clone())),
            Arc::new(GuideCodec),
            Arc::new(move || now),
        );
        (r, did, key)
    }

    fn post_event(text: &str) -> BridgeEvent {
        BridgeEvent {
            origin: Origin::Vtc,
            origin_id: "k|1".into(),
            link: "l1".into(),
            author: "did:alice".into(),
            at: 1_700_000_000_000,
            title: None,
            text: text.into(),
            kind: EventKind::Post,
            reply_to: None,
            record_key: None,
            provenance: None,
        }
    }

    #[tokio::test]
    async fn two_members_exchange_a_signed_line_and_the_receipt_is_relayed() {
        let relay = Arc::new(FakeRelay::new());
        let (a, a_did, _) = room_for(&relay, 1, 1_700_000_000_000);
        let (b, _b_did, _) = room_for(&relay, 2, 1_700_000_001_000);
        let receipt = a.post(&post_event("hello geb")).await.unwrap();
        assert_eq!(receipt.receipt, Receipt::Relayed);
        assert_eq!(
            receipt.foreign_ref.as_deref(),
            Some(
                line_id("room-1", &a_did, 1_700_000_000_000, "hello geb")
                    .unwrap()
                    .as_str()
            )
        );
        let got = b.poll(None).await.unwrap();
        assert_eq!(got.len(), 1);
        let ev = &got[0].event;
        assert_eq!(ev.text, "hello geb");
        assert_eq!(ev.author, a_did, "author is the sender");
        assert_eq!(ev.provenance.as_ref().unwrap().check, AuthorCheck::Verified);
        // The sender does not see its own line back.
        assert!(a.poll(None).await.unwrap().is_empty());
        // Replaying the same events is a no-op thanks to the dedup window.
        assert!(b.poll(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn dropped_publish_is_only_accepted() {
        let relay = Arc::new(FakeRelay::new());
        relay.set_dropping(true);
        let (a, _, _) = room_for(&relay, 1, 1_700_000_000_000);
        assert_eq!(
            a.post(&post_event("lost")).await.unwrap().receipt,
            Receipt::Accepted
        );
    }

    #[tokio::test]
    async fn forged_and_unsigned_lines_are_marked_not_trusted() {
        let relay = Arc::new(FakeRelay::new());
        let (b, _, _) = room_for(&relay, 2, 1_700_000_001_000);
        let keys = FakeGroup::new("x").relay_keys().unwrap();
        let (mallory_did, mallory_key) = device(9);
        let (victim_did, _) = device(7);
        let codec = GuideCodec;
        let mut n = 0u64;
        let mut post = |sender: &str, line: LineBody| {
            n += 1;
            let g = FakeGroup::new(sender);
            let m = g.seal(&codec.encode_line(&line).unwrap()).unwrap();
            let env = codec
                .encode_envelope(&Envelope::Ml { m: b64_encode(&m) })
                .unwrap();
            let content = pair::seal(&keys, KIND_MAILBOX, &env).unwrap();
            relay.inject(
                RelayEvent::sign(
                    &keys.nostr_secret,
                    KIND_MAILBOX,
                    1_700_000_000 + n,
                    vec![],
                    content,
                )
                .unwrap(),
            );
        };
        // Unsigned line.
        post(&mallory_did, LineBody::new(1, "unsigned".into()));
        // Signed by mallory's key but claiming to be the victim's device.
        let mut forged = LineBody::new(2, "forged".into());
        let doc = signing_doc("room-1", &victim_did, &forged).unwrap();
        forged.sg = Some(sign::sign_json(&mallory_key, &doc).unwrap());
        post(&victim_did, forged);
        // A signature over some other room.
        let mut wrong_room = LineBody::new(3, "wrong room".into());
        let doc = signing_doc("other-room", &mallory_did, &wrong_room).unwrap();
        wrong_room.sg = Some(sign::sign_json(&mallory_key, &doc).unwrap());
        post(&mallory_did, wrong_room);
        // A properly signed line.
        let mut good = LineBody::new(4, "good".into());
        let doc = signing_doc("room-1", &mallory_did, &good).unwrap();
        good.sg = Some(sign::sign_json(&mallory_key, &doc).unwrap());
        post(&mallory_did, good);

        let got = b.poll(None).await.unwrap();
        let checks: Vec<_> = got
            .iter()
            .map(|p| {
                (
                    p.event.text.as_str(),
                    p.event.provenance.as_ref().unwrap().check,
                )
            })
            .collect();
        assert_eq!(
            checks,
            vec![
                ("unsigned", AuthorCheck::Unsigned),
                ("forged", AuthorCheck::Unverified),
                ("wrong room", AuthorCheck::Unverified),
                ("good", AuthorCheck::Verified),
            ]
        );
    }

    #[tokio::test]
    async fn garbage_is_dropped_and_commits_stop_the_poll() {
        let relay = Arc::new(FakeRelay::new());
        let (b, _, _) = room_for(&relay, 2, 1_700_000_001_000);
        let keys = FakeGroup::new("x").relay_keys().unwrap();
        // Inside the 7-day window a first read starts at.
        let mk = |_id: &str, at: u64, content: String| {
            RelayEvent::sign(
                &keys.nostr_secret,
                KIND_MAILBOX,
                1_700_000_000 + at,
                vec![],
                content,
            )
            .unwrap()
        };
        relay.inject(mk("g1", 1, "!!not base64!!".into()));
        // A forged signature on an otherwise valid event is dropped too.
        let mut forged = mk(
            "g0",
            1,
            pair::seal(&keys, KIND_MAILBOX, br#"{"t":"ack","a":[]}"#).unwrap(),
        );
        forged.sig = "00".repeat(64);
        relay.inject(forged);
        relay.inject(mk(
            "g2",
            2,
            pair::seal(&keys, KIND_MAILBOX, b"{not json").unwrap(),
        ));
        relay.inject(mk(
            "g3",
            3,
            pair::seal(&keys, KIND_MAILBOX, br#"{"t":"zz"}"#).unwrap(),
        ));
        relay.inject(mk(
            "g4",
            4,
            pair::seal(&keys, KIND_MAILBOX, br#"{"t":"ack","a":[]}"#).unwrap(),
        ));
        assert!(b.poll(None).await.unwrap().is_empty());
        relay.inject(mk(
            "c1",
            5,
            pair::seal(&keys, KIND_MAILBOX, br#"{"t":"mc","e":1,"m":"QQ=="}"#).unwrap(),
        ));
        assert!(matches!(b.poll(None).await, Err(Error::Unsupported(_))));
    }

    #[tokio::test]
    async fn refuses_unflattened_kinds_and_oversize() {
        let relay = Arc::new(FakeRelay::new());
        let (a, _, _) = room_for(&relay, 1, 1_700_000_000_000);
        let mut e = post_event("x");
        e.kind = EventKind::Retract {
            target: "k|1".into(),
        };
        assert!(a.post(&e).await.is_err());
        assert!(a.post(&post_event(&"x".repeat(20_001))).await.is_err());
        assert!(relay.all().is_empty());
    }

    /// Round 3 section 6: a line is at most 20,000 UTF-16 code units, counted
    /// as JavaScript counts, not bytes and not characters.
    #[tokio::test]
    async fn the_line_limit_counts_utf16_units_not_chars_or_bytes() {
        let relay = Arc::new(FakeRelay::new());
        let (a, _, _) = room_for(&relay, 1, 1_700_000_000_000);
        let (b, _, _) = room_for(&relay, 2, 1_700_000_001_000);
        // 10,000 emoji are 20,000 units (and 40,000 bytes): at the limit.
        assert_eq!(utf16_len(&"\u{1F600}".repeat(10_000)), 20_000);
        a.post(&post_event(&"\u{1F600}".repeat(10_000)))
            .await
            .unwrap();
        // 10,001 emoji are only 10,001 chars but 20,002 units: refused.
        let e = a
            .post(&post_event(&"\u{1F600}".repeat(10_001)))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("20002") && e.contains("UTF-16"), "{e}");
        // 19,999 ASCII + one emoji: 20,000 chars, 20,001 units: refused.
        let edge = format!("{}\u{1F600}", "a".repeat(19_999));
        assert_eq!(edge.chars().count(), 20_000);
        assert!(a.post(&post_event(&edge)).await.is_err());
        // 20,000 two-byte characters are 20,000 units: accepted.
        a.post(&post_event(&"\u{e9}".repeat(20_000))).await.unwrap();
        assert_eq!(
            relay.all().len(),
            2,
            "refused lines never reached the relay"
        );
        let got = b.poll(None).await.unwrap();
        assert_eq!(got.len(), 2);
    }

    #[tokio::test]
    async fn a_received_line_over_20000_units_is_dropped() {
        let relay = Arc::new(FakeRelay::new());
        let (b, _, _) = room_for(&relay, 2, 1_700_000_001_000);
        let (did, _) = device(9);
        let g = FakeGroup::new(&did);
        let keys = g.relay_keys().unwrap();
        let line = |at: u64, text: &str| {
            let plain =
                serde_json::to_vec(&serde_json::json!({"t":"l","at":at,"text":text})).unwrap();
            let env = format!(
                r#"{{"t":"ml","m":"{}"}}"#,
                b64_encode(&g.seal(&plain).unwrap())
            );
            RelayEvent::sign(
                &keys.nostr_secret,
                KIND_MAILBOX,
                at / 1000,
                vec![],
                pair::seal(&keys, KIND_MAILBOX, env.as_bytes()).unwrap(),
            )
            .unwrap()
        };
        relay.inject(line(1_700_000_000_000, &"\u{1F600}".repeat(10_001)));
        relay.inject(line(1_700_000_000_001, &"\u{1F600}".repeat(10_000)));
        let got = b.poll(None).await.unwrap();
        assert_eq!(got.len(), 1, "only the line within the limit");
        assert_eq!(got[0].event.text.chars().count(), 10_000);
    }

    /// Round 3 section 6: no event over 120,000 bytes; an error, not a cut.
    struct Padded(FakeGroup, usize);
    #[async_trait]
    impl GebGroup for Padded {
        async fn ensure_seated(&self) -> Result<JoinState> {
            self.0.ensure_seated().await
        }
        async fn leave(&self) -> Result<()> {
            Ok(())
        }
        fn relay_keys(&self) -> Result<RelayKeys> {
            self.0.relay_keys()
        }
        fn seal(&self, p: &[u8]) -> Result<Vec<u8>> {
            let mut v = self.0.seal(p)?;
            v.extend(std::iter::repeat_n(b' ', self.1));
            Ok(v)
        }
        fn open(&self, m: &[u8]) -> Result<OpenedMessage> {
            self.0.open(m)
        }
    }

    #[tokio::test]
    async fn an_event_over_120000_bytes_is_refused_not_truncated() {
        let (did, key) = device(1);
        let mk = |pad: usize, relay: &Arc<FakeRelay>| {
            GebRoom::new(
                "room-1".into(),
                relay.clone(),
                Arc::new(Padded(FakeGroup::new(&did), pad)),
                Arc::new(LocalSigner::new(did.clone(), key.clone())),
                Arc::new(GuideCodec),
                Arc::new(|| 1_700_000_000_000),
            )
        };
        let relay = Arc::new(FakeRelay::new());
        let e = mk(100_000, &relay)
            .post(&post_event("hi"))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("120000") && e.contains("not truncated"), "{e}");
        assert!(relay.all().is_empty());
        // The largest legal line (20,000 three-byte characters, about 107,000
        // bytes once sealed and wrapped twice) is under the limit, and was
        // over the old 65,536.
        let ok = mk(0, &relay)
            .post(&post_event(&"\u{4e2d}".repeat(20_000)))
            .await
            .unwrap();
        assert_eq!(ok.receipt, Receipt::Relayed);
        let sent = relay.all();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].json_len() > 65_536 && sent[0].json_len() <= MAX_EVENT_BYTES);
    }

    #[tokio::test]
    async fn m3_pieces_fail_closed() {
        let relay = Arc::new(FakeRelay::new());
        let (did, key) = device(1);
        let r = GebRoom::new(
            "room-1".into(),
            relay,
            Arc::new(UnsupportedGroup),
            Arc::new(LocalSigner::new(did, key)),
            Arc::new(GuideCodec),
            Arc::new(|| 0),
        );
        assert!(matches!(r.join().await, Err(Error::Unsupported(_))));
        assert!(matches!(
            r.post(&post_event("x")).await,
            Err(Error::Unsupported(_))
        ));
    }

    /// The pump, unchanged, against the fake Geb adapter and against loopback.
    #[tokio::test]
    async fn pump_runs_against_fake_geb() {
        let relay = Arc::new(FakeRelay::new());
        let (bridge, bridge_did, _) = room_for(&relay, 1, 1_700_000_000_000);
        let (human, _, _) = room_for(&relay, 2, 1_700_000_000_500);
        let room = Arc::new(MemoryRoom::new());
        let store = Arc::new(MemoryStore::new());
        let pump = Pump::new(
            LinkRuntime::new("l1", "did:key:persona", b"s".to_vec(), Directions::Both),
            room.clone(),
            Arc::new(bridge),
            store,
        );
        pump.start().await.unwrap();
        room.add("did:alice", Some("Plan"), "ship it", 1).unwrap();
        human.post(&post_event("hello from geb")).await.unwrap();
        let r = pump.tick().await.unwrap();
        assert_eq!((r.posted, r.written), (1, 1));
        let w = &room.writes()[0];
        assert!(w.body.contains("hello from geb") && w.body.contains("signature verified"));
        // The Geb member sees the bridged post, with the quoted header.
        let seen = human.poll(None).await.unwrap();
        let bridged: Vec<_> = seen
            .iter()
            .filter(|p| p.event.author == bridge_did)
            .collect();
        assert_eq!(bridged.len(), 1);
        assert!(
            bridged[0]
                .event
                .text
                .starts_with("> did:alice wrote:\nPlan\n\nship it")
        );
        // Nothing echoes on the next tick.
        let r2 = pump.tick().await.unwrap();
        assert_eq!((r2.posted, r2.written), (0, 0));
    }

    #[tokio::test]
    async fn a_retraction_is_an_ordinary_signed_reply_line() {
        let relay = Arc::new(FakeRelay::new());
        let (a, a_did, _) = room_for(&relay, 1, 1_700_000_000_000);
        let (b, _, _) = room_for(&relay, 2, 1_700_000_001_000);
        let first = a.post(&post_event("original")).await.unwrap();
        let original = first.foreign_ref.unwrap();
        let mut retract = post_event("[retracted: earlier post k|1]");
        retract.at += 1;
        retract.reply_to = Some(original.clone());
        a.post(&retract).await.unwrap();
        let got = b.poll(None).await.unwrap();
        assert_eq!(got.len(), 2);
        // The reader derives the same id for the original line.
        let derived = line_id("room-1", &a_did, 1_700_000_000_000, "original").unwrap();
        assert_eq!(derived, original);
        // Relay order within one second is by event id, so find the reply.
        let reply = got
            .iter()
            .find(|p| p.event.text.starts_with("[retracted"))
            .unwrap();
        assert_eq!(reply.event.reply_to.as_deref(), Some(derived.as_str()));
        assert_eq!(
            reply.event.provenance.as_ref().unwrap().check,
            AuthorCheck::Verified
        );
        // A malformed reference is refused, not sent.
        retract.reply_to = Some("NOT-HEX".into());
        assert!(a.post(&retract).await.is_err());
    }

    #[tokio::test]
    async fn seating_states_pass_through() {
        use crate::foreign::JoinState;
        let relay = Arc::new(FakeRelay::new());
        let (did, key) = device(1);
        let group = Arc::new(FakeGroup::new(&did));
        let r = GebRoom::new(
            "room-1".into(),
            relay,
            group.clone(),
            Arc::new(LocalSigner::new(did, key)),
            Arc::new(GuideCodec),
            Arc::new(|| 0),
        );
        assert_eq!(r.join().await.unwrap(), JoinState::Seated);
        group.set_join_state(JoinState::Pending);
        assert_eq!(r.join().await.unwrap(), JoinState::Pending);
        group.refuse("removed");
        assert!(matches!(r.join().await, Err(Error::Refused(_))));
    }
}
