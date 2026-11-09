//! Room status `rs`, `rc` catch-up, fork verdicts, `seat-ask`, re-seat Welcome
//! and the dead-branch re-post (answers round 2 sections 5 and 8, round 3
//! sections 3 and 5, round 4 sections 8-10), against the in-process second
//! client. Self-consistency only: no Geb node is involved.

use super::*;
use crate::geb::crypto::line_id::line_id;
use crate::geb::status::{ChainEntry, RoomStatus};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

fn st(e: u64, a: &str, chain: Vec<ChainEntry>) -> RoomStatus {
    RoomStatus {
        e,
        a: a.into(),
        chain,
        lines: None,
        ls: None,
        cps: None,
    }
}

fn entry(e: u64, h: &str, a: &str) -> ChainEntry {
    ChainEntry {
        e,
        h: h.into(),
        a: a.into(),
    }
}

fn room_ref() -> RoomRef {
    RoomRef {
        id: ROOM.into(),
        name: None,
    }
}

/// Everything we sent to A since the last call.
fn sent(w: &World) -> Vec<Frame> {
    w.bus.take(&w.our_did, &w.a.did)
}

fn rs_of(frames: &[Frame]) -> Vec<RoomStatus> {
    frames
        .iter()
        .filter_map(|f| match f {
            Frame::Group(GroupOp::Rs { s: Some(s), .. }) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

fn seat_asks(frames: &[Frame]) -> Vec<Option<String>> {
    frames
        .iter()
        .filter_map(|f| match f {
            Frame::Group(GroupOp::SeatAsk { kp, .. }) => Some(kp.clone()),
            _ => None,
        })
        .collect()
}

/// A merges a self-update from the current epoch and we settle it from the
/// relay: A and we are one epoch on; B (not told) stays behind.
async fn a_commits_and_we_settle(w: &mut World) -> Vec<u8> {
    let c = w.a.stage_self_update();
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    let t = w.now() + 6_000;
    w.at(t);
    w.poll().await.unwrap();
    w.at(t + 3_000);
    w.poll().await.unwrap();
    assert_eq!(w.client.epoch(), Some(w.a.epoch()));
    c
}

#[tokio::test]
async fn rs_after_joining_names_epoch_and_authenticator_and_after_a_settle_the_chain() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat_raw().await;
    let joined = rs_of(&sent(&w));
    assert_eq!(joined.len(), 1, "one status after joining");
    let s = &joined[0];
    assert_eq!(s.e, w.a.epoch());
    assert_eq!(s.a, w.a.auth16(), "OpenMLS epoch authenticator, 16 hex");
    assert!(s.chain.is_empty(), "no Commit known from before our join");
    assert!(s.lines.is_none() && s.ls.is_none(), "no own lines held yet");

    let c = a_commits_and_we_settle(&mut w).await;
    let after = rs_of(&sent(&w));
    assert_eq!(after.len(), 1, "one status after the settle that merged");
    let s = &after[0];
    assert_eq!(s.e, w.a.epoch());
    assert_eq!(s.a, w.a.auth16());
    assert_eq!(
        s.chain,
        vec![entry(
            w.a.epoch(),
            &hex::encode(commit_hash(&c))[..16],
            &w.a.auth16()
        )],
        "e = the epoch the Commit MADE, h = winner hash, a = authenticator there"
    );
    // The frame on the wire has Geb's shape.
    let wire = serde_json::to_value(Frame::Group(GroupOp::Rs {
        room: Some(room_ref()),
        s: Some(s.clone()),
        via: None,
    }))
    .unwrap();
    assert_eq!(wire["op"], "rs");
    assert_eq!(wire["s"]["chain"][0]["h"].as_str().unwrap().len(), 16);

    // Own lines appear (and only ours) once we hold one.
    w.room
        .post(&text_event("hello", 1_700_000_000_000))
        .await
        .unwrap();
    let mine = w.client.room_status().unwrap();
    let l = mine.lines.unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[&w.our_did].n, 1);
    assert_eq!(l[&w.our_did].last, 1_700_000_000_000);
    assert!(mine.ls.is_some());
}

#[tokio::test]
async fn a_status_is_not_sent_to_the_newly_added_and_is_rate_limited_per_peer() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    // Unchanged state: the first goes, a repeat within 5 s does not, one after 5 s does.
    w.at(w.now() + 5_000);
    w.client.send_rs_to(&w.a.did, false).await;
    assert_eq!(rs_of(&sent(&w)).len(), 1);
    w.client.send_rs_to(&w.a.did, false).await;
    assert!(rs_of(&sent(&w)).is_empty(), "same state inside 5 s");
    w.at(w.now() + 5_000);
    w.client.send_rs_to(&w.a.did, false).await;
    assert_eq!(rs_of(&sent(&w)).len(), 1, "5 s later");
    // A changed epoch goes at once.
    a_commits_and_we_settle(&mut w).await;
    assert_eq!(rs_of(&sent(&w)).len(), 1);
}

#[tokio::test]
async fn unprompted_statuses_follow_start_and_are_bounded_by_the_minimum_interval() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.client.set_unprompted_statuses(true);
    w.seat_raw().await;
    assert_eq!(rs_of(&sent(&w)).len(), 1, "joining");
    let t0 = w.now();
    w.poll().await.unwrap(); // first pass: dyad comes up, start timer begins
    assert!(rs_of(&sent(&w)).is_empty(), "gated: sent a moment ago");
    w.at(t0 + 1_600);
    w.poll().await.unwrap();
    assert!(
        rs_of(&sent(&w)).is_empty(),
        "1.5 s send gated by the 5 s rule"
    );
    w.at(t0 + 8_100);
    w.poll().await.unwrap();
    assert_eq!(rs_of(&sent(&w)).len(), 1, "8 s send goes");
    w.at(t0 + 60_000);
    w.poll().await.unwrap();
    assert!(rs_of(&sent(&w)).is_empty(), "nothing more unprompted");
}

#[tokio::test]
async fn an_rs_with_no_valid_body_is_dropped_and_a_non_member_rs_is_dropped() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let t = w.now() + 6_000;
    w.at(t);
    // Wire level: no `s`, a bad `a`.
    for bad in [
        r#"{"k":"g","op":"rs","room":{"id":"geb-room-0001"}}"#,
        r#"{"k":"g","op":"rs","room":{"id":"geb-room-0001"},"s":{"e":1,"a":"zz","chain":[]}}"#,
    ] {
        let f = crate::geb::wire::parse_frame(bad.as_bytes()).unwrap();
        assert!(matches!(f, Frame::Group(GroupOp::Rs { s: None, .. })));
        w.bus.put(&w.a.did, &w.our_did, f);
    }
    w.poll().await.unwrap();
    assert!(sent(&w).is_empty(), "dropped: no answer, no fork");
    assert!(w.client.split().is_none());
    // A device that is not a member of the room.
    let stranger = Sim::new(90).did;
    w.client
        .on_rs(
            &stranger,
            Some(room_ref()),
            Some(st(w.client.epoch().unwrap() + 4, "aaaaaaaa", vec![])),
        )
        .await;
    assert!(sent(&w).is_empty());
    // Another room's status.
    w.client
        .on_rs(
            &w.a.did,
            Some(RoomRef {
                id: "other-room-9".into(),
                name: None,
            }),
            Some(st(1, "aaaaaaaa", vec![])),
        )
        .await;
    assert!(sent(&w).is_empty());
}

#[tokio::test]
async fn a_lagging_peer_gets_each_missing_commit_as_rc_then_our_status() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let old_epoch = w.a.epoch();
    let old_auth = w.a.auth16();
    let c = a_commits_and_we_settle(&mut w).await;
    sent(&w);
    // A says it is still at the old epoch.
    w.bus.put(
        &w.a.did,
        &w.our_did,
        Frame::Group(GroupOp::Rs {
            room: Some(room_ref()),
            s: Some(st(old_epoch, &old_auth, vec![])),
            via: None,
        }),
    );
    w.at(w.now() + 6_000);
    w.poll().await.unwrap();
    let out = sent(&w);
    let [
        Frame::Group(GroupOp::Rc { room, e, c: bytes }),
        Frame::Group(GroupOp::Rs { s: Some(s), .. }),
    ] = out.as_slice()
    else {
        panic!("rc then rs: {out:?}")
    };
    assert_eq!(room.id, ROOM);
    assert_eq!(*e, old_epoch, "e is the epoch the Commit was made FROM");
    assert_eq!(STANDARD.decode(bytes).unwrap(), c);
    assert_eq!(s.e, w.a.epoch());
}

#[tokio::test]
async fn rc_is_judged_at_once_for_our_epoch_held_for_later_and_dropped_below() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let e0 = w.a.epoch();
    // Two Commits in a row from A; neither is on the relay.
    let c1 = w.a.stage_self_update();
    w.a.merge_pending();
    let c2 = w.a.stage_self_update();
    w.a.merge_pending();
    let rc = |e: u64, c: &[u8]| {
        Frame::Group(GroupOp::Rc {
            room: room_ref(),
            e,
            c: STANDARD.encode(c),
        })
    };
    // The later one first: held, not tested; then ours: judged at once.
    w.bus.put(&w.a.did, &w.our_did, rc(e0 + 1, &c2));
    w.bus.put(&w.a.did, &w.our_did, rc(e0, &c1));
    w.at(w.now() + 6_000);
    w.poll().await.unwrap();
    assert_eq!(w.client.epoch(), Some(e0 + 2), "both applied, in order");
    assert!(w.our_keys_match(&w.a));
    // Below our epoch: dropped.
    w.bus.put(&w.a.did, &w.our_did, rc(e0, &c1));
    w.at(w.now() + 6_000);
    w.poll().await.unwrap();
    assert_eq!(w.client.held_commits(), 0);
    // An rc goes through validCommit: a Remove by a non-admin in a v2 room is
    // refused even when it arrives by rc, never merged around the check.
    let (mut w, mut _x) = (World::build(Arc::new(AllKnown), ""), 0);
    w.seat().await;
    let kp = Sim::new(31).key_package();
    let bad = w.b.stage_by_ref_add(kp).1; // a proposal by reference: failed
    w.bus.put(&w.a.did, &w.our_did, rc(w.b.epoch(), &bad));
    w.at(w.now() + 6_000);
    let before = w.client.epoch();
    w.poll().await.unwrap();
    assert_eq!(w.client.epoch(), before, "an invalid rc merges nothing");
    _x += 1;
}

/// Our client sits at A's branch; B forks at the same epoch.
async fn forked_world() -> (World, RoomStatus) {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    // B commits from the common epoch on its own (the fork); A's wins on us.
    let cb = w.b.stage_self_update();
    w.b.merge_pending();
    let _ = cb;
    a_commits_and_we_settle(&mut w).await;
    sent(&w);
    let b_status = st(
        w.b.epoch(),
        &w.b.auth16(),
        vec![entry(w.b.epoch(), "bbbbbbbbbbbbbbbb", &w.b.auth16())],
    );
    (w, b_status)
}

#[tokio::test]
async fn a_fork_at_the_same_epoch_is_decided_by_the_lower_authenticator() {
    let (w, b_status) = forked_world().await;
    let mine = w.a.auth16();
    w.client
        .on_rs(&w.b.did, Some(room_ref()), Some(b_status.clone()))
        .await;
    let split = w.client.split().expect("the split is recorded");
    assert_eq!(split.epoch, w.a.epoch());
    assert_eq!(split.reason, "hash");
    assert_eq!(split.we_won, mine < b_status.a);
    assert_eq!(
        split.asked, split.we_won,
        "the winner marks the loser asked"
    );
    // Whoever loses, we never ask to be re-seated from a fork and never commit.
    let out = sent(&w);
    assert!(
        seat_asks(&out).is_empty(),
        "a fork loser does not askReseat"
    );
    assert!(
        !out.iter()
            .any(|f| matches!(f, Frame::Group(GroupOp::Welcome { .. }))),
        "no healer duty"
    );
}

#[tokio::test]
async fn fork_verdicts_follow_forkminewins_rules_one_and_two() {
    // Rule 1: they are ahead and every other is ahead of me: I lose even
    // though the lower authenticator is mine.
    let (w, _) = forked_world().await;
    let e = w.client.epoch().unwrap();
    // A (an "other") is far ahead of us.
    w.client
        .on_rs(
            &w.a.did,
            Some(room_ref()),
            Some(st(e + 5, "1111111111111111", vec![])),
        )
        .await;
    let theirs = st(
        e + 3,
        "2222222222222222",
        vec![entry(e, "bbbbbbbbbbbbbbbb", "ffffffffffffffff")],
    );
    w.client
        .on_rs(&w.b.did, Some(room_ref()), Some(theirs))
        .await;
    let s = w.client.split().unwrap();
    assert_eq!((s.we_won, s.reason.as_str()), (false, "behind-all"));
    assert!(!s.asked);
    assert!(seat_asks(&sent(&w)).is_empty(), "the loser only waits");

    // Rule 2: they are behind me and every other is ahead of them: I win even
    // though the lower authenticator is theirs.
    let (mut w, _) = forked_world().await;
    a_commits_and_we_settle(&mut w).await; // chain now holds two epochs
    let e = w.client.epoch().unwrap();
    w.client
        .on_rs(
            &w.a.did,
            Some(room_ref()),
            Some(st(e + 5, "1111111111111111", vec![])),
        )
        .await;
    let theirs = st(
        e - 1,
        "0000000000000000",
        vec![entry(e - 1, "bbbbbbbbbbbbbbbb", "0000000000000000")],
    );
    w.client
        .on_rs(&w.b.did, Some(room_ref()), Some(theirs))
        .await;
    let s = w.client.split().unwrap();
    assert_eq!((s.we_won, s.reason.as_str()), (true, "they-behind-all"));
    assert!(
        s.asked,
        "the winner marks the loser asked for the elected healer"
    );
}

#[tokio::test]
async fn behind_re_reads_then_asks_to_be_reseated_once_with_no_kp_then_goes_quiet() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let e = w.client.epoch().unwrap();
    let ahead = Frame::Group(GroupOp::Rs {
        room: Some(room_ref()),
        s: Some(st(e + 2, "3333333333333333", vec![])),
        via: None,
    });
    let t0 = w.now() + 6_000;
    w.at(t0);
    w.bus.put(&w.a.did, &w.our_did, ahead.clone());
    let report = {
        w.poll().await.unwrap();
        // The re-read was taken by the poll; the answer went out.
        sent(&w)
    };
    assert_eq!(rs_of(&report).len(), 1, "our status again");
    assert!(
        seat_asks(&report).is_empty(),
        "not yet: first sight of the pair"
    );
    // The same pair, one settle window later (3000 ms): askReseat.
    w.at(t0 + 6_000);
    w.bus.put(&w.a.did, &w.our_did, ahead.clone());
    w.poll().await.unwrap();
    let out = sent(&w);
    assert_eq!(seat_asks(&out), vec![None], "seat-ask WITHOUT a kp");
    // Backed off: the same pair again does not ask a second time, and our rs
    // stays quiet for 600 s.
    w.at(t0 + 70_000);
    w.bus.put(&w.a.did, &w.our_did, ahead.clone());
    w.poll().await.unwrap();
    let out = sent(&w);
    assert!(
        seat_asks(&out).is_empty() && rs_of(&out).is_empty(),
        "{out:?}"
    );
    w.at(t0 + 700_000);
    w.client.send_rs_to(&w.a.did, false).await;
    assert_eq!(rs_of(&sent(&w)).len(), 1, "quiet only for 600 s");
}

#[tokio::test]
async fn behind_asks_a_re_read_from_the_start_of_retention() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let e = w.client.epoch().unwrap();
    w.client
        .on_rs(
            &w.a.did,
            Some(room_ref()),
            Some(st(e + 1, "4444444444444444", vec![])),
        )
        .await;
    let r = w.client.settle(w.now() + 6_000).await.unwrap();
    assert!(r.reread, "a behind verdict asks for a re-read");
    let r = w.client.settle(w.now() + 7_000).await.unwrap();
    assert!(!r.reread, "once");
}

#[tokio::test]
async fn a_seat_check_gets_a_body_rs_even_inside_the_quiet_time() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let e = w.client.epoch().unwrap();
    w.client
        .on_rs(
            &w.a.did,
            Some(room_ref()),
            Some(st(e + 2, "3333333333333333", vec![])),
        )
        .await;
    sent(&w);
    w.at(w.now() + 6_000);
    w.client
        .on_rs(
            &w.a.did,
            Some(room_ref()),
            Some(st(e + 2, "3333333333333333", vec![])),
        )
        .await;
    sent(&w); // askReseat fired: quiet now
    w.bus.put(
        &w.a.did,
        &w.our_did,
        Frame::Group(GroupOp::SeatCheck {
            room: room_ref(),
            e: 1,
        }),
    );
    w.at(w.now() + 6_000);
    w.poll().await.unwrap();
    assert_eq!(rs_of(&sent(&w)).len(), 1);
}

// ---- re-seat -------------------------------------------------------------

/// Seat, post a line of ours, and have A stage a re-seat of us from our next
/// stock package. Returns (our line text, at, commit, welcome frame).
async fn reseat_setup(w: &mut World) -> (u64, Vec<u8>, Frame) {
    let kps = w.seat_raw().await;
    sent(w);
    let at = 1_700_000_000_000;
    w.room.post(&text_event("mine-1", at)).await.unwrap();
    let (commit, welcome) = w.a.stage_reseat_full(&w.our_did.clone(), parse_kp(&kps[1]));
    let frame = welcome_frame(ROOM, &w.a.did, &w.policy, &welcome);
    (at, commit, frame)
}

#[tokio::test]
async fn a_reseat_welcome_replaces_the_group_and_our_dead_branch_lines_are_reposted() {
    let mut w = World::build(Arc::new(AllKnown), "");
    let (at, _commit, welcome) = reseat_setup(&mut w).await;
    let old_epoch = w.client.epoch().unwrap();
    w.a.merge_pending();
    w.bus.put(&w.a.did, &w.our_did, welcome);
    w.at(w.now() + 6_000);
    let got = w.poll().await.unwrap();
    assert_eq!(w.client.reseats(), 1);
    assert_eq!(w.client.epoch(), Some(w.a.epoch()));
    assert!(w.a.epoch() > old_epoch);
    assert!(
        w.our_keys_match(&w.a),
        "relay keys re-derived from the new group"
    );
    let s = w.client.room_status().unwrap();
    assert!(
        s.chain.is_empty(),
        "the chain restarts at the Welcome's epoch"
    );
    assert_eq!(s.a, w.a.auth16());
    assert!(
        rs_of(&sent(&w)).iter().any(|s| s.e == w.a.epoch()),
        "a status after the re-seat"
    );
    // Our own line from the dead branch was re-posted: original id and `at`,
    // fk:1, readable by A under the new epoch.
    let events = w
        .relay
        .fetch(KIND_MAILBOX, &w.a.keys(ROOM).pubkey_hex().unwrap(), None)
        .await
        .unwrap();
    let mut found = Vec::new();
    for ev in events {
        let k = w.a.keys(ROOM);
        let Ok(b) = pair::open(&k, KIND_MAILBOX, &ev.content) else {
            continue;
        };
        if let Ok(Envelope::Ml { m }) = serde_json::from_slice(&b) {
            let raw = crate::geb::crypto::b64_decode(&m).unwrap();
            if let Some((who, line)) = w.a.open_line(&raw)
                && who == w.our_did
            {
                found.push(line);
            }
        }
    }
    assert_eq!(found.len(), 1, "exactly one re-post");
    let l = &found[0];
    assert_eq!((l.at, l.text.as_str()), (at, "mine-1"));
    assert_eq!(l.fk, Some(serde_json::json!(1)));
    assert_eq!(
        l.id.as_deref(),
        Some(line_id(ROOM, &w.our_did, at, "mine-1").unwrap().as_str())
    );
    assert!(l.sg.is_some(), "signed afresh");
    // Own-author skip: the bridge does not take its own re-post as a new line.
    assert!(
        got.iter().all(|p| p.event.text != "mine-1"),
        "a re-post is never re-bridged"
    );
    // And a later poll does not post it twice.
    w.at(w.now() + 6_000);
    w.poll().await.unwrap();
    assert!(w.client.pending_reposts_for_test().is_empty());
}

#[tokio::test]
async fn the_reseat_commit_alone_waits_for_its_welcome_and_asks_with_a_kp_after_120_s() {
    let mut w = World::build(Arc::new(AllKnown), "");
    let (_at, commit, welcome) = reseat_setup(&mut w).await;
    w.post_mc(&w.a, &commit).await;
    w.a.merge_pending();
    let t = w.now() + 6_000;
    w.at(t);
    w.poll().await.unwrap();
    w.at(t + 3_000);
    w.poll().await.expect("a re-seat is not a removal: no halt");
    assert!(w.client.is_reseating());
    sent(&w);
    // Nothing is read meanwhile, and nothing breaks.
    w.at(t + 30_000);
    assert!(w.poll().await.unwrap().is_empty());
    assert!(seat_asks(&sent(&w)).is_empty());
    w.at(t + 130_000);
    w.poll().await.unwrap();
    let asks = seat_asks(&sent(&w));
    assert_eq!(asks.len(), 1);
    let kp = asks[0].clone().expect("a fresh bound package");
    assert_eq!(
        binding_status(parse_kp(&kp).leaf_node()),
        BindingStatus::Verified
    );
    // The Welcome arrives: seated again.
    w.bus.put(&w.a.did, &w.our_did, welcome);
    w.at(t + 140_000);
    w.poll().await.unwrap();
    assert!(!w.client.is_reseating());
    assert_eq!(w.client.epoch(), Some(w.a.epoch()));
    assert!(w.our_keys_match(&w.a));
}

#[tokio::test]
async fn a_welcome_that_is_not_a_reseat_of_us_is_ignored_and_the_old_group_stays() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let e = w.client.epoch();
    // A Welcome for a package of someone else's: we hold no key for it.
    let x = Sim::new(40);
    let (_c, welcome) = w.a.stage_add(x.key_package());
    w.a.drop_pending();
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
    );
    w.at(w.now() + 6_000);
    w.poll().await.unwrap();
    assert_eq!(w.client.epoch(), e);
    assert_eq!(w.client.reseats(), 0);
    assert!(w.our_keys_match(&w.a));
    // From a device that is not a member of our group: ignored before opening.
    let stranger = Sim::new(91).did;
    let kps = {
        let k = w.client.relay_keys().unwrap();
        let _ = k;
        Vec::<String>::new()
    };
    let _ = kps;
    w.client
        .on_reseat_welcome(
            &stranger,
            &match welcome_frame(ROOM, &w.a.did, &w.policy, &welcome) {
                Frame::Group(GroupOp::Welcome { room, .. }) => room,
                _ => unreachable!(),
            },
            &crate::geb::crypto::b64_encode(&welcome),
        )
        .await;
    assert_eq!(w.client.reseats(), 0);
}

#[tokio::test]
async fn a_welcome_for_a_package_we_no_longer_hold_is_answered_with_a_bound_seat_ask() {
    let mut w = World::build(Arc::new(AllKnown), "");
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    sent(&w);
    let x = Sim::new(41);
    let (_c, welcome) = w.a.stage_add(x.key_package());
    w.a.drop_pending();
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
    );
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    let asks = seat_asks(&sent(&w));
    assert_eq!(asks.len(), 1);
    let kp = asks[0].clone().expect("with a fresh bound KeyPackage");
    assert!(crate::geb::wire::is_std_b64(&kp));
    assert_eq!(
        binding_status(parse_kp(&kp).leaf_node()),
        BindingStatus::Verified
    );
    // Backed off: asking again at once sends nothing more.
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
    );
    w.room.join().await.unwrap();
    assert!(seat_asks(&sent(&w)).is_empty());
}

#[tokio::test]
async fn a_missing_local_copy_asks_for_a_reseat_with_a_bound_kp() {
    let mut w = World::build(Arc::new(AllKnown), "");
    let store = Arc::new(MemState::default());
    let vault = MemoryVault::default();
    let (c1, room1) = restarted(&w, store.clone(), &vault);
    assert_eq!(room1.join().await.unwrap(), JoinState::Pending);
    let stock = w.bus.take(&w.our_did, &w.a.did);
    let Some(Frame::Group(GroupOp::KpStock { kps, .. })) = stock.first().cloned() else {
        panic!("no kp-stock")
    };
    let (commit, welcome) = w.a.stage_add(parse_kp(&kps[0]));
    w.a.merge_pending();
    w.b.apply(&commit).unwrap();
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
    );
    assert_eq!(room1.join().await.unwrap(), JoinState::Seated);
    drop((c1, room1));
    // The snapshot survives but the group inside it is gone (evicted).
    let mut snap: serde_json::Value =
        serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
    snap["values"] = serde_json::json!([]);
    store.save(&serde_json::to_vec(&snap).unwrap()).unwrap();
    let (_c2, room2) = restarted(&w, store.clone(), &vault);
    w.bus.take(&w.our_did, &w.a.did);
    assert_eq!(room2.join().await.unwrap(), JoinState::Pending);
    let asks = seat_asks(&sent(&w));
    assert_eq!(asks.len(), 1);
    assert!(asks[0].is_some(), "a bound KeyPackage, never none");
}

#[tokio::test]
async fn the_chain_survives_a_restart_and_an_older_snapshot_loads_with_an_empty_one() {
    let mut w = World::build(Arc::new(AllKnown), "");
    let store = Arc::new(MemState::default());
    let vault = MemoryVault::default();
    let (c1, room1) = restarted(&w, store.clone(), &vault);
    assert_eq!(room1.join().await.unwrap(), JoinState::Pending);
    let stock = w.bus.take(&w.our_did, &w.a.did);
    let Some(Frame::Group(GroupOp::KpStock { kps, .. })) = stock.first().cloned() else {
        panic!("no kp-stock")
    };
    let (commit, welcome) = w.a.stage_add(parse_kp(&kps[0]));
    w.a.merge_pending();
    w.b.apply(&commit).unwrap();
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
    );
    assert_eq!(room1.join().await.unwrap(), JoinState::Seated);
    let c = w.a.stage_self_update();
    post(
        &w.relay_dyn,
        &w.a.keys(ROOM),
        &mc(w.a.epoch(), &c),
        w.secs(),
    )
    .await;
    w.a.merge_pending();
    room1.poll(None).await.unwrap();
    w.at(w.now() + 3_000);
    room1.poll(None).await.unwrap();
    assert_eq!(c1.room_status().unwrap().chain.len(), 1);
    drop((c1, room1));
    let (c2, _r2) = restarted(&w, store.clone(), &vault);
    let s = c2.room_status().unwrap();
    assert_eq!(s.chain.len(), 1);
    assert_eq!(s.chain[0].a, w.a.auth16());
    // An older snapshot has no `heal` at all: empty chain, still seated.
    drop((c2, _r2));
    let mut snap: serde_json::Value =
        serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
    snap.as_object_mut().unwrap().remove("heal");
    store.save(&serde_json::to_vec(&snap).unwrap()).unwrap();
    let (c3, _r3) = restarted(&w, store.clone(), &vault);
    assert!(c3.room_status().unwrap().chain.is_empty());
}

#[tokio::test]
async fn a_reposted_line_we_already_bridged_is_not_bridged_twice_and_an_unseen_one_is_once() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let at = 1_700_000_000_500;
    let original = w.a.seal_line(ROOM, at, "from A", true);
    w.post_ml(&w.a, &original).await;
    let got = w.poll().await.unwrap();
    assert_eq!(got.iter().filter(|p| p.event.text == "from A").count(), 1);
    let id = line_id(ROOM, &w.a.did, at, "from A").unwrap();
    let again = w.a.seal_repost(ROOM, at, "from A", &id);
    w.post_ml(&w.a, &again).await;
    let got = w.poll().await.unwrap();
    assert!(got.iter().all(|p| p.event.text != "from A"), "dedup by id");
    // A line we never saw, re-posted: bridged once.
    let id2 = line_id(ROOM, &w.a.did, at + 1, "lost line").unwrap();
    let lost = w.a.seal_repost(ROOM, at + 1, "lost line", &id2);
    w.post_ml(&w.a, &lost).await;
    let got = w.poll().await.unwrap();
    assert_eq!(
        got.iter().filter(|p| p.event.text == "lost line").count(),
        1
    );
}

#[tokio::test]
async fn own_lines_are_kept_bounded_to_100() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    for i in 0..105u64 {
        w.room
            .post(&text_event(&format!("line {i}"), 1_700_000_000_000 + i))
            .await
            .unwrap();
    }
    let s = w.client.room_status().unwrap();
    assert_eq!(s.lines.unwrap()[&w.our_did].n, 100);
}

// ---- the non-secret fork marker `status` reads (geb::forkmark) ----------------

#[tokio::test]
async fn a_recorded_split_is_mirrored_in_the_unsealed_marker() {
    use crate::geb::forkmark::{self, ForkState};
    let (w, b_status) = forked_world().await;
    assert_eq!(
        forkmark::read(&*w.marks).await.unwrap(),
        None,
        "no split yet"
    );
    w.client
        .on_rs(&w.b.did, Some(room_ref()), Some(b_status.clone()))
        .await;
    let split = w.client.split().expect("the split is recorded");
    let m = forkmark::read(&*w.marks).await.unwrap().expect("a marker");
    assert_eq!(m.link, "l1");
    assert_eq!(m.fork_epoch, split.epoch);
    assert_eq!((m.our_epoch, m.their_epoch), (split.our_epoch, b_status.e));
    assert_eq!(m.detected_at_ms, split.at_ms);
    assert_eq!(m.reseated_at_ms, None);
    assert_eq!(
        m.state,
        if split.we_won {
            ForkState::BranchWon
        } else {
            ForkState::WaitingForReseat
        }
    );
    // The same status again changes nothing.
    w.client
        .on_rs(&w.b.did, Some(room_ref()), Some(b_status))
        .await;
    assert_eq!(forkmark::read(&*w.marks).await.unwrap(), Some(m));
}

#[tokio::test]
async fn accepting_a_reseat_welcome_marks_the_split_reseated() {
    use crate::geb::forkmark::{self, ForkState};
    let mut w = World::build(Arc::new(AllKnown), "");
    let kps = w.seat_raw().await;
    sent(&w);
    // The fork, as in `forked_world`: B commits alone from the common epoch.
    let _ = w.b.stage_self_update();
    w.b.merge_pending();
    a_commits_and_we_settle(&mut w).await;
    sent(&w);
    let b_status = st(
        w.b.epoch(),
        &w.b.auth16(),
        vec![entry(w.b.epoch(), "bbbbbbbbbbbbbbbb", &w.b.auth16())],
    );
    w.client
        .on_rs(&w.b.did, Some(room_ref()), Some(b_status))
        .await;
    let before = forkmark::read(&*w.marks).await.unwrap().expect("marker");
    assert_ne!(before.state, ForkState::Reseated);
    // The healer re-seats us; the Welcome is accepted.
    let (_commit, welcome) = w.a.stage_reseat_full(&w.our_did.clone(), parse_kp(&kps[1]));
    let frame = welcome_frame(ROOM, &w.a.did, &w.policy, &welcome);
    w.a.merge_pending();
    w.bus.put(&w.a.did, &w.our_did, frame);
    w.at(w.now() + 6_000);
    w.poll().await.unwrap();
    assert_eq!(w.client.reseats(), 1);
    let after = forkmark::read(&*w.marks).await.unwrap().expect("marker");
    assert_eq!(after.state, ForkState::Reseated);
    assert!(after.reseated_at_ms.is_some());
    assert_eq!(
        (
            after.fork_epoch,
            after.our_epoch,
            after.their_epoch,
            after.detected_at_ms
        ),
        (
            before.fork_epoch,
            before.our_epoch,
            before.their_epoch,
            before.detected_at_ms
        ),
        "the detection facts are kept"
    );
}
