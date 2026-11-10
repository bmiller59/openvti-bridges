//! Pure mapping between VTC records, [`BridgeEvent`]s and what a foreign room
//! accepts. No I/O and no foreign-system types: behaviour that depends on the
//! room comes from [`RoomCapabilities`] only.

use crate::foreign::{RoomCapabilities, SizeUnit};
use crate::model::{AuthorCheck, BridgeEvent, EventKind, Origin};
use crate::room::{PROVENANCE_OPEN, RecordWrite, RoomRecord};
use crate::{Error, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::HashMap;

/// Largest foreign text kept when writing a record to the VTC room (bytes): a
/// bound the core puts on a record body, however the foreign room counts. It is
/// above any message limit an adapter declares in characters or code units
/// today, so an honest line is not cut. An adapter that needed more would add
/// a capability for it; none does.
pub const MAX_INBOUND_TEXT_BYTES: usize = 80_000;
const TRUNCATION_MARK: &str = "\n[truncated]";
const MAX_AUTHOR_CHARS: usize = 200;

/// Whether `c` is a Unicode format character (general category Cf): bidi
/// controls and isolates, zero-width space / joiner / non-joiner, word joiner,
/// BOM, soft hyphen, the interlinear annotation marks and the tag characters.
/// None renders, several reorder or hide neighbouring text. Written out
/// because the standard library has no general-category lookup; the list is
/// the Cf set of Unicode 15.
fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2
        | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Make an author label safe to put in a one-line header: no control or
/// format characters (a bidi override in a DID-like label would reorder the
/// header), no line breaks.
pub fn sanitize_label(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control() && !is_format_char(*c) && !matches!(*c, '\u{2028}' | '\u{2029}')
        })
        .take(MAX_AUTHOR_CHARS)
        .collect()
}

/// Clean untrusted text from either side. Every line break is normalised to
/// `\n` (CRLF, a bare CR, NEL, vertical tab, form feed, U+2028 and U+2029 all
/// start a new line, so none can hide a line start from the quoting that
/// follows), then control characters other than newline and tab and every
/// Unicode format character (Cf: bidi overrides and isolates, zero-width
/// space and joiners, BOM, ...) are removed. Stripping the joiner U+200D
/// splits joined emoji sequences into their parts; that cost is accepted.
pub fn strip_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\u{85}' | '\u{b}' | '\u{c}' | '\u{2028}' | '\u{2029}' => out.push('\n'),
            '\n' | '\t' => out.push(c),
            c if c.is_control() || is_format_char(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Quote every line with `> `, as email does, so no line of untrusted text can
/// pass for the bridge's own unquoted header. An empty line becomes `>`.
fn quote_lines(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8 + 2);
    for (i, line) in s.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push('>');
        if !line.is_empty() {
            out.push(' ');
            out.push_str(line);
        }
    }
    out
}

/// Length of `s` in UTF-16 code units (a JavaScript string's `length`): a
/// character outside the BMP counts 2.
pub fn utf16_units(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// Length of `s` in `unit`s.
pub fn measure(unit: SizeUnit, s: &str) -> usize {
    match unit {
        SizeUnit::Utf16 => utf16_units(s),
        SizeUnit::Chars => s.chars().count(),
        SizeUnit::Bytes => s.len(),
    }
}

/// Cut `s` to at most `max` `unit`s, on a char boundary (a surrogate pair is
/// never split), marking the cut inside the limit. Returns `s` unchanged when
/// it already fits. The result is never longer than `max`: when `max` is
/// shorter than the marker the text is cut without one.
pub fn truncate(unit: SizeUnit, s: &str, max: usize) -> String {
    match unit {
        SizeUnit::Utf16 => truncate_utf16(s, max),
        SizeUnit::Chars => truncate_weighted(s, max, |_| 1),
        SizeUnit::Bytes => truncate_bytes(s, max),
    }
}

/// Cut `s` to at most `max` UTF-16 code units (the [`SizeUnit::Utf16`] arm of
/// [`truncate`]), on a char boundary, marking the cut inside the limit.
pub fn truncate_utf16(s: &str, max: usize) -> String {
    truncate_weighted(s, max, char::len_utf16)
}

/// The cut shared by the character-counting units: `weight(c)` is what `c`
/// counts for.
fn truncate_weighted(s: &str, max: usize, weight: fn(char) -> usize) -> String {
    let total: usize = s.chars().map(weight).sum();
    if total <= max {
        return s.to_string();
    }
    let mark: usize = TRUNCATION_MARK.chars().map(weight).sum();
    let (budget, with_mark) = if max >= mark {
        (max - mark, true)
    } else {
        (max, false)
    };
    let mut units = 0;
    let mut end = 0;
    for (i, c) in s.char_indices() {
        let n = weight(c);
        if units + n > budget {
            break;
        }
        units += n;
        end = i + c.len_utf8();
    }
    let mut out = s[..end].to_string();
    if with_mark {
        out.push_str(TRUNCATION_MARK);
    }
    out
}

/// Cut `s` to at most `max` bytes on a char boundary, marking the cut inside
/// the limit. Returns `s` unchanged when it already fits.
pub fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let room = max.saturating_sub(TRUNCATION_MARK.len());
    let mut end = room.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    if max >= TRUNCATION_MARK.len() {
        out.push_str(TRUNCATION_MARK);
    }
    out
}

/// The stable id of a record's event on the VTC side: `key|version` for
/// content, `key|version|retract` for a tombstone.
pub fn origin_id_for(rec: &RoomRecord) -> String {
    if rec.retracted {
        format!("{}|{}|retract", rec.key, rec.version)
    } else {
        format!("{}|{}", rec.key, rec.version)
    }
}

/// A record as an outbound event, or `None` when it must not cross: the
/// bridge's own writes (echo suppression), records a bridge wrote
/// (provenance marker), records already cross-referenced and a tombstone of a
/// key that was never bridged.
///
/// `prior` is the `origin_id` of the newest version of this record's KEY that
/// was bridged before, if any. That, and only that, decides what the record
/// is: the host's `version` is the room-wide arrival order, not a per-key
/// counter, so `version > 1` says nothing about an edit. A key bridged before
/// makes a content record a [`EventKind::Supersede`] of `prior` and a
/// tombstone an [`EventKind::Retract`] of it; a key never bridged makes a
/// content record a plain [`EventKind::Post`] (whatever its version) and a
/// tombstone nothing.
pub fn record_to_event(
    rec: &RoomRecord,
    link: &str,
    persona: &str,
    already_bridged: impl Fn(&str) -> bool,
    prior: Option<&str>,
) -> Option<BridgeEvent> {
    if rec.author == persona || rec.is_bridged() {
        return None;
    }
    let origin_id = origin_id_for(rec);
    let (kind, record_key) = if rec.retracted {
        let target = prior?;
        (
            EventKind::Retract {
                target: target.to_string(),
            },
            None,
        )
    } else {
        let kind = match prior {
            Some(p) => EventKind::Supersede {
                replaces: p.to_string(),
            },
            None => EventKind::Post,
        };
        (kind, Some(rec.key.clone()))
    };
    if already_bridged(&origin_id) {
        return None;
    }
    Some(BridgeEvent {
        origin: Origin::Vtc,
        origin_id,
        link: link.into(),
        author: if rec.retracted && rec.author.is_empty() {
            "a room member".into()
        } else {
            rec.author.clone()
        },
        at: rec.at,
        title: rec.title.clone(),
        text: rec.body.clone(),
        kind,
        reply_to: None,
        record_key,
        provenance: None,
    })
}

/// Wording of the notice lines that stand in for an edit or a retraction the
/// foreign room cannot express natively. `{target}` is replaced by the
/// original post's id on the VTC side.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Notices {
    /// For a new version of an earlier post.
    pub update: String,
    /// For a retraction.
    pub retract: String,
}

impl Default for Notices {
    fn default() -> Self {
        Self {
            update: "[update to earlier post {target}]".into(),
            retract: "[retracted: earlier post {target}]".into(),
        }
    }
}

impl Notices {
    /// Reject wording that could not be sent safely.
    pub fn validate(&self) -> Result<()> {
        for (name, t) in [("update", &self.update), ("retract", &self.retract)] {
            if t.is_empty() || t.chars().count() > 200 || t.chars().any(char::is_control) {
                return Err(Error::Config(format!(
                    "notice {name}: 1-200 characters, no control characters"
                )));
            }
        }
        Ok(())
    }

    fn render(template: &str, target: &str) -> String {
        template.replace("{target}", &sanitize_label(target))
    }
}

/// Shape an event for a room with the given capabilities: choose how a
/// supersede or retraction is expressed, add the quoted author header and fit
/// the size limit. The result is a `Post`, unless the room can express the
/// kind natively.
///
/// A retraction (and a supersede where editing is unsupported) becomes an
/// ordinary line carrying the notice. When the room supports replies and
/// `resolve` knows the foreign id of the original (the xref stores it for each
/// bridged record), the line also answers that original via `reply_to`. It is
/// never a new message kind, and never dropped.
pub fn prepare_outbound(
    ev: &BridgeEvent,
    caps: &RoomCapabilities,
    notices: &Notices,
    resolve: impl Fn(&str) -> Option<String>,
) -> BridgeEvent {
    let author = sanitize_label(&ev.author);
    let mut body = String::new();
    let mut kind = ev.kind.clone();
    let mut reply_to = ev.reply_to.clone();
    let mut flatten = |template: &str, original: &str| {
        body.push_str(&Notices::render(template, original));
        body.push('\n');
        if caps.supports_replies {
            reply_to = resolve(original).or(reply_to.take());
        }
        kind = EventKind::Post;
    };
    match &ev.kind {
        EventKind::Post => {}
        EventKind::Supersede { replaces } => {
            if !caps.supports_edit {
                flatten(&notices.update, replaces);
            }
        }
        EventKind::Retract { target } => {
            if !caps.supports_delete {
                flatten(&notices.retract, target);
            }
        }
    }
    if let Some(t) = ev.title.as_deref().filter(|t| !t.is_empty()) {
        body.push_str(&strip_controls(t));
        body.push_str("\n\n");
    }
    body.push_str(&strip_controls(&ev.text));
    // The one unquoted line is the header; everything the VTC member wrote
    // (title, text, notices) is quoted line by line. The size limit applies to
    // the transformed text, quote prefixes included.
    let text = truncate(
        caps.size_limit.unit,
        &format!(
            "{author} wrote:\n{}",
            quote_lines(body.trim_end_matches('\n'))
        ),
        caps.size_limit.max,
    );
    BridgeEvent {
        title: None,
        text,
        kind,
        reply_to,
        ..ev.clone()
    }
}

/// SHA-256 of the foreign message bytes, hex: the dedup id.
pub fn msg_hash(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(Sha256::digest(bytes))
}

/// Deterministic opaque record key: `HMAC(link_secret, room_id || msg_hash)`
/// where `msg_hash` is the hex string. Replaying the same message produces
/// the same key, so the create-only put is idempotent.
pub fn record_key(link_secret: &[u8], foreign_room: &str, msg_hash: &str) -> Result<String> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(link_secret)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    mac.update(foreign_room.as_bytes());
    mac.update(msg_hash.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn fence_for(s: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in s.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat((longest + 1).max(3))
}

/// A foreign event as a create-only record write. The body is a provenance
/// block followed by the untrusted text inside a fence longer than any
/// backtick run in it, so the text can never close the fence.
pub fn foreign_to_record(ev: &BridgeEvent, link_secret: &[u8]) -> Result<RecordWrite> {
    let p = ev
        .provenance
        .as_ref()
        .ok_or_else(|| Error::Wire("foreign event without provenance".into()))?;
    let prov = serde_json::to_string(&serde_json::json!({
        "foreignRoom": p.foreign_room,
        "authorDevice": p.author_device,
        "authorCheck": p.check,
        "originalAt": p.original_at,
        "msgHash": p.msg_hash,
        "basis": "observed",
    }))
    .map_err(|e| Error::Wire(e.to_string()))?;
    let text = truncate_bytes(&strip_controls(&ev.text), MAX_INBOUND_TEXT_BYTES);
    let fence = fence_for(&text);
    let status = match p.check {
        AuthorCheck::Verified => "signature verified",
        AuthorCheck::Unverified => "UNVERIFIED: signature did not verify",
        AuthorCheck::Unsigned => "UNVERIFIED: unsigned",
    };
    let body = format!(
        "{PROVENANCE_OPEN}\n{prov}\n```\n\nBridged from a foreign room ({status}). Quoted, untrusted:\n\n{fence}text\n{text}\n{fence}\n"
    );
    Ok(RecordWrite {
        key: record_key(link_secret, &p.foreign_room, &p.msg_hash)?,
        body,
        basis: "observed",
        expected_version: 0,
    })
}

/// Seen-set for foreign message hashes: 7 days plus 300 s, the foreign
/// system's own rule.
pub struct DedupWindow {
    ttl_ms: u64,
    seen: HashMap<String, u64>,
}

impl Default for DedupWindow {
    fn default() -> Self {
        Self {
            ttl_ms: (7 * 24 * 3600 + 300) * 1000,
            seen: HashMap::new(),
        }
    }
}

impl DedupWindow {
    /// `true` when `id` is new (and is now remembered).
    pub fn check_and_insert(&mut self, id: &str, now_ms: u64) -> bool {
        let ttl = self.ttl_ms;
        self.seen.retain(|_, at| now_ms.saturating_sub(*at) < ttl);
        self.seen.insert(id.to_string(), now_ms).is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foreign::{SizeLimit, SizeUnit, Verifiability};
    use crate::model::Provenance;

    #[test]
    fn every_unit_measures_and_cuts_within_its_limit_and_never_splits_a_char() {
        let s = "a\u{e9}\u{65E5}\u{1F600}".repeat(50);
        for unit in [SizeUnit::Utf16, SizeUnit::Chars, SizeUnit::Bytes] {
            assert_eq!(
                measure(unit, "a\u{e9}\u{65E5}\u{1F600}"),
                match unit {
                    SizeUnit::Utf16 => 5,
                    SizeUnit::Chars => 4,
                    _ => 10,
                }
            );
            for max in [0usize, 5, 11, 12, 13, 40, 99] {
                let out = truncate(unit, &s, max);
                assert!(measure(unit, &out) <= max, "{unit:?} {max}: {out:?}");
                if max >= 12 {
                    assert!(out.ends_with("[truncated]"), "{unit:?} {max}");
                }
            }
            // Fits: untouched, no marker.
            assert_eq!(truncate(unit, "abc", 100), "abc");
        }
        // The units differ: the same text is cut at different places.
        let cut_chars = truncate(SizeUnit::Chars, &s, 20);
        let cut_bytes = truncate(SizeUnit::Bytes, &s, 20);
        assert_eq!(measure(SizeUnit::Chars, &cut_chars), 20);
        assert!(cut_bytes.len() <= 20 && cut_bytes != cut_chars);
    }

    fn caps(edit: bool, del: bool, max: usize) -> RoomCapabilities {
        RoomCapabilities {
            size_limit: SizeLimit::new(SizeUnit::Utf16, max),
            supports_edit: edit,
            supports_delete: del,
            supports_replies: false,
            authors_verifiable: Verifiability::PerMessage,
        }
    }

    fn rec(author: &str, body: &str, version: u64) -> RoomRecord {
        RoomRecord {
            key: "k".into(),
            version,
            author: author.into(),
            title: Some("T".into()),
            body: body.into(),
            at: 5,
            retracted: false,
        }
    }

    #[test]
    fn echo_suppression() {
        let none = |_: &str| false;
        assert!(record_to_event(&rec("did:a", "hi", 1), "l", "did:p", none, None).is_some());
        // The bridge's own persona.
        assert!(record_to_event(&rec("did:p", "hi", 1), "l", "did:p", none, None).is_none());
        // A record a bridge wrote.
        let bridged = format!("{PROVENANCE_OPEN}\n{{}}\n```\n");
        assert!(record_to_event(&rec("did:a", &bridged, 1), "l", "did:p", none, None).is_none());
        // Already cross-referenced.
        assert!(
            record_to_event(&rec("did:a", "hi", 1), "l", "did:p", |id| id == "k|1", None).is_none()
        );
    }

    #[test]
    fn a_key_bridged_before_is_a_supersede_and_the_version_is_irrelevant() {
        let e =
            record_to_event(&rec("did:a", "v2", 2), "l", "did:p", |_| false, Some("k|1")).unwrap();
        assert_eq!(
            e.kind,
            EventKind::Supersede {
                replaces: "k|1".into()
            }
        );
        assert_eq!(e.record_key.as_deref(), Some("k"));
        // Room-wide arrival order: the edit may sit at version 40 and the
        // earlier post at 3.
        let e = record_to_event(
            &rec("did:a", "v2", 40),
            "l",
            "did:p",
            |_| false,
            Some("k|3"),
        )
        .unwrap();
        assert_eq!(
            e.kind,
            EventKind::Supersede {
                replaces: "k|3".into()
            }
        );
    }

    #[test]
    fn a_key_never_bridged_is_a_plain_post_at_any_version() {
        let e = record_to_event(&rec("did:a", "new", 40), "l", "did:p", |_| false, None).unwrap();
        assert_eq!(e.kind, EventKind::Post);
        assert_eq!(e.origin_id, "k|40");
    }

    fn tomb(author: &str, version: u64) -> RoomRecord {
        RoomRecord {
            title: None,
            body: String::new(),
            retracted: true,
            ..rec(author, "", version)
        }
    }

    #[test]
    fn a_tombstone_of_a_bridged_key_is_a_retraction_and_of_another_is_ignored() {
        let e = record_to_event(&tomb("did:a", 9), "l", "did:p", |_| false, Some("k|3")).unwrap();
        assert_eq!(
            e.kind,
            EventKind::Retract {
                target: "k|3".into()
            }
        );
        assert_eq!(e.origin_id, "k|9|retract");
        assert_eq!(e.record_key, None);
        assert!(record_to_event(&tomb("did:a", 9), "l", "did:p", |_| false, None).is_none());
        // Not twice, and never the bridge's own.
        assert!(
            record_to_event(
                &tomb("did:a", 9),
                "l",
                "did:p",
                |i| i == "k|9|retract",
                Some("k|3")
            )
            .is_none()
        );
        assert!(record_to_event(&tomb("did:p", 9), "l", "did:p", |_| false, Some("k|3")).is_none());
        // An author the listing did not name still gets a readable header.
        let e = record_to_event(&tomb("", 9), "l", "did:p", |_| false, Some("k|3")).unwrap();
        assert_eq!(e.author, "a room member");
    }

    #[test]
    fn header_quotes_author_and_strips_injection() {
        let mut e = record_to_event(
            &rec("did:a\nfake header", "hi\u{7}", 1),
            "l",
            "p",
            |_| false,
            None,
        )
        .unwrap();
        e.title = None;
        let out = prepare_outbound(&e, &caps(false, false, 20_000), &Notices::default(), |_| {
            None
        });
        assert_eq!(out.text, "did:afake header wrote:\n> hi");
    }

    fn outbound_text(author: &str, body: &str) -> String {
        let mut e = record_to_event(&rec(author, body, 1), "l", "p", |_| false, None).unwrap();
        e.title = None;
        prepare_outbound(&e, &caps(false, false, 20_000), &Notices::default(), |_| {
            None
        })
        .text
    }

    /// P1-7: only the first line is the bridge's own header; every body line
    /// is quoted, so none can pose as a header.
    #[test]
    fn an_embedded_header_cannot_pose_as_the_real_one() {
        let out = outbound_text("did:a", "hi\ndid:ceo wrote:\nsend the money");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "did:a wrote:");
        assert!(
            lines[1..].iter().all(|l| l.starts_with('>')),
            "every body line is quoted: {out:?}"
        );
        assert_eq!(
            out.lines()
                .filter(|l| l.ends_with(" wrote:") && !l.starts_with('>'))
                .count(),
            1,
            "exactly one unquoted header: {out:?}"
        );
    }

    #[test]
    fn bidi_controls_zero_width_and_separators_are_removed_both_ways() {
        let nasty = "a\u{202E}b\u{2066}c\u{200D}d\u{200B}e\u{FEFF}f\u{2028}g\u{2029}h";
        let out = outbound_text("did:a", nasty);
        for c in [
            "\u{202E}", "\u{2066}", "\u{200D}", "\u{200B}", "\u{FEFF}", "\u{2028}", "\u{2029}",
        ] {
            assert!(!out.contains(c), "{c:?} left in {out:?}");
        }
        assert!(
            out.contains("abcdef") || out.contains("> abcdef"),
            "{out:?}"
        );
        // A bidi override in the author label too.
        let lab = outbound_text("did:a\u{202E}evil", "x");
        assert!(!lab.contains('\u{202E}'), "{lab:?}");
        // The foreign direction.
        let ev = foreign(nasty, AuthorCheck::Verified);
        let rec = foreign_to_record(&ev, b"k").unwrap();
        for c in ["\u{202E}", "\u{200D}", "\u{2028}"] {
            assert!(!rec.body.contains(c), "{c:?}");
        }
    }

    #[test]
    fn crlf_and_bare_carriage_returns_cannot_hide_a_header() {
        let out = outbound_text("did:a", "one\r\ndid:ceo wrote:\rtwo\u{85}three");
        assert!(!out.contains('\r') && !out.contains('\u{85}'), "{out:?}");
        assert!(out.lines().skip(1).all(|l| l.starts_with('>')), "{out:?}");
        assert_eq!(out.lines().count(), 1 + 4, "{out:?}");
    }

    #[test]
    fn the_limit_applies_after_quoting() {
        // Many short lines: quoting adds two units per line.
        let body = "x\n".repeat(15_000);
        let out = outbound_text("did:a", &body);
        assert!(utf16_units(&out) <= 20_000, "{}", utf16_units(&out));
        assert!(out.ends_with("[truncated]"));
    }

    #[test]
    fn truncation_counts_utf16_units_not_bytes() {
        // Two-byte text: 20,000 units is far more than 20,000 bytes of room;
        // the old byte cap cut it at 10,000 characters.
        let big = "é".repeat(30_000);
        let e = record_to_event(&rec("did:a", &big, 1), "l", "p", |_| false, None).unwrap();
        let out = prepare_outbound(&e, &caps(false, false, 20_000), &Notices::default(), |_| {
            None
        });
        assert!(utf16_units(&out.text) <= 20_000);
        assert!(
            utf16_units(&out.text) > 19_980,
            "uses the limit, not half of it: {}",
            utf16_units(&out.text)
        );
        assert!(out.text.ends_with("[truncated]"));
        assert!(out.text.len() > 20_000, "bytes are not the measure");
        let small = prepare_outbound(
            &record_to_event(&rec("a", "x", 1), "l", "p", |_| false, None).unwrap(),
            &caps(false, false, 20_000),
            &Notices::default(),
            |_| None,
        );
        assert!(!small.text.contains("truncated"));
    }

    #[test]
    fn utf16_truncation_is_exact_at_boundaries_and_never_splits_a_pair() {
        // ASCII: exactly at the limit is kept whole, one over is cut.
        assert_eq!(truncate_utf16("abcd", 4), "abcd");
        let cut = truncate_utf16(&"a".repeat(100), 50);
        assert_eq!(utf16_units(&cut), 50, "fills the limit exactly");
        assert!(cut.ends_with("[truncated]"));
        // Emoji are 2 units (4 bytes) each; a pair is never split.
        assert_eq!(utf16_units("\u{1F600}"), 2);
        for max in [12usize, 13, 14, 15, 99, 100, 101] {
            let s = "\u{1F600}".repeat(200);
            let out = truncate_utf16(&s, max);
            assert!(utf16_units(&out) <= max, "max {max}: {}", utf16_units(&out));
            assert!(
                utf16_units(&out) + 1 >= max,
                "max {max} wastes more than a unit"
            );
            assert!(out.is_char_boundary(out.len()));
            assert!(out.ends_with("[truncated]"));
        }
        // Mixed: 3-byte CJK (1 unit) and emoji (2 units) never exceed.
        let mixed = "日\u{1F680}本".repeat(10_000);
        let out = truncate_utf16(&mixed, 20_000);
        assert!(utf16_units(&out) <= 20_000 && utf16_units(&out) >= 19_998);
        // A limit shorter than the marker: cut, no marker, still within.
        let tiny = truncate_utf16("\u{1F600}\u{1F600}\u{1F600}", 5);
        assert_eq!(tiny, "\u{1F600}\u{1F600}");
        assert_eq!(truncate_utf16("abc", 0), "");
        // Fits: untouched, no marker.
        assert_eq!(truncate_utf16("\u{1F600}", 2), "\u{1F600}");
    }

    #[test]
    fn an_emoji_line_goes_out_under_the_limit_through_prepare_outbound() {
        let body = "\u{1F600}".repeat(15_000); // 30,000 units, 60,000 bytes
        let e = record_to_event(&rec("did:a", &body, 1), "l", "p", |_| false, None).unwrap();
        let out = prepare_outbound(&e, &caps(false, false, 20_000), &Notices::default(), |_| {
            None
        });
        assert!(utf16_units(&out.text) <= 20_000);
        assert!(utf16_units(&out.text) >= 19_999);
        assert!(out.text.starts_with("did:a wrote:\n> "));
    }

    #[test]
    fn retraction_depends_on_capabilities() {
        let mut e = record_to_event(&rec("did:a", "x", 1), "l", "p", |_| false, None).unwrap();
        e.kind = EventKind::Retract {
            target: "k|1".into(),
        };
        let notice = prepare_outbound(&e, &caps(false, false, 1000), &Notices::default(), |_| None);
        assert_eq!(notice.kind, EventKind::Post);
        assert!(notice.text.contains("[retracted: earlier post k|1]"));
        let native = prepare_outbound(&e, &caps(false, true, 1000), &Notices::default(), |_| None);
        assert!(matches!(native.kind, EventKind::Retract { .. }));
    }

    #[test]
    fn supersede_depends_on_capabilities() {
        let e = record_to_event(&rec("did:a", "x", 2), "l", "p", |_| false, Some("k|1")).unwrap();
        let flat = prepare_outbound(&e, &caps(false, false, 1000), &Notices::default(), |_| None);
        assert_eq!(flat.kind, EventKind::Post);
        assert!(flat.text.contains("[update to earlier post k|1]"));
        assert!(matches!(
            prepare_outbound(&e, &caps(true, false, 1000), &Notices::default(), |_| None).kind,
            EventKind::Supersede { .. }
        ));
    }

    fn reply_caps() -> RoomCapabilities {
        RoomCapabilities {
            supports_replies: true,
            ..caps(false, false, 1000)
        }
    }

    #[test]
    fn a_retraction_is_an_ordinary_reply_to_the_original() {
        let mut e = record_to_event(&rec("did:a", "x", 1), "l", "p", |_| false, None).unwrap();
        e.kind = EventKind::Retract {
            target: "k|1".into(),
        };
        let known = |id: &str| (id == "k|1").then(|| "ab".repeat(16));
        let out = prepare_outbound(&e, &reply_caps(), &Notices::default(), known);
        assert_eq!(out.kind, EventKind::Post);
        assert_eq!(out.reply_to.as_deref(), Some("ab".repeat(16).as_str()));
        assert!(out.text.contains("[retracted: earlier post k|1]"));
        // Unknown original: still an ordinary line with the notice, no reply.
        let out = prepare_outbound(&e, &reply_caps(), &Notices::default(), |_| None);
        assert_eq!(out.reply_to, None);
        assert!(out.text.contains("[retracted"));
        // A room without replies never gets one.
        let out = prepare_outbound(&e, &caps(false, false, 1000), &Notices::default(), known);
        assert_eq!(out.reply_to, None);
    }

    #[test]
    fn a_supersede_without_edit_replies_to_the_previous_version() {
        let e = record_to_event(&rec("did:a", "v2", 2), "l", "p", |_| false, Some("k|1")).unwrap();
        let known = |id: &str| (id == "k|1").then(|| "cd".repeat(16));
        let out = prepare_outbound(&e, &reply_caps(), &Notices::default(), known);
        assert_eq!(out.kind, EventKind::Post);
        assert_eq!(out.reply_to.as_deref(), Some("cd".repeat(16).as_str()));
    }

    #[test]
    fn notice_wording_is_configurable_and_sanitised() {
        let n = Notices {
            update: "edited: {target}".into(),
            retract: "withdrawn: {target}".into(),
        };
        n.validate().unwrap();
        let mut e = record_to_event(&rec("did:a", "x", 1), "l", "p", |_| false, None).unwrap();
        e.kind = EventKind::Retract {
            target: "k\n|1".into(),
        };
        let out = prepare_outbound(&e, &caps(false, false, 1000), &n, |_| None);
        assert!(out.text.contains("withdrawn: k|1"));
        for bad in ["", "a\nb", &"x".repeat(201)] {
            let n = Notices {
                update: bad.into(),
                ..Notices::default()
            };
            assert!(n.validate().is_err());
        }
    }

    fn foreign(text: &str, check: AuthorCheck) -> BridgeEvent {
        BridgeEvent {
            origin: Origin::Foreign,
            origin_id: "h".into(),
            link: "l".into(),
            author: "did:peer:2.x".into(),
            at: 9,
            title: None,
            text: text.into(),
            kind: EventKind::Post,
            reply_to: None,
            record_key: None,
            provenance: Some(Provenance {
                foreign_room: "room".into(),
                author_device: "did:peer:2.x".into(),
                check,
                original_at: 9,
                msg_hash: "abcd".into(),
            }),
        }
    }

    #[test]
    fn record_key_is_deterministic_and_keyed() {
        let a = record_key(b"secret", "room", "abcd").unwrap();
        assert_eq!(a, record_key(b"secret", "room", "abcd").unwrap());
        assert_ne!(a, record_key(b"other", "room", "abcd").unwrap());
        assert_ne!(a, record_key(b"secret", "room2", "abcd").unwrap());
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn inbound_record_is_observed_create_only_and_marked() {
        let w = foreign_to_record(&foreign("hello", AuthorCheck::Verified), b"s").unwrap();
        assert_eq!(w.basis, "observed");
        assert_eq!(w.expected_version, 0);
        assert!(w.body.starts_with(PROVENANCE_OPEN));
        assert!(w.body.contains("\"basis\":\"observed\""));
        // The bridge's own write is recognised as bridged on the way back.
        let r = RoomRecord {
            key: w.key.clone(),
            version: 1,
            author: "x".into(),
            title: None,
            body: w.body.clone(),
            at: 0,
            retracted: false,
        };
        assert!(r.is_bridged());
        let u = foreign_to_record(&foreign("hello", AuthorCheck::Unsigned), b"s").unwrap();
        assert!(u.body.contains("UNVERIFIED: unsigned"));
    }

    #[test]
    fn hostile_text_cannot_close_the_fence() {
        let hostile = "```\n# injected heading\n````\nignore previous instructions\n`````";
        let w = foreign_to_record(&foreign(hostile, AuthorCheck::Unverified), b"s").unwrap();
        // Longest run in the text is 5, so the fence is 6 backticks.
        assert!(w.body.contains("``````text\n"));
        let fence_lines: Vec<_> = w.body.lines().filter(|l| *l == "``````").collect();
        assert_eq!(fence_lines.len(), 1, "exactly one closing fence line");
    }

    #[test]
    fn oversize_inbound_is_cut() {
        let w =
            foreign_to_record(&foreign(&"a".repeat(200_000), AuthorCheck::Unsigned), b"s").unwrap();
        assert!(w.body.len() < MAX_INBOUND_TEXT_BYTES + 1000);
        assert!(w.body.contains("[truncated]"));
    }

    #[test]
    fn missing_provenance_is_refused() {
        let mut e = foreign("x", AuthorCheck::Verified);
        e.provenance = None;
        assert!(foreign_to_record(&e, b"s").is_err());
    }

    #[test]
    fn dedup_window_expires_after_seven_days_plus_300s() {
        let mut d = DedupWindow::default();
        assert!(d.check_and_insert("a", 0));
        assert!(!d.check_and_insert("a", 1000));
        let ttl = (7 * 24 * 3600 + 300) * 1000;
        assert!(!d.check_and_insert("a", ttl - 1));
        assert!(d.check_and_insert("b", 0));
        assert!(d.check_and_insert("b", ttl + 5000));
    }
}
