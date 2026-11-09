//! Geb path B JSON shapes from the guide. Reading is strict about *types*
//! (an unknown envelope, frame or plaintext type is an error, so the caller
//! fails closed) and tolerant about *extra fields* (Geb may add fields; we do
//! not own this format, so `deny_unknown_fields` would only break on upgrade).
//! Field types follow Geb's answers (path B answers 8 and 10, commit
//! release 0.5.14; re-pinned to 0.5.15, `fdf804d`). A value Geb reads leniently (a flag honoured only when exactly
//! `true`, a reaction's `on` coerced with `!!`) is kept as a raw `Value` with a
//! helper that applies Geb's rule.

use crate::geb::crypto::frame_id::is_frame_id;
use crate::geb::crypto::line_id::is_line_ref;
use crate::geb::crypto::ratchet::Side;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Longest line text, in UTF-16 code units (JavaScript string length), not
/// bytes and not scalar values: an emoji outside the BMP counts 2.
pub const MAX_LINE_CHARS: usize = 20_000;
/// Largest Nostr event we post, in bytes of NIP-01 JSON: Geb plans every event
/// to fit 120,000 bytes, under the 131,072-byte per-event cap public relays
/// carry (round 3 section 6). Over it is an error, never a truncation.
pub const MAX_EVENT_BYTES: usize = 120_000;
/// Largest event we will read from a relay: the relay's own per-event cap.
pub const MAX_RECV_EVENT_BYTES: usize = 131_072;

/// Longest KeyPackage in a `kp-stock`, in base64 characters.
pub const MAX_STOCK_KP_CHARS: usize = 65_536;
/// Most ack ids in one envelope.
pub const MAX_ACK_IDS: usize = 200;
/// Most mentions on a line.
pub const MAX_MENTIONS: usize = 16;
/// Longest mention name, in characters.
pub const MAX_MENTION_NAME_CHARS: usize = 40;
/// Most one-tap options on a line.
pub const MAX_OPTIONS: usize = 10;
/// Longest option, in characters.
pub const MAX_OPTION_CHARS: usize = 60;
/// Longest reaction emoji, in UTF-16 units.
pub const MAX_EMOJI_UNITS: usize = 16;
/// Longest room name, in characters.
pub const MAX_ROOM_NAME_CHARS: usize = 80;

/// The length Geb's code measures: UTF-16 code units (JavaScript `.length`).
pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Whether `id` matches the room id pattern `[A-Za-z0-9_-]{8,64}` (also the
/// MLS group id, as UTF-8).
pub fn is_room_id(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Whether `s` matches `^[A-Za-z0-9+/=]+$`, the pattern Geb applies to a
/// KeyPackage string : standard
/// base64 characters. A base64url string (`-`, `_`) fails it and Geb DROPS that
/// string. (Alphabet only; padding and length are the decoder's business.)
pub fn is_std_b64(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// The KeyPackage strings of a `kp-stock` that Geb keeps: those matching
/// [`is_std_b64`], at most 16 . UNVERIFIED: whether Geb
/// cuts the stock to the FIRST 16 or checks the count before filtering.
pub fn stock_kept(kps: &[String]) -> Vec<&str> {
    kps.iter()
        .map(String::as_str)
        .filter(|k| is_std_b64(k))
        .take(16)
        .collect()
}

fn is_peer_did(s: &str) -> bool {
    s.starts_with("did:peer:2.")
}

/// A mailbox envelope (the JSON sealed into a kind 4177 event).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum Envelope {
    /// A dyad frame: `f` is the frame's padded base64, `d` the *sender's* side.
    #[serde(rename = "f")]
    Frame { f: String, d: Side },
    /// Receipts: frame ids, each exactly 16 lowercase hex characters, at most
    /// [`MAX_ACK_IDS`] per envelope. Posted on the pair mailbox.
    #[serde(rename = "ack")]
    Ack { a: Vec<String> },
    /// A room line: `m` is a base64 MLS PrivateMessage.
    #[serde(rename = "ml")]
    Ml { m: String },
    /// A room commit: `e` is the JSON integer MLS epoch the Commit was made
    /// *from*, `m` the standard base64 Commit. …
    /// … epoch; here a non-integer `e` fails to decode
    /// and the mailbox event is dropped as unreadable, the same outcome. A
    /// decoded `mc` stops the poll (see `GebRoom::poll`).
    #[serde(rename = "mc")]
    Mc { e: u64, m: String },
    /// Connect-when-apart, responder to inviter, on the pair mailbox.
    #[serde(rename = "response")]
    Response {
        response: VrcResponse,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// Connect-when-apart, inviter to responder, on the pair mailbox.
    #[serde(rename = "completion")]
    Completion { completion: VrcCompletion },
}

/// `type` of an invitation.
pub const INVITATION_TYPE: &str = "vrc-invitation";
/// `type` of a response.
pub const RESPONSE_TYPE: &str = "vrc-response";
/// `type` of a completion.
pub const COMPLETION_TYPE: &str = "vrc-completion";

/// `{type:"vrc-invitation", did, endpoint, nonce}`; `nonce` is 32 hex.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invitation {
    /// Always [`INVITATION_TYPE`].
    #[serde(rename = "type")]
    pub kind: String,
    /// The inviter's DID; must equal the payload's `from`.
    pub did: String,
    /// Where to answer; the inviter's DID.
    pub endpoint: String,
    /// 32 lowercase hex characters, echoed by the response and completion.
    pub nonce: String,
}

/// The sealed kind-4178 payload `{v:1, from, invitation, sig, name?}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvitePayload {
    /// Always 1.
    pub v: u32,
    /// The inviter's DID.
    pub from: String,
    /// The invitation.
    pub invitation: Invitation,
    /// `sign_json(invitation)` by the inviter.
    pub sig: String,
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// `{type:"vrc-response", did, endpoint, vrc, nonce}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VrcResponse {
    /// Always [`RESPONSE_TYPE`].
    #[serde(rename = "type")]
    pub kind: String,
    /// The responder's DID.
    pub did: String,
    /// The responder's DID.
    pub endpoint: String,
    /// The responder's VRC about the inviter.
    pub vrc: Value,
    /// The invitation's nonce.
    pub nonce: String,
}

/// `{type:"vrc-completion", vrc, nonce}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VrcCompletion {
    /// Always [`COMPLETION_TYPE`].
    #[serde(rename = "type")]
    pub kind: String,
    /// The inviter's VRC about the responder.
    pub vrc: Value,
    /// The invitation's nonce.
    pub nonce: String,
}

/// Whether `n` is a 32-character lowercase hex nonce.
pub fn is_nonce(n: &str) -> bool {
    n.len() == 32 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Envelope {
    /// Check the constraints Geb states for the envelope.
    pub fn validate(&self) -> Result<()> {
        match self {
            Envelope::Response { response, .. }
                if response.kind != RESPONSE_TYPE || !is_nonce(&response.nonce) =>
            {
                return Err(Error::Wire("malformed vrc-response".into()));
            }
            Envelope::Completion { completion }
                if completion.kind != COMPLETION_TYPE || !is_nonce(&completion.nonce) =>
            {
                return Err(Error::Wire("malformed vrc-completion".into()));
            }
            _ => {}
        }
        if let Envelope::Ack { a } = self {
            if a.len() > MAX_ACK_IDS {
                return Err(Error::Wire("more than 200 ack ids".into()));
            }
            if let Some(bad) = a.iter().find(|id| !is_frame_id(id)) {
                return Err(Error::Wire(format!(
                    "ack id is not 16 lowercase hex characters: {}",
                    bad.chars().take(24).collect::<String>()
                )));
            }
        }
        Ok(())
    }
}

/// The room a group frame names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoomRef {
    /// Room id.
    pub id: String,
    /// Room name (absent in a `kp` reply).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The room header in a `welcome` (answer 8): `{v:2, id, name, founder, since,
/// policy, nameAt?, nameBy?}`. The header's `policy` is informational; …
/// … MLS group context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoomInfo {
    /// Always 2.
    pub v: u32,
    /// Room id, matching `[A-Za-z0-9_-]{8,64}`.
    pub id: String,
    /// Room name: non-empty, at most 80 characters.
    pub name: String,
    /// The founder's `did:peer:2.` DID.
    pub founder: String,
    /// Founding time, ms.
    pub since: u64,
    /// The policy **as a JSON string**; re-clean it with [`RoomInfo::policy`].
    pub policy: String,
    /// When the name was set, ms.
    #[serde(default, rename = "nameAt", skip_serializing_if = "Option::is_none")]
    pub name_at: Option<u64>,
    /// Who set the name (a DID).
    #[serde(default, rename = "nameBy", skip_serializing_if = "Option::is_none")]
    pub name_by: Option<String>,
    /// Everything else, preserved.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl RoomInfo {
    /// Check the header constraints Geb states.
    pub fn validate(&self) -> Result<()> {
        if self.v != 2 {
            return Err(Error::Wire("room header v must be 2".into()));
        }
        if !is_room_id(&self.id) {
            return Err(Error::Wire("room id must match [A-Za-z0-9_-]{8,64}".into()));
        }
        let n = self.name.chars().count();
        if n == 0 || n > MAX_ROOM_NAME_CHARS {
            return Err(Error::Wire("room name must be 1-80 characters".into()));
        }
        if !is_peer_did(&self.founder) {
            return Err(Error::Wire("room founder is not a did:peer:2 DID".into()));
        }
        if self
            .name_by
            .as_deref()
            .is_some_and(|d| !d.starts_with("did:"))
        {
            return Err(Error::Wire("nameBy is not a DID".into()));
        }
        Ok(())
    }

    /// The header's policy, cleaned the way Geb cleans it. Informational only.
    pub fn policy(&self) -> super::policy::RoomPolicy {
        super::policy::parse_policy(&self.policy)
    }
}

/// Group (`k:"g"`) operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum GroupOp {
    /// A stock of KeyPackages; a higher `gen` replaces the stock (at most 16).
    #[serde(rename = "kp-stock")]
    KpStock {
        #[serde(rename = "gen")]
        generation: u64,
        kps: Vec<String>,
    },
    /// A request for a KeyPackage.
    #[serde(rename = "kp-req")]
    KpReq { room: RoomRef },
    /// A device's room status request `{k:"g", op:"rs"}`, sent when a commit
    /// cannot be processed; it starts Geb's fork repair (answer 9).
    // UNVERIFIED: the answers name `{k:"g", op:"rs"}` and nothing else about
    // it; whether it carries `room:{id}` (sent here, tolerated absent) and
    // what the receiver replies is not stated.
    #[serde(rename = "rs")]
    Rs {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        room: Option<RoomRef>,
    },
    /// The answer to `kp-req`.
    #[serde(rename = "kp")]
    Kp { room: RoomRef, kp: String },
    /// Seating: `w` is the standard base64 MLS Welcome; `ent` an optional
    /// entry time (ms), set on a re-seat.
    #[serde(rename = "welcome")]
    Welcome {
        room: RoomInfo,
        w: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ent: Option<u64>,
    },
    /// `{k:"g", op:"kp-low", gen, n}`: a holder spent one of our packages (or
    /// holds fewer than six) and asks for a new stock. `gen` is the stock
    /// generation it holds from us, `n` how many it holds. Answered with a
    /// `kp-stock` at `max(our last gen to them, gen) + 1` (round 3 section 5).
    #[serde(rename = "kp-low")]
    KpLow {
        #[serde(rename = "gen")]
        generation: u64,
        n: u64,
    },
    /// `{k:"g", op:"seat-check", room:{id}, e}`: a member that added us asks
    /// whether we hold the room, `e` being the epoch of its add. Answered with
    /// `rs` when seated (round 3 section 3); silence never commits.
    #[serde(rename = "seat-check")]
    SeatCheck { room: RoomRef, e: u64 },
    /// A group op this bridge does not implement (`rc`, `seat-ask`, `leave`, or
    /// any other `op`). Never built by serde: only [`parse_frame`] makes it,
    /// so a peer's unknown op is not a parse failure. It carries the op name
    /// for the log and nothing else; it is acked and ignored (see
    /// `geb::dyad`). Never sent.
    #[serde(skip)]
    Ignored(String),
}

/// The `op` values [`GroupOp`] has typed variants for.
const KNOWN_GROUP_OPS: [&str; 7] = [
    "kp-stock",
    "kp-req",
    "rs",
    "kp",
    "welcome",
    "kp-low",
    "seat-check",
];

/// Parse the JSON of a dyad frame. Strict about *kinds* (an unknown `k`
/// fails: a kind may carry authority, so the caller fails closed), tolerant of
/// *group ops*: `{k:"g", op:<anything else>}` is [`GroupOp::Ignored`], because
/// Geb sends ops this bridge does not build (`rc`, `seat-ask`, `leave`) and an
/// op without authority here must neither fail the parse nor be dropped. A
/// known op with a malformed body, or a `g` frame with no string `op`, still
/// fails.
pub fn parse_frame(bytes: &[u8]) -> Result<Frame> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| Error::Wire(format!("frame: {e}")))?;
    if v.get("k").and_then(Value::as_str) == Some("g")
        && let Some(op) = v.get("op").and_then(Value::as_str)
        && !KNOWN_GROUP_OPS.contains(&op)
    {
        // The name is peer-controlled: bounded and printable for the log.
        let op: String = op.chars().filter(|c| !c.is_control()).take(32).collect();
        return Ok(Frame::Group(GroupOp::Ignored(op)));
    }
    serde_json::from_value(v).map_err(|e| Error::Wire(format!("frame: {e}")))
}

/// A frame inside a dyad envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "k")]
pub enum Frame {
    /// A chat line `{k:"m", d, id, re?, nr?, o?}`. `id` is sender-minted
    /// (16 random hex), accepted at 16-64 hex; `re` is an answered line's id,
    /// same pattern; `nr` is honoured only when `true`; `o` is cleaned like a
    /// room line's options.
    #[serde(rename = "m")]
    Message {
        d: String,
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        re: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nr: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        o: Option<Vec<String>>,
    },
    /// A dyad reaction `{k:"r", re, e, on}`.
    #[serde(rename = "r")]
    Reaction(Reaction),
    /// A group operation.
    #[serde(rename = "g")]
    Group(GroupOp),
    /// Capabilities `{k:"cap", dm, fc?, rv?, wp?}`. `dm` is a number >= 0,
    /// floored by receivers; … room".
    /// `fc` and `rv` count only when exactly `1` (fragments, room events over
    /// the dyad); `wp` is … The
    /// bridge sends `dm: 0` and `fc: 0` (stated, because an UNKNOWN `fc` makes
    /// Geb hold a large frame back until it hears from us), and leaves `rv`
    /// and `wp` unset ([`Frame::bridge_cap`]).
    #[serde(rename = "cap")]
    Cap {
        dm: serde_json::Number,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fc: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rv: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wp: Option<String>,
    },
}

/// A reaction (dyad `{k:"r", re, e, on}`, room `{t:"r", at, re, e, on}`): a set
/// of (emoji, who). `on: false` removes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reaction {
    /// The reacted line's id, 16-64 hex.
    pub re: String,
    /// One emoji, at most 16 UTF-16 units. (On the dyad Geb also refuses
    /// letters, digits, punctuation and whitespace; the room checks length
    /// only. The bridge sends no reactions.)
    pub e: String,
    /// Coerced with `!!` by Geb; read it with [`Reaction::is_on`].
    pub on: Value,
}

impl Reaction {
    /// JavaScript truthiness of `on`.
    pub fn is_on(&self) -> bool {
        match &self.on {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
            Value::String(s) => !s.is_empty(),
            Value::Array(_) | Value::Object(_) => true,
        }
    }

    /// Check `re` and `e`.
    pub fn validate(&self) -> Result<()> {
        if !is_line_ref(&self.re) {
            return Err(Error::Wire(
                "reaction re must be 16-64 lowercase hex".into(),
            ));
        }
        let units = self.e.encode_utf16().count();
        if units == 0 || units > MAX_EMOJI_UNITS {
            return Err(Error::Wire(
                "reaction emoji must be 1-16 UTF-16 units".into(),
            ));
        }
        Ok(())
    }
}

impl Frame {
    /// Check the constraints Geb states for a frame.
    pub fn validate(&self) -> Result<()> {
        match self {
            Frame::Message { id, re, o, .. } => {
                if !((16..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())) {
                    return Err(Error::Wire(
                        "frame message id must be 16-64 hex characters".into(),
                    ));
                }
                if re.as_deref().is_some_and(|r| !is_line_ref(r)) {
                    return Err(Error::Wire("frame re must be 16-64 lowercase hex".into()));
                }
                if let Some(o) = o {
                    check_options(o)?;
                }
                Ok(())
            }
            Frame::Reaction(r) => r.validate(),
            Frame::Group(GroupOp::Welcome { room, .. }) => room.validate(),
            Frame::Group(GroupOp::KpStock { generation, kps }) => {
                // Round 3 section 5: `gen` an integer >= 1, at most 16
                // packages kept, each standard base64 of at most 65,536
                // characters.
                if *generation == 0
                    || kps.len() > 16
                    || kps
                        .iter()
                        .any(|k| !is_std_b64(k) || k.len() > MAX_STOCK_KP_CHARS)
                {
                    return Err(Error::Wire(
                        "kp-stock: gen >= 1, at most 16 KeyPackages, each standard base64 \
                         (^[A-Za-z0-9+/=]+$) of at most 65,536 characters"
                            .into(),
                    ));
                }
                Ok(())
            }
            Frame::Group(GroupOp::KpLow { generation, .. }) if *generation == 0 => {
                Err(Error::Wire("kp-low: gen must be >= 1".into()))
            }
            Frame::Group(GroupOp::SeatCheck { room, .. }) if !is_room_id(&room.id) => {
                Err(Error::Wire("seat-check: bad room id".into()))
            }
            Frame::Group(GroupOp::Kp { kp, .. }) => {
                if !is_std_b64(kp) {
                    return Err(Error::Wire(
                        "kp: a KeyPackage is standard base64 (^[A-Za-z0-9+/=]+$)".into(),
                    ));
                }
                Ok(())
            }
            Frame::Group(_) | Frame::Cap { .. } => Ok(()),
        }
    }

    /// A `cap` frame that is safe to send: `dm: 0` (never claims direct
    /// rooms), `fc: 0` (we do not reassemble `{k:"fc"}` fragments; round 3
    /// section 3), `rv` unset (no room events over the dyad), no `wp`.
    ///
    /// KNOWN LIMITATION (open item): with `fc:0` Geb sends a frame that does
    /// not fit one 120,000-byte event whole, and the relay refuses it, so a
    /// Welcome too large for one event (a big room: the ratchet tree rides in
    /// it) never reaches us and joining a large room fails. Implementing
    /// `fc` fragments (`{k:"fc", id, i, n, d}`, `n` <= 64) is not done.
    pub fn bridge_cap() -> Frame {
        Frame::Cap {
            dm: 0.into(),
            fc: Some(Value::from(0)),
            rv: None,
            wp: None,
        }
    }
}

fn check_options(o: &[String]) -> Result<()> {
    if o.len() > MAX_OPTIONS
        || o.iter()
            .any(|s| s.trim().is_empty() || s.chars().count() > MAX_OPTION_CHARS || s.trim() != s)
    {
        return Err(Error::Wire(
            "options: at most 10 trimmed, non-empty strings of at most 60 characters".into(),
        ));
    }
    Ok(())
}

/// The plaintext inside an MLS application message. Only `l` (a line) and `r`
/// (a reaction) are understood; `ag` (an agreement, an unstable format),
/// `h`, `p`, `n`, `m` and the rest are errors and the caller drops the
/// message. There is no edit, delete or retract kind on the wire; never
/// invent one (answer 11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum RoomPlaintext {
    /// A chat line.
    #[serde(rename = "l")]
    Line(LineBody),
    /// A reaction `{t:"r", at, re, e, on}`.
    #[serde(rename = "r")]
    Reaction {
        /// Milliseconds since the epoch.
        at: u64,
        #[serde(flatten)]
        reaction: Reaction,
    },
}

/// A mention `{d, n?}`: `d` is a `did:peer:2.` DID, `n` the name as typed
/// (1-40 characters; absent in "wire 2", where the text holds one U+FFFC per
/// mention instead).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mention {
    /// The mentioned member's DID.
    pub d: String,
    /// The name as typed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
}

/// `{t:"l", at, text, re?, m?, o?, nr?, sg}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineBody {
    /// Milliseconds since the epoch, claimed by the author.
    pub at: u64,
    /// Non-empty, up to 20,000 characters.
    pub text: String,
    /// The id of the line answered. In a room this is the **derived** id
    /// ([`crate::geb::crypto::line_id::line_id`]); `^[0-9a-f]{16,64}$`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub re: Option<String>,
    /// At most 16 mentions. …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m: Option<Vec<Mention>>,
    /// One-tap options: trimmed, non-empty, at most 10 of at most 60
    /// characters. Senders attach them only to an addressed line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub o: Option<Vec<String>>,
    /// "Needs a reply". Added before signing; read only when `=== true`, see
    /// [`LineBody::needs_reply`]. The bridge never sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nr: Option<Value>,
    /// The author's `sign_json` over [`signing_doc`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sg: Option<String>,
}

impl LineBody {
    /// A plain line with no optional fields.
    pub fn new(at: u64, text: String) -> Self {
        Self {
            at,
            text,
            re: None,
            m: None,
            o: None,
            nr: None,
            sg: None,
        }
    }

    /// A plain line answering the line with derived id `re`.
    pub fn reply(at: u64, text: String, re: String) -> Self {
        Self {
            re: Some(re),
            ..Self::new(at, text)
        }
    }

    /// Whether the sender marked the line "needs a reply" (only `true` counts).
    pub fn needs_reply(&self) -> bool {
        self.nr == Some(Value::Bool(true))
    }

    /// Check what we may send: the full set of stated constraints.
    pub fn validate(&self) -> Result<()> {
        self.validate_inbound()?;
        if let Some(m) = &self.m {
            if m.len() > MAX_MENTIONS {
                return Err(Error::Wire("more than 16 mentions".into()));
            }
            for x in m {
                if !is_peer_did(&x.d) {
                    return Err(Error::Wire("mention d is not a did:peer:2 DID".into()));
                }
                if x.n
                    .as_deref()
                    .is_some_and(|n| n.is_empty() || n.chars().count() > MAX_MENTION_NAME_CHARS)
                {
                    return Err(Error::Wire("mention name must be 1-40 characters".into()));
                }
            }
        }
        if let Some(o) = &self.o {
            check_options(o)?;
        }
        Ok(())
    }

    /// Check what we require of a line we read: non-empty text within the
    /// limit and a well-formed `re`. Mentions and options are not rejected on
    /// content, because the bridge acts on neither and Geb cleans them.
    pub fn validate_inbound(&self) -> Result<()> {
        let n = utf16_len(&self.text);
        if n == 0 {
            return Err(Error::Wire("line text is empty".into()));
        }
        if n > MAX_LINE_CHARS {
            return Err(Error::Wire(
                "line text over 20,000 UTF-16 code units".into(),
            ));
        }
        if self.re.as_deref().is_some_and(|r| !is_line_ref(r)) {
            return Err(Error::Wire("line re must be 16-64 lowercase hex".into()));
        }
        Ok(())
    }
}

/// The document a line's `sg` signs: `{v:1, room, author, body}` where `body`
/// is the plaintext without `sg` (guide). `nr`, when
/// present, is added before signing and so is part of `body`.
pub fn signing_doc(room: &str, author: &str, line: &LineBody) -> Result<Value> {
    let mut body = line.clone();
    body.sg = None;
    let body =
        serde_json::to_value(RoomPlaintext::Line(body)).map_err(|e| Error::Wire(e.to_string()))?;
    Ok(serde_json::json!({"v": 1, "room": room, "author": author, "body": body}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelopes_round_trip_and_match_the_guide_shapes() {
        let f: Envelope = serde_json::from_value(json!({"t":"f","f":"AAAA","d":"lo"})).unwrap();
        assert_eq!(
            f,
            Envelope::Frame {
                f: "AAAA".into(),
                d: Side::Lo
            }
        );
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            json!({"t":"f","f":"AAAA","d":"lo"})
        );
        let mc: Envelope = serde_json::from_value(json!({"t":"mc","e":4,"m":"QQ=="})).unwrap();
        assert_eq!(
            mc,
            Envelope::Mc {
                e: 4,
                m: "QQ==".into()
            }
        );
        let ml = serde_json::to_value(Envelope::Ml { m: "QQ==".into() }).unwrap();
        assert_eq!(ml, json!({"t":"ml","m":"QQ=="}));
        let ack: Envelope =
            serde_json::from_value(json!({"t":"ack","a":["0123456789abcdef"]})).unwrap();
        assert!(ack.validate().is_ok());
        assert!(serde_json::from_value::<Envelope>(json!({"t":"ack","a":["abc",12]})).is_err());
    }

    #[test]
    fn unknown_types_fail_closed() {
        assert!(serde_json::from_value::<Envelope>(json!({"t":"zz"})).is_err());
        assert!(serde_json::from_value::<Envelope>(json!({"f":"x","d":"lo"})).is_err());
        assert!(serde_json::from_value::<Envelope>(json!({"t":"f","f":"x","d":"mid"})).is_err());
        assert!(serde_json::from_value::<Frame>(json!({"k":"fc","i":1})).is_err());
        assert!(serde_json::from_value::<Frame>(json!({"k":"g","op":"mystery"})).is_err());
        let rs: Frame = serde_json::from_value(json!({"k":"g","op":"rs"})).unwrap();
        assert_eq!(rs, Frame::Group(GroupOp::Rs { room: None }));
        let rs = Frame::Group(GroupOp::Rs {
            room: Some(RoomRef {
                id: "geb-room-0001".into(),
                name: None,
            }),
        });
        assert_eq!(
            serde_json::to_value(&rs).unwrap(),
            json!({"k":"g","op":"rs","room":{"id":"geb-room-0001"}})
        );
        assert!(serde_json::from_value::<RoomPlaintext>(json!({"t":"ag","at":1,"d":{}})).is_err());
    }

    #[test]
    fn unknown_group_ops_parse_as_ignored_but_unknown_kinds_and_bad_known_ops_fail() {
        for op in ["rc", "seat-ask", "leave", "brand-new"] {
            let j = json!({"k":"g","op":op,"room":{"id":"r"},"e":1,"c":"AA"}).to_string();
            assert_eq!(
                parse_frame(j.as_bytes()).unwrap(),
                Frame::Group(GroupOp::Ignored(op.into()))
            );
        }
        // A hostile op name is bounded and printable.
        let long = format!("x\n{}", "y".repeat(100));
        let j = json!({"k":"g","op":long}).to_string();
        let Frame::Group(GroupOp::Ignored(n)) = parse_frame(j.as_bytes()).unwrap() else {
            panic!()
        };
        assert!(n.len() <= 32 && !n.contains('\n'));
        // Known ops still parse typed.
        let j = json!({"k":"g","op":"kp-req","room":{"id":"r"}}).to_string();
        assert!(matches!(
            parse_frame(j.as_bytes()).unwrap(),
            Frame::Group(GroupOp::KpReq { .. })
        ));
        // Fail closed: an unknown kind (it may carry authority), a `g` with no
        // string op, a known op with a bad body, not JSON.
        for bad in [
            json!({"k":"zz","op":"rc"}),
            json!({"k":"g"}),
            json!({"k":"g","op":5}),
            json!({"k":"g","op":"kp-req"}),
            json!({"k":"g","op":"welcome","w":"AA"}),
        ] {
            assert!(parse_frame(bad.to_string().as_bytes()).is_err(), "{bad}");
        }
        assert!(parse_frame(b"not json").is_err());
        // The typed serde still refuses an unknown op; Ignored is never sent.
        assert!(
            serde_json::from_value::<Frame>(json!({"k":"g","op":"rc"})).is_err(),
            "only parse_frame is tolerant"
        );
        assert!(serde_json::to_vec(&Frame::Group(GroupOp::Ignored("rc".into()))).is_err());
    }

    #[test]
    fn key_package_strings_are_standard_base64_only() {
        assert!(is_std_b64("AbZ09+/=="));
        for bad in ["", "ab-c", "ab_c", "ab c", "ab.c", "ab\n"] {
            assert!(!is_std_b64(bad), "{bad:?}");
        }
        let kps: Vec<String> = ["AAA=", "ab-c", "BBB="].map(String::from).to_vec();
        assert_eq!(stock_kept(&kps), ["AAA=", "BBB="]);
        let many: Vec<String> = (0..20).map(|_| "AAAA".to_string()).collect();
        assert_eq!(stock_kept(&many).len(), 16);
        let stock = |kps: Vec<String>| Frame::Group(GroupOp::KpStock { generation: 1, kps });
        assert!(stock(vec!["AAAA".into()]).validate().is_ok());
        assert!(stock(vec!["AA-A".into()]).validate().is_err());
        assert!(stock(many).validate().is_err());
        let kp = |s: &str| {
            Frame::Group(GroupOp::Kp {
                room: RoomRef {
                    id: "r".into(),
                    name: None,
                },
                kp: s.into(),
            })
        };
        assert!(kp("AAAA").validate().is_ok());
        assert!(kp("AA_A").validate().is_err());
    }

    #[test]
    fn extra_fields_are_tolerated() {
        let l: RoomPlaintext =
            serde_json::from_value(json!({"t":"l","at":1,"text":"x","future":true})).unwrap();
        assert!(matches!(l, RoomPlaintext::Line(_)));
    }

    #[test]
    fn nested_group_frames() {
        let g: Frame =
            serde_json::from_value(json!({"k":"g","op":"kp-stock","gen":3,"kps":["a","b"]}))
                .unwrap();
        assert_eq!(
            g,
            Frame::Group(GroupOp::KpStock {
                generation: 3,
                kps: vec!["a".into(), "b".into()]
            })
        );
        assert_eq!(
            serde_json::to_value(&g).unwrap(),
            json!({"k":"g","op":"kp-stock","gen":3,"kps":["a","b"]})
        );
        let req: Frame =
            serde_json::from_value(json!({"k":"g","op":"kp-req","room":{"id":"r","name":"n"}}))
                .unwrap();
        assert!(matches!(req, Frame::Group(GroupOp::KpReq { .. })));
        let kp: Frame =
            serde_json::from_value(json!({"k":"g","op":"kp","room":{"id":"r"},"kp":"AA"})).unwrap();
        assert!(matches!(kp, Frame::Group(GroupOp::Kp { .. })));
        let w: Frame = serde_json::from_value(json!({
            "k":"g","op":"welcome","w":"AA",
            "room":{"v":2,"id":"room-0001","name":"n","founder":"did:peer:2.x","since":5,
                    "policy":"{\"v\":1}","nameAt":7,"zz":9}
        }))
        .unwrap();
        assert!(w.validate().is_ok());
        match w {
            Frame::Group(GroupOp::Welcome { room, ent, .. }) => {
                assert_eq!(room.extra.get("zz"), Some(&json!(9)));
                assert_eq!(room.policy, "{\"v\":1}");
                assert_eq!(room.name_at, Some(7));
                assert_eq!(ent, None);
                assert_eq!(room.policy().v, 1);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    fn header() -> RoomInfo {
        RoomInfo {
            v: 2,
            id: "room-0001".into(),
            name: "n".into(),
            founder: "did:peer:2.x".into(),
            since: 1,
            policy: "{}".into(),
            name_at: None,
            name_by: None,
            extra: Map::new(),
        }
    }

    #[test]
    fn welcome_header_constraints() {
        assert!(header().validate().is_ok());
        let mut h = header();
        h.id = "short".into();
        assert!(h.validate().is_err());
        h.id = "has space".repeat(2);
        assert!(h.validate().is_err());
        h.id = "a".repeat(65);
        assert!(h.validate().is_err());
        for name in ["".to_string(), "x".repeat(81)] {
            let mut h = header();
            h.name = name;
            assert!(h.validate().is_err());
        }
        let mut h = header();
        h.name = "é".repeat(80);
        assert!(h.validate().is_ok());
        h.founder = "did:key:z".into();
        assert!(h.validate().is_err());
        // The policy must be a JSON string, not an object.
        let bad = json!({"v":2,"id":"room-0001","name":"n","founder":"did:peer:2.x","since":1,"policy":{}});
        assert!(serde_json::from_value::<RoomInfo>(bad).is_err());
    }

    #[test]
    fn ack_limits() {
        let ok = Envelope::Ack {
            a: vec!["0123456789abcdef".into(); 200],
        };
        assert!(ok.validate().is_ok());
        let many = Envelope::Ack {
            a: vec!["0123456789abcdef".into(); 201],
        };
        assert!(many.validate().is_err());
        for bad in ["0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0"] {
            assert!(
                Envelope::Ack {
                    a: vec![bad.into()]
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn line_field_types() {
        let l: LineBody = serde_json::from_value(json!({
            "at": 1, "text": "x", "re": "0123456789abcdef0123456789abcdef",
            "m": [{"d":"did:peer:2.a","n":"al"}], "o": ["a","b"], "nr": true, "sg": "s"
        }))
        .unwrap();
        assert!(l.validate().is_ok() && l.needs_reply());
        let mut l2 = l.clone();
        l2.nr = Some(json!("true"));
        assert!(!l2.needs_reply());
        // Mention and option limits apply to what we send.
        let mut m = LineBody::new(1, "x".into());
        m.m = Some(vec![
            Mention {
                d: "did:peer:2.a".into(),
                n: None
            };
            17
        ]);
        assert!(m.validate().is_err());
        let mut o = LineBody::new(1, "x".into());
        o.o = Some(vec!["a".into(); 11]);
        assert!(o.validate().is_err());
        o.o = Some(vec!["x".repeat(61)]);
        assert!(o.validate().is_err());
        o.o = Some(vec!["  ".into()]);
        assert!(o.validate().is_err());
        o.o = Some(vec!["x".repeat(60)]);
        assert!(o.validate().is_ok());
        let mut n = LineBody::new(1, "x".into());
        n.m = Some(vec![Mention {
            d: "did:peer:2.a".into(),
            n: Some("n".repeat(41)),
        }]);
        assert!(n.validate().is_err());
        // Inbound is lenient on content.
        n.m = Some(vec![
            Mention {
                d: "did:peer:2.a".into(),
                n: Some("n".repeat(41))
            };
            20
        ]);
        assert!(n.validate_inbound().is_ok());
        let bad_re = LineBody::reply(1, "x".into(), "XYZ".into());
        assert!(bad_re.validate().is_err());
        assert!(LineBody::new(1, String::new()).validate().is_err());
    }

    #[test]
    fn reactions_and_cap_shapes() {
        let r = Reaction {
            re: "0123456789abcdef".into(),
            e: "\u{1F44D}".into(),
            on: json!(1),
        };
        assert!(r.validate().is_ok() && r.is_on());
        let off = Reaction {
            on: json!(0),
            ..r.clone()
        };
        assert!(!off.is_on());
        assert!(
            Reaction {
                e: "x".repeat(17),
                ..r.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Reaction {
                re: "zz".into(),
                ..r.clone()
            }
            .validate()
            .is_err()
        );
        let f: Frame =
            serde_json::from_value(json!({"k":"r","re":"0123456789abcdef","e":"x","on":true}))
                .unwrap();
        assert!(matches!(f, Frame::Reaction(_)));
        let p: RoomPlaintext = serde_json::from_value(
            json!({"t":"r","at":1,"re":"0123456789abcdef","e":"x","on":false}),
        )
        .unwrap();
        assert!(matches!(p, RoomPlaintext::Reaction { at: 1, .. }));
        let c: Frame = serde_json::from_value(json!({"k":"cap","dm":1.7,"fc":1})).unwrap();
        assert!(matches!(c, Frame::Cap { .. }));
        assert!(serde_json::from_value::<Frame>(json!({"k":"cap"})).is_err());
    }

    #[test]
    fn message_id_constraint() {
        let ok = Frame::Message {
            d: "hi".into(),
            id: "0123456789abcdef".into(),
            re: None,
            nr: None,
            o: None,
        };
        assert!(ok.validate().is_ok());
        for bad in ["short", "0123456789abcdeg", &"a".repeat(65)] {
            let f = Frame::Message {
                d: "hi".into(),
                id: bad.to_string(),
                re: None,
                nr: None,
                o: None,
            };
            assert!(f.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn kp_low_and_seat_check_parse_typed_and_stock_limits_hold() {
        let low = parse_frame(br#"{"k":"g","op":"kp-low","gen":3,"n":2}"#).unwrap();
        assert_eq!(
            low,
            Frame::Group(GroupOp::KpLow {
                generation: 3,
                n: 2
            })
        );
        assert!(low.validate().is_ok());
        assert!(
            Frame::Group(GroupOp::KpLow {
                generation: 0,
                n: 0
            })
            .validate()
            .is_err()
        );
        // A known op with a bad body fails (it is not "ignored").
        assert!(parse_frame(br#"{"k":"g","op":"kp-low","gen":"x"}"#).is_err());
        let sc = parse_frame(br#"{"k":"g","op":"seat-check","room":{"id":"geb-room-0001"},"e":4}"#)
            .unwrap();
        assert!(matches!(sc, Frame::Group(GroupOp::SeatCheck { e: 4, .. })));
        assert!(sc.validate().is_ok());
        let stock =
            |generation, kps: Vec<String>| Frame::Group(GroupOp::KpStock { generation, kps });
        assert!(stock(1, vec!["AAAA".into(); 16]).validate().is_ok());
        assert!(
            stock(0, vec!["AAAA".into()]).validate().is_err(),
            "gen >= 1"
        );
        assert!(stock(1, vec!["AAAA".into(); 17]).validate().is_err());
        assert!(stock(1, vec!["A".repeat(65_536)]).validate().is_ok());
        assert!(stock(1, vec!["A".repeat(65_537)]).validate().is_err());
    }

    #[test]
    fn the_bridge_sends_dm_zero_fc_zero_and_no_rv() {
        let v = serde_json::to_value(Frame::bridge_cap()).unwrap();
        assert_eq!(v, json!({"k":"cap","dm":0,"fc":0}));
        assert!(v.get("rv").is_none() && v.get("wp").is_none());
    }

    #[test]
    fn line_limits_and_signing_doc_excludes_sg() {
        assert!(LineBody::new(1, "é".repeat(20_000)).validate().is_ok());
        assert!(LineBody::new(1, "x".repeat(20_001)).validate().is_err());
        // UTF-16 code units, as JavaScript counts: an emoji is two.
        assert!(
            LineBody::new(1, "\u{1F600}".repeat(10_000))
                .validate()
                .is_ok()
        );
        assert!(
            LineBody::new(1, "\u{1F600}".repeat(10_001))
                .validate()
                .is_err()
        );
        assert_eq!(utf16_len("a\u{1F600}\u{e9}"), 4);
        let mut l = LineBody::new(7, "hello".into());
        let unsigned = signing_doc("room", "did:a", &l).unwrap();
        l.sg = Some("SIG".into());
        assert_eq!(unsigned, signing_doc("room", "did:a", &l).unwrap());
        assert_eq!(
            unsigned,
            json!({"v":1,"room":"room","author":"did:a","body":{"t":"l","at":7,"text":"hello"}})
        );
    }
}
