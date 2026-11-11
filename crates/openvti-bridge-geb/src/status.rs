//! The room status `rs` body, its cleaner and the comparison (Geb answers
//! round 2 section 5, round 4 sections 8 and 9; Geb code).
//! Pure: no MLS, no clock, built in every build.
//!
//! ```text
//! { k:"g", op:"rs", room:{id},
//!   s:{ e:<int >= 0>, a:<authenticator hex, 16>,
//!       chain:[ {e:<int >= 1, the epoch the Commit MADE>, h:<hash hex 16>, a:<hex 16>} ],
//!       lines?:{<author DID>:{n,last}}, ls?:<ms>, cps?:{...} },
//!   via?:[<member DIDs>] }
//! ```
//!
//! UNVERIFIED (the answers do not settle; each is a choice here):
//! - the exact algorithm of `compareStatus` is not
//!   written out; [`compare_status`] is our reading of "equal / ahead (they
//!   lag) / behind / fork at the lowest epoch where the authenticators differ";
//! - whether `cleanStatus` drops a bad chain entry or the whole status (we
//!   drop the whole status: fail closed), and whether more than 100,000 chain
//!   entries or 1,000 holdings is refused or truncated (chain: refused;
//!   holdings: the first 1,000 kept);
//! - how the authenticator is cut: the lowercase hex of the epoch
//!   authenticator, first 16 characters (8 bytes).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Hex characters kept of a hash or an authenticator (`CHAIN_HEX`).
pub const CHAIN_HEX: usize = 16;
/// Most chain entries a receiver accepts.
pub const MAX_CHAIN: usize = 100_000;
/// Most authors in a holdings map.
pub const MAX_HOLDINGS: usize = 1_000;
/// Most chain entries WE send. A dyad frame must fit one event (about 36,000
/// bytes of plaintext, and we say `fc:0`); an entry is about 70 bytes, so the
/// newest 300 fit with room to spare. UNVERIFIED: whether a truncated chain
/// compares the same on Geb's side (a receiver that holds more reads the
/// overlap).
pub const MAX_CHAIN_SENT: usize = 300;

/// One settled Commit: the epoch it MADE, the winner's hash and the
/// authenticator at that epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    /// The epoch the Commit made (>= 1).
    pub e: u64,
    /// The winning Commit's SHA-256, first 16 hex.
    pub h: String,
    /// The epoch authenticator at `e`, first 16 hex.
    pub a: String,
}

/// What a member holds of one author's lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holding {
    /// How many lines.
    pub n: u64,
    /// The newest, ms.
    pub last: u64,
}

/// The status body `s`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomStatus {
    /// The sender's MLS epoch.
    pub e: u64,
    /// The epoch authenticator, first 16 hex.
    pub a: String,
    /// The settled Commits.
    pub chain: Vec<ChainEntry>,
    /// Lines held per author.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<BTreeMap<String, Holding>>,
    /// The sender's own entry time, ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ls: Option<u64>,
    /// Persona-card holdings (read, never sent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cps: Option<BTreeMap<String, Holding>>,
}

fn clean_hex(v: &Value, min: usize) -> Option<String> {
    let s = v.as_str()?;
    if s.len() < min || s.len() > 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(s[..s.len().min(CHAIN_HEX)].to_ascii_lowercase())
}

fn clean_uint(v: &Value) -> Option<u64> {
    v.as_u64()
}

fn clean_holdings(v: &Value) -> Option<BTreeMap<String, Holding>> {
    let m = v.as_object()?;
    let mut out = BTreeMap::new();
    for (k, h) in m {
        if out.len() >= MAX_HOLDINGS {
            break;
        }
        if let (Some(n), Some(last)) = (
            h.get("n").and_then(clean_uint),
            h.get("last").and_then(clean_uint),
        ) {
            out.insert(k.clone(), Holding { n, last });
        }
    }
    Some(out)
}

/// `cleanStatus`: `None` when `s` is not a valid status.
pub fn clean_status(s: &Value) -> Option<RoomStatus> {
    let e = clean_uint(s.get("e")?)?;
    let a = clean_hex(s.get("a")?, 8)?;
    let raw = s.get("chain")?.as_array()?;
    if raw.len() > MAX_CHAIN {
        return None;
    }
    let mut chain = Vec::with_capacity(raw.len());
    for c in raw {
        let ce = clean_uint(c.get("e")?)?;
        if ce < 1 {
            return None;
        }
        chain.push(ChainEntry {
            e: ce,
            h: clean_hex(c.get("h")?, 1)?,
            a: clean_hex(c.get("a")?, 1)?,
        });
    }
    Some(RoomStatus {
        e,
        a,
        chain,
        lines: s.get("lines").and_then(clean_holdings),
        ls: s.get("ls").and_then(clean_uint),
        cps: s.get("cps").and_then(clean_holdings),
    })
}

/// `cleanVia`: non-empty strings, de-duplicated, sorted.
pub fn clean_via(v: &Value) -> Vec<String> {
    let Some(a) = v.as_array() else {
        return Vec::new();
    };
    let mut out: Vec<String> = a
        .iter()
        .filter_map(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 512)
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_HOLDINGS);
    out
}

/// What comparing a peer's status with ours says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comparison {
    /// The same epoch state: nothing to do.
    Equal,
    /// We are ahead (they lag): send them what they miss.
    Ahead,
    /// We are behind: re-read the room, ask to be re-seated if it persists.
    Behind,
    /// The histories split. `epoch` is the lowest epoch where the two
    /// authenticators differ; `hash_wins` is true when OUR authenticator there
    /// is the lower (the lower wins).
    Fork { epoch: u64, hash_wins: bool },
}

fn auth_map(s: &RoomStatus) -> BTreeMap<u64, &str> {
    let mut m: BTreeMap<u64, &str> = s.chain.iter().map(|c| (c.e, c.a.as_str())).collect();
    m.insert(s.e, s.a.as_str());
    m
}

fn same_auth(a: &str, b: &str) -> bool {
    let n = a.len().min(b.len());
    a[..n] == b[..n]
}

/// `compareStatus` (our reading, see the module notes): a fork at the lowest
/// epoch both sides hold an authenticator for where they differ; otherwise the
/// side at the higher epoch is ahead.
pub fn compare_status(mine: &RoomStatus, theirs: &RoomStatus) -> Comparison {
    let (m, t) = (auth_map(mine), auth_map(theirs));
    for (e, ma) in &m {
        if let Some(ta) = t.get(e)
            && !same_auth(ma, ta)
        {
            return Comparison::Fork {
                epoch: *e,
                hash_wins: ma < ta,
            };
        }
    }
    match mine.e.cmp(&theirs.e) {
        std::cmp::Ordering::Equal => Comparison::Equal,
        std::cmp::Ordering::Greater => Comparison::Ahead,
        std::cmp::Ordering::Less => Comparison::Behind,
    }
}

/// Why a fork verdict went the way it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkReason {
    /// Rule 1: they and every other member are ahead of me.
    BehindAll,
    /// Rule 2: they are behind me and every other member is ahead of them.
    TheyBehindAll,
    /// Rule 3: the lower authenticator decides.
    Hash,
}

/// `forkMineWins(hashWins, mine, theirs, others)` (round 4 Q9). `others` holds, for each other member, the epoch
/// of the newest status heard from it. `every` over an empty list is true (UNVERIFIED that Geb reads it so).
pub fn fork_mine_wins(
    hash_wins: bool,
    mine: u64,
    theirs: u64,
    others: &[u64],
) -> (bool, ForkReason) {
    if theirs > mine && others.iter().all(|&o| o > mine) {
        return (false, ForkReason::BehindAll);
    }
    if theirs < mine && others.iter().all(|&o| o > theirs) {
        return (true, ForkReason::TheyBehindAll);
    }
    (hash_wins, ForkReason::Hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn st(e: u64, a: &str, chain: &[(u64, &str)]) -> RoomStatus {
        RoomStatus {
            e,
            a: a.into(),
            chain: chain
                .iter()
                .map(|(e, a)| ChainEntry {
                    e: *e,
                    h: "0".repeat(16),
                    a: (*a).into(),
                })
                .collect(),
            lines: None,
            ls: None,
            cps: None,
        }
    }

    #[test]
    fn clean_status_follows_the_stated_rules() {
        let ok = json!({"e":3,"a":"ABCDEF0123456789ABCDEF","chain":[{"e":1,"h":"aa","a":"bb"}]});
        let s = clean_status(&ok).unwrap();
        assert_eq!(s.a, "abcdef0123456789", "cut to 16, lowercase");
        assert_eq!(s.chain[0].h, "aa");
        for bad in [
            json!({"a":"abcdef01","chain":[]}),
            json!({"e":-1,"a":"abcdef01","chain":[]}),
            json!({"e":1.5,"a":"abcdef01","chain":[]}),
            json!({"e":1,"a":"abc","chain":[]}),
            json!({"e":1,"a":"xyzxyzxyz","chain":[]}),
            json!({"e":1,"a":"abcdef01"}),
            json!({"e":1,"a":"abcdef01","chain":[{"e":0,"h":"aa","a":"bb"}]}),
            json!({"e":1,"a":"abcdef01","chain":[{"e":1,"h":"zz","a":"bb"}]}),
            json!({"e":1,"a":"abcdef01","chain":[{"e":1,"h":"aa"}]}),
        ] {
            assert!(clean_status(&bad).is_none(), "{bad}");
        }
        let many = json!({"e":1,"a":"abcdef01","chain":
            (0..MAX_CHAIN + 1).map(|i| json!({"e":i + 1,"h":"aa","a":"bb"})).collect::<Vec<_>>()});
        assert!(clean_status(&many).is_none(), "over 100,000 entries");
        let holds: serde_json::Map<String, Value> = (0..MAX_HOLDINGS + 5)
            .map(|i| (format!("did:x{i}"), json!({"n":1,"last":2})))
            .collect();
        let h = json!({"e":1,"a":"abcdef01","chain":[],"lines":holds,"ls":7});
        let s = clean_status(&h).unwrap();
        assert_eq!(s.lines.unwrap().len(), MAX_HOLDINGS);
        assert_eq!(s.ls, Some(7));
        assert_eq!(clean_via(&json!(["b", "a", "", "b", 3])), vec!["a", "b"]);
    }

    #[test]
    fn compare_equal_ahead_behind_fork() {
        let a = st(
            3,
            "ccc00000ccc00000",
            &[(1, "a1"), (2, "b2"), (3, "ccc00000ccc00000")],
        );
        assert_eq!(compare_status(&a, &a.clone()), Comparison::Equal);
        let lag = st(2, "b2", &[(1, "a1"), (2, "b2")]);
        assert_eq!(compare_status(&a, &lag), Comparison::Ahead);
        assert_eq!(compare_status(&lag, &a), Comparison::Behind);
        // A different authenticator at the SAME epoch is a fork there.
        let f = st(3, "ddd00000ddd00000", &[(1, "a1"), (2, "b2")]);
        assert_eq!(
            compare_status(&a, &f),
            Comparison::Fork {
                epoch: 3,
                hash_wins: true
            }
        );
        // The LOWEST differing epoch is the verdict's epoch, not the top one.
        let g = st(4, "eee", &[(1, "a1"), (2, "zz"), (3, "yy"), (4, "eee")]);
        assert_eq!(
            compare_status(&a, &g),
            Comparison::Fork {
                epoch: 2,
                hash_wins: true
            }
        );
        assert_eq!(
            compare_status(&g, &a),
            Comparison::Fork {
                epoch: 2,
                hash_wins: false
            }
        );
        // No shared epoch (we joined later): the higher epoch is ahead.
        let late = st(10, "f0f0", &[]);
        assert_eq!(compare_status(&late, &lag), Comparison::Ahead);
    }

    #[test]
    fn fork_mine_wins_rules_in_order() {
        // 1: theirs > mine and every other > mine: I lose, even if my hash wins.
        assert_eq!(
            fork_mine_wins(true, 3, 5, &[4, 6]),
            (false, ForkReason::BehindAll)
        );
        // 1 fails (one other <= mine) and 2 does not apply: the hash decides.
        assert_eq!(fork_mine_wins(true, 3, 5, &[3]), (true, ForkReason::Hash));
        assert_eq!(fork_mine_wins(false, 3, 5, &[3]), (false, ForkReason::Hash));
        // 2: theirs < mine and every other > theirs: I win, even if my hash loses.
        assert_eq!(
            fork_mine_wins(false, 5, 3, &[4]),
            (true, ForkReason::TheyBehindAll)
        );
        assert_eq!(fork_mine_wins(false, 5, 3, &[3]), (false, ForkReason::Hash));
        // Equal epochs: the hash.
        assert_eq!(fork_mine_wins(true, 4, 4, &[9]), (true, ForkReason::Hash));
    }
}
