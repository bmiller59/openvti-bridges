//! A trivial in-memory [`ForeignRoom`]: proves the core does not depend on any
//! foreign system. Posts are recorded; injected events are served by `poll`.
//! It supports everything and delivers instantly.

use crate::foreign::{
    Cursor, ForeignIdentity, ForeignRoom, JoinState, Polled, Posted, Receipt, RoomCapabilities,
    Verifiability,
};
use crate::model::{AuthorCheck, BridgeEvent, EventKind, Origin, Provenance};
use crate::{Error, Result};
use async_trait::async_trait;
use std::sync::Mutex;

#[derive(Default)]
struct Inner {
    joined: bool,
    /// Seating answers `Pending` until cleared.
    pending: bool,
    /// Every call fails with `Refused` (seating refused or leaf removed).
    refused: Option<String>,
    /// Every post fails: `Some(true)` with a permanent (`Wire`) error,
    /// `Some(false)` with a transient (`Foreign`) one.
    fail_posts: Option<bool>,
    inbox: Vec<BridgeEvent>,
    posted: Vec<BridgeEvent>,
}

/// In-memory foreign room.
pub struct Loopback {
    id: String,
    inner: Mutex<Inner>,
}

impl Loopback {
    /// A room the bridge presents itself in as `id`.
    pub fn new(id: &str) -> Self {
        Self {
            id: id.into(),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Inject a message as a foreign member.
    pub fn inject(&self, author: &str, text: &str, at: u64) -> Result<()> {
        let mut g = self.lock()?;
        let n = g.inbox.len();
        let hash = format!("loop{n}");
        g.inbox.push(BridgeEvent {
            origin: Origin::Foreign,
            origin_id: hash.clone(),
            link: String::new(),
            author: author.into(),
            at,
            title: None,
            text: text.into(),
            kind: EventKind::Post,
            reply_to: None,
            record_key: None,
            provenance: Some(Provenance {
                foreign_room: "loopback".into(),
                author_device: author.into(),
                check: AuthorCheck::Verified,
                original_at: at,
                msg_hash: hash,
            }),
        });
        Ok(())
    }

    /// Make joining answer `Pending` (an "ask" room) until `false`.
    pub fn set_pending(&self, pending: bool) -> Result<()> {
        self.lock()?.pending = pending;
        Ok(())
    }

    /// Refuse the bridge from now on.
    pub fn refuse(&self, why: &str) -> Result<()> {
        self.lock()?.refused = Some(why.into());
        Ok(())
    }

    /// Make every post fail from now on (`None` stops): permanently
    /// (`Some(true)`, a `Wire` error that cannot succeed) or transiently
    /// (`Some(false)`, a `Foreign` error a later try may pass).
    pub fn fail_posts(&self, permanent: Option<bool>) -> Result<()> {
        self.lock()?.fail_posts = permanent;
        Ok(())
    }

    /// Everything the bridge posted.
    pub fn posted(&self) -> Vec<BridgeEvent> {
        self.inner
            .lock()
            .map(|g| g.posted.clone())
            .unwrap_or_default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| Error::Foreign("poisoned".into()))
    }
}

fn index_of(c: &Cursor) -> usize {
    c.0.as_slice()
        .try_into()
        .map(u64::from_be_bytes)
        .unwrap_or(0) as usize
}

#[async_trait]
impl ForeignRoom for Loopback {
    async fn join(&self) -> Result<JoinState> {
        let mut g = self.lock()?;
        if let Some(why) = &g.refused {
            return Err(Error::Refused(why.clone()));
        }
        if g.pending {
            return Ok(JoinState::Pending);
        }
        g.joined = true;
        Ok(JoinState::Seated)
    }
    async fn leave(&self) -> Result<()> {
        self.lock()?.joined = false;
        Ok(())
    }
    async fn poll(&self, after: Option<&Cursor>) -> Result<Vec<Polled>> {
        let g = self.lock()?;
        if let Some(why) = &g.refused {
            return Err(Error::Refused(why.clone()));
        }
        let from = after.map(index_of).unwrap_or(0);
        Ok(g.inbox
            .iter()
            .enumerate()
            .skip(from)
            .map(|(i, e)| Polled {
                event: e.clone(),
                cursor: Cursor(((i + 1) as u64).to_be_bytes().to_vec()),
            })
            .collect())
    }
    async fn post(&self, event: &BridgeEvent) -> Result<Posted> {
        let mut g = self.lock()?;
        if let Some(why) = &g.refused {
            return Err(Error::Refused(why.clone()));
        }
        if !g.joined {
            return Err(Error::Foreign("not joined".into()));
        }
        match g.fail_posts {
            Some(true) => return Err(Error::Wire("a line that cannot be encoded".into())),
            Some(false) => return Err(Error::Foreign("relay unreachable".into())),
            None => {}
        }
        let foreign_ref = format!("lbline{}", g.posted.len());
        g.posted.push(event.clone());
        Ok(Posted {
            receipt: Receipt::Delivered,
            foreign_ref: Some(foreign_ref),
        })
    }
    fn identity(&self) -> ForeignIdentity {
        ForeignIdentity {
            id: self.id.clone(),
        }
    }
    fn capabilities(&self) -> RoomCapabilities {
        RoomCapabilities {
            max_message_units: 1_000_000,
            supports_edit: true,
            supports_delete: true,
            supports_replies: true,
            authors_verifiable: Verifiability::Transport,
        }
    }
}
