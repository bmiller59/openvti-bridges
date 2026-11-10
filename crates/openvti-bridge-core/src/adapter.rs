//! What the core asks of a bridge kind (an adapter), and nothing more.
//!
//! A kind is named by a stable lower-kebab string (`geb`, `loopback`). Its
//! settings live in two operator-visible places the core does not interpret:
//! `[bridges.<kind>]` (global to the kind) and `[links.<kind>]` (one link's
//! own table). The core hands the raw table to the kind, which parses it with
//! its own `deny_unknown_fields` types.
//!
//! The trait has default methods only, so adding a method later is not a
//! breaking change for an implementer.

use crate::config::LinkConfig;
use crate::foreign::ForeignRoom;
use crate::secrets::{KeyMinter, LinkSecrets};
use crate::store::BridgeStore;
use crate::{Error, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;

/// An operator verb a kind adds under `bridge <kind> <verb>`.
#[derive(Debug, Clone, Copy)]
pub struct VerbSpec {
    /// The verb, lower-kebab.
    pub name: &'static str,
    /// One line of help.
    pub help: &'static str,
    /// The positional arguments, for the usage line (`<did>`).
    pub args: &'static str,
}

/// What a verb returns: lines to print, and values to remember in the link's
/// own `[links.<kind>]` table (each appended to the list under its key unless
/// already there).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VerbResult {
    /// Printed, one per line.
    pub lines: Vec<String>,
    /// `(key, value)` pairs appended to the link's kind table.
    pub remember: Vec<(String, String)>,
}

/// Everything the core hands a kind to build one link.
pub struct LinkCtx {
    /// The link's configuration.
    pub link: LinkConfig,
    /// The kind's `[bridges.<kind>]` table (empty when absent).
    pub global: toml::Table,
    /// The link's secrets.
    pub secrets: LinkSecrets,
    /// The secret-store key at-rest keys derive from.
    pub store_key: zeroize::Zeroizing<[u8; 32]>,
    /// The link's directory.
    pub dir: PathBuf,
    /// The link's store with state records sealed at rest.
    pub store: Arc<dyn BridgeStore>,
}

/// A link's foreign side, built.
pub struct BuiltLink {
    /// The foreign room the pump posts through.
    pub foreign: Arc<dyn ForeignRoom>,
    /// The kind's operator verbs for this link.
    pub handle: Arc<dyn AdapterHandle>,
}

/// A built link's operator verbs.
#[async_trait]
pub trait AdapterHandle: Send + Sync {
    /// Run `verb`. The shell has already refused a paused or halted link.
    async fn verb(&self, name: &str, _args: &[String]) -> Result<VerbResult> {
        Err(Error::Config(format!("no such verb {name:?}")))
    }
}

/// A handle with no verbs.
pub struct NoVerbs;

#[async_trait]
impl AdapterHandle for NoVerbs {}

/// A bridge kind: the seam between the core's configuration and one adapter.
#[async_trait]
pub trait BridgeKind: Send + Sync {
    /// The stable name: config `kind`, the table names, and the state prefix.
    fn kind(&self) -> &'static str;

    /// One line saying what the kind bridges to.
    fn describe(&self) -> &'static str;

    /// Check the `[bridges.<kind>]` table. The default accepts only an empty
    /// table: a kind with no global settings refuses an unknown key.
    fn validate_global(&self, table: &toml::Table) -> Result<()> {
        if table.is_empty() {
            Ok(())
        } else {
            Err(crate::Error::Config(format!(
                "[bridges.{}] takes no settings",
                self.kind()
            )))
        }
    }

    /// Check one link's `[links.<kind>]` table.
    fn validate_link(&self, table: &toml::Table) -> Result<()>;

    /// The key naming the foreign room this link bridges, compared across the
    /// links of this kind so one foreign room is bridged by one link.
    fn foreign_room_key(&self, table: &toml::Table) -> Result<String>;

    /// The longest `display_name` (in characters) the foreign system accepts,
    /// if it limits one.
    fn max_display_name(&self) -> Option<usize> {
        None
    }

    /// What `status` prints for the kind (its pinned reading of the foreign
    /// system). Defaults to the description.
    fn pinned_reading(&self) -> String {
        self.describe().into()
    }

    /// Render the foreign cursor `status` shows (the default is hex).
    fn describe_cursor(&self, raw: &[u8]) -> String {
        hex::encode(raw)
    }

    /// Extra `status` lines for a link, read from its store alone (status has
    /// no keys).
    async fn status_lines(&self, _store: &dyn BridgeStore) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// The operator verbs of `bridge <kind> <verb>`.
    fn verbs(&self) -> &'static [VerbSpec] {
        &[]
    }

    /// The halt codes the kind may raise with `Error::adapter_halt`, each with
    /// what it means (the census test holds every raised code to this list).
    fn halt_codes(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// Mint the kind's secrets for a new link. The default is a link with no
    /// adapter secret.
    async fn mint_link_secrets(
        &self,
        _minter: &dyn KeyMinter,
        _context: &str,
        link: &LinkConfig,
    ) -> Result<LinkSecrets> {
        Ok(LinkSecrets::new(&link.persona))
    }

    /// One line naming what setup minted for a link (a device DID), if any.
    fn describe_secrets(&self, _secrets: &LinkSecrets) -> Option<String> {
        None
    }

    /// Build one link's foreign side.
    async fn build(&self, _ctx: &LinkCtx) -> Result<BuiltLink> {
        Err(Error::Unsupported("this kind builds no link"))
    }
}

/// The kinds a binary was built with.
pub type Kinds<'a> = &'a [&'a dyn BridgeKind];

/// Find a kind by name.
pub fn find<'a>(kinds: Kinds<'a>, kind: &str) -> Option<&'a dyn BridgeKind> {
    kinds.iter().copied().find(|k| k.kind() == kind)
}

/// The enabled kind names, for an error message.
pub fn names(kinds: Kinds<'_>) -> String {
    let v: Vec<&str> = kinds.iter().map(|k| k.kind()).collect();
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}
