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

use crate::Result;

/// A bridge kind: the seam between the core's configuration and one adapter.
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
