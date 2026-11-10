//! The bridge kinds this binary was built with.

use crate::Result;
use crate::adapter::Kinds;
use crate::config::Config;

/// Every kind compiled into this build.
pub fn kinds() -> Kinds<'static> {
    static KINDS: [&dyn crate::adapter::BridgeKind; 1] = [&crate::geb::KIND];
    &KINDS
}

/// Read a config file and check it against the kinds of this build.
pub fn load_config(path: &std::path::Path) -> Result<Config> {
    let cfg = Config::load(path)?;
    cfg.validate_kinds(kinds())
        .map_err(|e| crate::Error::Config(format!("{}: {e}", path.display())))?;
    Ok(cfg)
}
