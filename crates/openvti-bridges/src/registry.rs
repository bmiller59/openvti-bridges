//! The bridge kinds this binary was built with.

use crate::Result;
use openvti_bridge_core::adapter::{BridgeKind, Kinds};
use openvti_bridge_core::config::Config;

/// Every kind compiled into this build (cargo features `geb`, `loopback`).
pub fn kinds() -> Kinds<'static> {
    static KINDS: &[&dyn BridgeKind] = &[
        #[cfg(feature = "geb")]
        &openvti_bridge_geb::KIND,
        #[cfg(feature = "loopback")]
        &openvti_bridge_core::loopback::KIND,
    ];
    KINDS
}

/// The kind a link names, from this build's registry.
pub fn kind_of(name: &str) -> Result<&'static dyn BridgeKind> {
    openvti_bridge_core::adapter::find(kinds(), name).ok_or_else(|| {
        openvti_bridge_core::Error::Config(format!(
            "bridge kind {name:?} is not built into this binary (built: {})",
            openvti_bridge_core::adapter::names(kinds())
        ))
    })
}

/// Read a config file and check it against the kinds of this build.
pub fn load_config(path: &std::path::Path) -> Result<Config> {
    let cfg = Config::load(path)?;
    cfg.validate_kinds(kinds())
        .map_err(|e| crate::Error::Config(format!("{}: {e}", path.display())))?;
    Ok(cfg)
}
