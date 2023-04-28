/// Decentralized Identifier syntax parsing and generation
pub mod did;
/// Decentralized Identity Document typing and (de)-serialization
pub mod document;
/// JSON Web Key management
pub mod jwk;
/// Multibase public key management
pub mod multibase;
/// In-Memory Registry for Decentralized Identity Documents, with some database-like features.
pub mod registry;
/// String handling routines; not included in prelude, should avoid using publicly.
pub mod string;
/// VersionTime [crate::url::URL] parameter handling
pub mod time;
/// DID URLs, a way to inter-link to [crate::did::DID]s.
pub mod url;

/// Convenience module for exporting all public types
pub mod prelude {
    // NOTE we did not include the string methods as they will pollute global namespace poorly
    pub use crate::{did::*, document::*, jwk::*, multibase::*, registry::*, time::*, url::*};
}
