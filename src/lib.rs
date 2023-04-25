pub mod did;
pub mod document;
pub mod jwk;
pub mod multibase;
pub mod registry;
pub mod string;
pub mod time;
pub mod url;

pub mod prelude {
    // NOTE we did not include the string methods as they will pollute global namespace poorly
    pub use crate::{did::*, document::*, jwk::*, multibase::*, registry::*, time::*, url::*};
}
