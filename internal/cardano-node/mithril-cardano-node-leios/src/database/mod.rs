//! Access to the `leios.imm.db` database of a Cardano node through layout adapters.
//!
//! One adapter per node database layout implements [LeiosImmutableDatabaseLayout]: it is the only
//! code that knows the tables, columns and encodings of its layout.

mod layout;
mod layout_rc_2026w44;
mod leios_immutable_database;

pub use layout::*;
pub use layout_rc_2026w44::*;
pub use leios_immutable_database::*;
