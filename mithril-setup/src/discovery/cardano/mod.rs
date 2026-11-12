//! Discovery of the Cardano block producer node running on the machine
//!
//! The [CardanoDiscoverer] holds the runtime agnostic logic, it observes the machine through
//! the probe traits ([ProcessProbe], [ServiceProbe] and [ToolProbe]) so that other runtimes
//! can be supported by providing other probe implementations.

mod command_line;
mod discoverer;
mod discovery;
pub mod host;
mod probes;

pub use discoverer::*;
pub use discovery::*;
pub use probes::*;
