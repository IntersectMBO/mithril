mod check;
mod context;
mod exec;
mod wait;

pub use check::*;
pub use context::*;
pub use exec::*;
pub use wait::*;

#[derive(Debug, Clone)]
pub struct ScenarioToolkit {
    /// Context shared by the toolkits, exposing the Cardano epoch timing.
    pub context: ScenarioToolkitContext,
    pub check: CheckToolkit,
    pub exec: ExecToolkit,
    pub wait: WaitToolkit,
}

impl ScenarioToolkit {
    pub fn new(context: ScenarioToolkitContext) -> Self {
        Self {
            check: CheckToolkit::new(context.clone()),
            exec: ExecToolkit::new(context.clone()),
            wait: WaitToolkit::new(context.clone()),
            context,
        }
    }
}
