//! Command to setup a Mithril signer

use anyhow::anyhow;
use clap::Parser;
use slog::info;

use crate::{
    CommandContext,
    orchestrator::state_machine::{Event, State, setup, transition},
    signer::orchestrator::SignerOrchestrator,
};

/// Set up a Mithril signer
#[derive(Parser, Debug, Clone)]
pub struct SignerCommand {}

impl SignerCommand {
    /// Main command execution
    pub async fn execute(&self, context: CommandContext) -> anyhow::Result<()> {
        context.require_unstable("signer", None)?;
        info!(context.logger(), "signer command");

        let orchestrator = SignerOrchestrator::new();
        let final_state = setup(&orchestrator, read_user_event).map_err(|e| anyhow!(e))?;

        match final_state {
            State::Failed(reason) => Err(anyhow!("Signer setup failed: {reason}")),
            state => {
                info!(context.logger(), "signer setup finished"; "state" => ?state);
                Ok(())
            }
        }
    }
}

/// Show the state to the user and ask for a line until it gives an event accepted by the state
fn read_user_event(state: &State) -> Event {
    loop {
        println!("{state:?}");
        println!("Type `name=value` to edit a field, or press Enter to confirm");

        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) => return Event::Confirmed,
            Ok(_) => {}
            Err(e) => {
                eprintln!("Can not read the user input: {e}");
                return Event::Confirmed;
            }
        }

        match accepted_user_event(state, &line) {
            Ok(event) => return event,
            Err(e) => eprintln!("{e}"),
        }
    }
}

/// Turn a line typed by the user into an event, only if the state machine accepts it in the state
fn accepted_user_event(state: &State, line: &str) -> anyhow::Result<Event> {
    let event = user_event(state, line)?;
    transition(state, event.clone()).map_err(|e| anyhow!(e))?;

    Ok(event)
}

/// Turn a line typed by the user into an event: an empty line confirms, `name=value` edits a field
fn user_event(state: &State, line: &str) -> anyhow::Result<Event> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(Event::Confirmed);
    }

    let State::Reviewing { store } = state else {
        return Err(anyhow!("Nothing to edit in {state:?}"));
    };
    let (name, value) = line
        .split_once('=')
        .ok_or_else(|| anyhow!("Expected `name=value`, got `{line}`"))?;

    let mut store = store.clone();
    store.user_update_field(name.trim(), value.trim().to_string())?;

    Ok(Event::StoreEdited(store))
}

#[cfg(test)]
mod tests {
    use crate::orchestrator::store::{Field, FieldState, FieldType, Store};

    use super::*;

    fn test_logger() -> slog::Logger {
        slog::Logger::root(slog::Discard, slog::o!())
    }

    fn reviewing_state() -> State {
        State::Reviewing {
            store: Store::new(vec![Field::init(
                "network".to_string(),
                "description".to_string(),
                FieldType::String,
                None,
            )]),
        }
    }

    #[tokio::test]
    async fn signer_command_returns_error_when_unstable_is_not_enabled() {
        let context = CommandContext::new(false, false, test_logger());
        let cmd = SignerCommand {};
        assert!(cmd.execute(context).await.is_err());
    }

    #[test]
    fn user_event_confirms_on_an_empty_line() {
        assert_eq!(
            Event::Confirmed,
            user_event(&reviewing_state(), "\n").unwrap()
        );
    }

    #[test]
    fn user_event_edits_the_field_filled_by_the_user() {
        let Event::StoreEdited(store) =
            user_event(&reviewing_state(), "network = preprod\n").unwrap()
        else {
            panic!("expected StoreEdited");
        };

        let network = store.get_field("network").unwrap();
        assert_eq!(Some("preprod".to_string()), network.value);
        assert_eq!(FieldState::FilledByUser, network.state);
    }

    #[test]
    fn accepted_user_event_rejects_an_event_the_state_machine_refuses() {
        assert!(accepted_user_event(&State::Idle, "\n").is_err());
    }

    #[test]
    fn accepted_user_event_confirms_only_when_all_the_fields_are_filled() {
        assert!(accepted_user_event(&reviewing_state(), "\n").is_err());

        let Event::StoreEdited(store) = user_event(&reviewing_state(), "network=preprod").unwrap()
        else {
            panic!("expected StoreEdited");
        };
        assert_eq!(
            Event::Confirmed,
            accepted_user_event(&State::Reviewing { store }, "\n").unwrap()
        );
    }

    #[test]
    fn user_event_rejects_an_unknown_field_or_a_malformed_line() {
        assert!(user_event(&reviewing_state(), "unknown=value").is_err());
        assert!(user_event(&reviewing_state(), "no equal sign").is_err());
    }
}
