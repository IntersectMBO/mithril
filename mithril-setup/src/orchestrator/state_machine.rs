//! Pure state machine example: discover and fill a store, let the user edit it, then save it.
//!
//! The `transition` function is the pure core: it never does I/O and only describes the I/O it
//! needs as an `Effect`. The `execute` and `run` functions are the shell: they perform the effects
//! and feed their results back to the core as events.

use std::io;

use crate::orchestrator::store::{Field, FieldType, Store};

/// Where the flow is, with the data known at that point
#[derive(Debug, Clone, PartialEq)]
enum State {
    /// The flow is not started yet
    Idle,

    /// Waiting for the result of the field discovery
    Discovering,

    /// Waiting for the user to edit or confirm the field
    Reviewing { store: Store },

    /// Waiting for the result of the field saving
    Saving { store: Store },

    /// The field is saved
    Done,

    /// The flow failed, with the reason of the failure
    Failed(String),
}

impl State {
    /// Whether the flow reached a state it never leaves
    fn is_finished(&self) -> bool {
        matches!(self, State::Done | State::Failed(_))
    }
}

/// Something that happened, sent by the user or produced by an effect

#[derive(Debug, Clone, PartialEq)]

enum Event {
    /// The user started the flow
    Started,

    /// The Store discovery finished or the reason of its failure
    Discovered(Result<Store, String>),

    /// The user replaced the proposed store in the store
    StoreEdited(Store),

    /// The user confirmed the proposed Field
    Confirmed,

    /// The Field saving finished, or the reason of its failure
    Saved(Result<(), String>),
}

/// Description of the I/O requested by the core, performed by the shell

#[derive(Debug, Clone, PartialEq)]

enum Effect {
    /// Discover the store
    DiscoverStore,

    /// Write the given store to a file
    SaveStore(Store),
}

/// Apply an event to a state and return the next state with the effect to perform, if any
///
/// Pure: no I/O, and the given state is left unchanged. An event that is not accepted in the
/// given state returns an error.
fn transition(state: &State, event: Event) -> Result<(State, Option<Effect>), String> {
    match (state, event) {
        (State::Idle, Event::Started) => Ok((State::Discovering, Some(Effect::DiscoverStore))),

        (State::Discovering, Event::Discovered(Ok(store))) => {
            Ok((State::Reviewing { store }, None))
        }

        (State::Discovering, Event::Discovered(Err(reason))) => Ok((State::Failed(reason), None)),

        (State::Reviewing { .. }, Event::StoreEdited(store)) => {
            Ok((State::Reviewing { store }, None))
        }

        (State::Reviewing { store }, Event::Confirmed) => Ok((
            State::Saving {
                store: store.clone(),
            },
            Some(Effect::SaveStore(store.clone())),
        )),

        (State::Saving { .. }, Event::Saved(Ok(()))) => Ok((State::Done, None)),

        (State::Saving { .. }, Event::Saved(Err(reason))) => Ok((State::Failed(reason), None)),

        (state, event) => Err(format!("{event:?} is not accepted in {state:?}")),
    }
}

/// Perform an effect and return the event holding its result
fn execute(effect: Effect) -> Event {
    match effect {
        Effect::DiscoverStore => {
            let discovered_store = Store::new(vec![Field {
                name: "Color".to_string(),
                default: Some("Blue".to_string()),
                description: "desc".to_string(),
                kind: FieldType::String,
                value: None,
            }]);
            Event::Discovered(Ok(discovered_store))
        }

        Effect::SaveStore(store) => Event::Saved(
            std::fs::write(std::env::temp_dir().join("name.txt"), "TODO")
                .map_err(|e| e.to_string()),
        ),
    }
}

/// Apply an event, then perform the effects until the flow waits for the next user event
fn run(state: &State, event: Event, execute: impl Fn(Effect) -> Event) -> Result<State, String> {
    let (mut state, mut effect) = transition(state, event)?;

    while let Some(pending) = effect {
        (state, effect) = transition(&state, execute(pending))?;
    }

    Ok(state)
}

/// Turn a line typed by the user into an event: an empty line confirms, any other text is the new name
// fn user_event(field_name: &str, line: &str) -> Event {
//     match line.trim() {
//         "" => Event::Confirmed,

//         name => {
//             field_to_edit =
//             Event::FieldEdited(name.to_string())
//         },
//     }
// }

// /// Start the flow, then apply the lines typed by the user until the flow is finished
// fn main() -> Result<(), String> {
//     let mut state = run(&State::Idle, Event::Started, execute)?;

//     while !state.is_finished() {
//         println!("{state:?} (type a new name, or press Enter to confirm)");

//         let mut line = String::new();

//         io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;

//         state = run(&state, user_event(&line), execute)?;
//     }

//     println!("{state:?}");

//     Ok(())
// }

#[cfg(test)]

mod tests {

    use super::*;

    #[test]

    fn started_asks_for_the_discovery() {
        let (state, effect) = transition(&State::Idle, Event::Started).unwrap();

        assert_eq!(State::Discovering, state);

        assert_eq!(Some(Effect::DiscoverStore), effect);
    }

    #[test]

    fn confirmed_asks_to_save_the_reviewed_name() {
        let reviewing = State::Reviewing {
            store: Store::new(vec![Field::init(
                "name".to_string(),
                "user name".to_string(),
                FieldType::String,
                Some("bob".to_string()),
            )]),
        };

        let (state, effect) = transition(&reviewing, Event::Confirmed).unwrap();

        assert_eq!(
            State::Saving {
                store: Store::new(vec![Field::init(
                    "name".to_string(),
                    "user name".to_string(),
                    FieldType::String,
                    Some("bob".to_string()),
                )]),
            },
            state
        );

        assert_eq!(
            Some(Effect::SaveStore(Store::new(vec![Field::init(
                "name".to_string(),
                "user name".to_string(),
                FieldType::String,
                Some("bob".to_string()),
            )]),)),
            effect
        );
    }

    #[test]

    fn a_failed_discovery_fails_the_setup() {
        let (state, _) = transition(
            &State::Discovering,
            Event::Discovered(Err("no USER".to_string())),
        )
        .unwrap();

        assert_eq!(State::Failed("no USER".to_string()), state);
    }

    #[test]

    fn an_unexpected_event_is_rejected() {
        assert!(transition(&State::Idle, Event::Confirmed).is_err());
    }

    #[test]

    fn replaying_the_events_rebuilds_the_same_state() {
        let events = vec![
            Event::Started,
            Event::Discovered(Ok(Store::new(vec![Field::init(
                "name".to_string(),
                "user name".to_string(),
                FieldType::String,
                Some("bob".to_string()),
            )]))),
            Event::StoreEdited(Store::new(vec![Field::init(
                "name".to_string(),
                "user name".to_string(),
                FieldType::String,
                Some("alice".to_string()),
            )])),
            Event::Confirmed,
            Event::Saved(Ok(())),
        ];

        let state = events
            .into_iter()
            .try_fold(State::Idle, |state, event| {
                transition(&state, event).map(|(next, _)| next)
            })
            .unwrap();

        assert_eq!(State::Done, state);
    }

    #[test]

    fn the_shell_can_be_replaced_by_a_fake() {
        let reviewing = run(&State::Idle, Event::Started, fake_execute).unwrap();

        let done = run(&reviewing, Event::Confirmed, fake_execute).unwrap();

        assert_eq!(
            State::Reviewing {
                store: Store::new(vec![Field::init(
                    "name".to_string(),
                    "user name".to_string(),
                    FieldType::String,
                    Some("carol".to_string()),
                )])
            },
            reviewing
        );

        assert_eq!(State::Done, done);
    }

    fn fake_execute(effect: Effect) -> Event {
        match effect {
            Effect::DiscoverStore => Event::Discovered(Ok(Store::new(vec![Field::init(
                "name".to_string(),
                "user name".to_string(),
                FieldType::String,
                Some("carol".to_string()),
            )]))),

            Effect::SaveStore(_) => Event::Saved(Ok(())),
        }
    }

    // #[test]

    // fn user_event_confirms_on_an_empty_line_and_edits_otherwise() {
    //     assert_eq!(Event::Confirmed, user_event("\n"));

    //     assert_eq!(
    //         Event::StoreEdited("alice".to_string()),
    //         user_event("alice\n")
    //     );
    // }
}
