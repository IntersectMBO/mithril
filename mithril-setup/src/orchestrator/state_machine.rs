//! State machine of the orchestrator

use crate::store::Store;

/// States of the orchestrator
#[derive(Debug, Clone, PartialEq)]
pub enum State {
    /// Starting point
    Idle,

    /// Discovering fields's values from the environment
    Discovering,

    /// Guessing fields's values from the previous discovering state
    Guessing(Store),

    /// Interacting with the user to confirm or modify the values
    Reviewing(Store),

    /// Checking the integrity of the reviewed values
    Validating(Store),

    /// Saving the values to the desired output
    Saving(Store),

    /// Final state, the orchestrator has finished its work
    Done,

    /// Error state, the orchestrator has failed to complete its work
    Failed(String), //TODO typed errors ?
}

/// Events to transition to another state
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// The user started the flow
    Started,

    /// The environment has been discovered, or the reason of its failure
    Discovered(Result<Store, String>),

    /// Fields values have been guessed from the discovered ones, or the reason of its failure
    Guessed(Result<Store, String>),

    /// The user reviewed and confirmed the store
    Reviewed(Store),

    /// The reviewed store is valid, or the list of validation errors
    Validated(Result<(), Vec<String>>),

    /// The Store saving finished, or the reason of its failure
    Saved(Result<(), String>),
}

/// Description of the I/O requested by the core, performed by the shell
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Discover the fields's values from the environment
    Discover,

    /// Guess the fields's values from the discovered ones
    Guess(Store),

    /// Interact with the user to confirm or modify the values
    Review {
        /// Store to review
        store: Store,
        /// Validation errors of a previous review, empty on the first review
        errors: Vec<String>,
    },

    /// Check the integrity of the values
    Validate(Store),

    /// Save the values to the desired output
    Save(Store),
}

/// Transition function to move from one state to another based on the event
pub fn transition(state: &State, event: Event) -> Result<(State, Option<Effect>), String> {
    match (state, event) {
        (State::Idle, Event::Started) => Ok((State::Discovering, Some(Effect::Discover))),

        (State::Discovering, Event::Discovered(Ok(store))) => {
            Ok((State::Guessing(store.clone()), Some(Effect::Guess(store))))
        }

        (State::Discovering, Event::Discovered(Err(reason))) => Ok((State::Failed(reason), None)),

        (State::Guessing(_), Event::Guessed(Ok(store))) => Ok((
            State::Reviewing(store.clone()),
            Some(Effect::Review {
                store,
                errors: vec![],
            }),
        )),

        (State::Guessing(_), Event::Guessed(Err(reason))) => Ok((State::Failed(reason), None)),

        (State::Reviewing(_), Event::Reviewed(store)) => Ok((
            State::Validating(store.clone()),
            Some(Effect::Validate(store)),
        )),

        (State::Validating(store), Event::Validated(Ok(()))) => {
            Ok((State::Saving(store.clone()), Some(Effect::Save(store.clone()))))
        }

        (State::Validating(store), Event::Validated(Err(errors))) => Ok((
            State::Reviewing(store.clone()),
            Some(Effect::Review {
                store: store.clone(),
                errors,
            }),
        )),

        (State::Saving(_), Event::Saved(Ok(()))) => Ok((State::Done, None)),

        (State::Saving(_), Event::Saved(Err(reason))) => Ok((State::Failed(reason), None)),

        (state, event) => Err(format!("{event:?} is not accepted in {state:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::default()
    }

    #[test]
    fn idle_started_goes_to_discovering_and_requests_discovery() {
        let result = transition(&State::Idle, Event::Started);

        assert_eq!(Ok((State::Discovering, Some(Effect::Discover))), result);
    }

    #[test]
    fn discovering_discovered_ok_goes_to_guessing_and_requests_guess() {
        let result = transition(&State::Discovering, Event::Discovered(Ok(store())));

        assert_eq!(
            Ok((State::Guessing(store()), Some(Effect::Guess(store())))),
            result
        );
    }

    #[test]
    fn discovering_discovered_err_goes_to_failed() {
        let result = transition(
            &State::Discovering,
            Event::Discovered(Err("boom".to_string())),
        );

        assert_eq!(Ok((State::Failed("boom".to_string()), None)), result);
    }

    #[test]
    fn guessing_guessed_ok_goes_to_reviewing_and_requests_review_without_errors() {
        let result = transition(&State::Guessing(store()), Event::Guessed(Ok(store())));

        assert_eq!(
            Ok((
                State::Reviewing(store()),
                Some(Effect::Review {
                    store: store(),
                    errors: vec![]
                })
            )),
            result
        );
    }

    #[test]
    fn guessing_guessed_err_goes_to_failed() {
        let result = transition(
            &State::Guessing(store()),
            Event::Guessed(Err("boom".to_string())),
        );

        assert_eq!(Ok((State::Failed("boom".to_string()), None)), result);
    }

    #[test]
    fn reviewing_reviewed_goes_to_validating_and_requests_validation() {
        let result = transition(&State::Reviewing(store()), Event::Reviewed(store()));

        assert_eq!(
            Ok((State::Validating(store()), Some(Effect::Validate(store())))),
            result
        );
    }

    #[test]
    fn validating_validated_ok_goes_to_saving_and_requests_save() {
        let result = transition(&State::Validating(store()), Event::Validated(Ok(())));

        assert_eq!(
            Ok((State::Saving(store()), Some(Effect::Save(store())))),
            result
        );
    }

    #[test]
    fn validating_validated_err_goes_back_to_reviewing_with_errors() {
        let errors = vec!["invalid field".to_string()];
        let result = transition(
            &State::Validating(store()),
            Event::Validated(Err(errors.clone())),
        );

        assert_eq!(
            Ok((
                State::Reviewing(store()),
                Some(Effect::Review {
                    store: store(),
                    errors
                })
            )),
            result
        );
    }

    #[test]
    fn saving_saved_ok_goes_to_done() {
        let result = transition(&State::Saving(store()), Event::Saved(Ok(())));

        assert_eq!(Ok((State::Done, None)), result);
    }

    #[test]
    fn saving_saved_err_goes_to_failed() {
        let result = transition(
            &State::Saving(store()),
            Event::Saved(Err("boom".to_string())),
        );

        assert_eq!(Ok((State::Failed("boom".to_string()), None)), result);
    }

    #[test]
    fn unexpected_event_is_rejected() {
        let result = transition(&State::Idle, Event::Saved(Ok(())));

        assert!(result.is_err(), "Expected Err, got {result:?}");
    }
}
