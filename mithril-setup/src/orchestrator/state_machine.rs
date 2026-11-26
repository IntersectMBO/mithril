//! State machine of the orchestrator

use crate::schema::FieldError;
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

    /// Showing the result of the saved values, kept to go back to their review
    ShowingResult(Store),

    /// Showing why the values could not be saved, kept to go back to their review
    ShowingFailure {
        /// Values that could not be saved
        store: Store,
        /// Reason of the save failure, the reason of the flow failure if the user exits
        reason: String,
    },

    /// Final state, the orchestrator has finished its work
    Done,

    /// Error state, the orchestrator has failed to complete its work
    Failed(String),

    /// Final state, the user aborted the flow
    Aborted,
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

    /// The user reviewed and confirmed the store, or the reason of the review failure
    Reviewed(Result<Store, String>),

    /// The reviewed store is valid, or the list of validation errors
    Validated(Result<(), Vec<FieldError>>),

    /// The Store saving finished, or the reason of its failure
    Saved(Result<(), String>),

    /// The user closed the result or the failure, or the reason of their display failure
    ResultShown(Result<(), String>),

    /// The user went back from the result or the failure to the review of the values
    WentBack,

    /// The user aborted the flow
    Aborted,
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
        errors: Vec<FieldError>,
    },

    /// Check the integrity of the values
    Validate(Store),

    /// Save the values to the desired output
    Save(Store),

    /// Show the result of the saved values to the user
    ShowResult,

    /// Show to the user why the values could not be saved
    ShowFailure(String),
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

        (State::Reviewing(_), Event::Reviewed(Ok(store))) => Ok((
            State::Validating(store.clone()),
            Some(Effect::Validate(store)),
        )),

        (State::Reviewing(_), Event::Reviewed(Err(reason))) => Ok((State::Failed(reason), None)),

        (State::Validating(store), Event::Validated(Ok(()))) => Ok((
            State::Saving(store.clone()),
            Some(Effect::Save(store.clone())),
        )),

        (State::Validating(store), Event::Validated(Err(errors))) => Ok((
            State::Reviewing(store.clone()),
            Some(Effect::Review {
                store: store.clone(),
                errors,
            }),
        )),

        (State::Saving(store), Event::Saved(Ok(()))) => Ok((
            State::ShowingResult(store.clone()),
            Some(Effect::ShowResult),
        )),

        (State::Saving(store), Event::Saved(Err(reason))) => Ok((
            State::ShowingFailure {
                store: store.clone(),
                reason: reason.clone(),
            },
            Some(Effect::ShowFailure(reason)),
        )),

        (State::ShowingResult(_), Event::ResultShown(Ok(()))) => Ok((State::Done, None)),

        (State::ShowingResult(_), Event::ResultShown(Err(reason))) => {
            Ok((State::Failed(reason), None))
        }

        (State::ShowingFailure { reason, .. }, Event::ResultShown(Ok(()))) => {
            Ok((State::Failed(reason.clone()), None))
        }

        // The save failure is kept, it is the reason the failure was shown
        (State::ShowingFailure { reason, .. }, Event::ResultShown(Err(display_reason))) => Ok((
            State::Failed(format!(
                "{reason} (the failure could not be shown: {display_reason})"
            )),
            None,
        )),

        (State::ShowingResult(store) | State::ShowingFailure { store, .. }, Event::WentBack) => {
            Ok((
                State::Reviewing(store.clone()),
                Some(Effect::Review {
                    store: store.clone(),
                    errors: vec![],
                }),
            ))
        }

        (State::Done | State::Failed(_) | State::Aborted, Event::Aborted) => Err(format!(
            "{:?} is not accepted in final state {state:?}",
            Event::Aborted
        )),

        (_, Event::Aborted) => Ok((State::Aborted, None)),

        (state, event) => Err(format!("{event:?} is not accepted in {state:?}")),
    }
}

#[cfg(test)]
mod tests {
    use crate::store::Origin;

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
        let result = transition(&State::Reviewing(store()), Event::Reviewed(Ok(store())));

        assert_eq!(
            Ok((State::Validating(store()), Some(Effect::Validate(store())))),
            result
        );
    }

    #[test]
    fn reviewing_reviewed_err_goes_to_failed() {
        let result = transition(
            &State::Reviewing(store()),
            Event::Reviewed(Err("boom".to_string())),
        );

        assert_eq!(Ok((State::Failed("boom".to_string()), None)), result);
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
        let errors = vec![FieldError::new("key", "invalid field")];
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
    fn saving_saved_ok_goes_to_showing_result_and_requests_result_display() {
        let result = transition(&State::Saving(store()), Event::Saved(Ok(())));

        assert_eq!(
            Ok((State::ShowingResult(store()), Some(Effect::ShowResult))),
            result
        );
    }

    #[test]
    fn showing_result_result_shown_ok_goes_to_done() {
        let result = transition(&State::ShowingResult(store()), Event::ResultShown(Ok(())));

        assert_eq!(Ok((State::Done, None)), result);
    }

    #[test]
    fn showing_result_result_shown_err_goes_to_failed() {
        let result = transition(
            &State::ShowingResult(store()),
            Event::ResultShown(Err("boom".to_string())),
        );

        assert_eq!(Ok((State::Failed("boom".to_string()), None)), result);
    }

    #[test]
    fn showing_result_or_failure_went_back_goes_to_reviewing_the_store_without_errors() {
        let mut saved_store = Store::default();
        saved_store.set("network", "preview", Origin::User);

        for state in [
            State::ShowingResult(saved_store.clone()),
            State::ShowingFailure {
                store: saved_store.clone(),
                reason: "boom".to_string(),
            },
        ] {
            let result = transition(&state, Event::WentBack);

            assert_eq!(
                Ok((
                    State::Reviewing(saved_store.clone()),
                    Some(Effect::Review {
                        store: saved_store.clone(),
                        errors: vec![]
                    })
                )),
                result,
                "from {state:?}"
            );
        }
    }

    fn showing_failure() -> State {
        State::ShowingFailure {
            store: store(),
            reason: "boom".to_string(),
        }
    }

    #[test]
    fn showing_failure_result_shown_ok_goes_to_failed_with_the_save_failure_reason() {
        let result = transition(&showing_failure(), Event::ResultShown(Ok(())));

        assert_eq!(Ok((State::Failed("boom".to_string()), None)), result);
    }

    #[test]
    fn showing_failure_result_shown_err_goes_to_failed_with_both_reasons() {
        let result = transition(
            &showing_failure(),
            Event::ResultShown(Err("no terminal".to_string())),
        );

        assert_eq!(
            Ok((
                State::Failed("boom (the failure could not be shown: no terminal)".to_string()),
                None
            )),
            result
        );
    }

    #[test]
    fn went_back_is_rejected_outside_of_showing_result() {
        let result = transition(&State::Saving(store()), Event::WentBack);

        assert!(result.is_err(), "Expected Err, got {result:?}");
    }

    #[test]
    fn saving_saved_err_goes_to_showing_failure_and_requests_failure_display() {
        let result = transition(
            &State::Saving(store()),
            Event::Saved(Err("boom".to_string())),
        );

        assert_eq!(
            Ok((
                showing_failure(),
                Some(Effect::ShowFailure("boom".to_string()))
            )),
            result
        );
    }

    #[test]
    fn aborted_goes_to_aborted_from_any_non_final_state() {
        for state in [
            State::Idle,
            State::Discovering,
            State::Guessing(store()),
            State::Reviewing(store()),
            State::Validating(store()),
            State::Saving(store()),
            State::ShowingResult(store()),
            showing_failure(),
        ] {
            let result = transition(&state, Event::Aborted);

            assert_eq!(Ok((State::Aborted, None)), result, "from {state:?}");
        }
    }

    #[test]
    fn aborted_is_rejected_from_final_states() {
        for state in [State::Done, State::Failed("boom".to_string()), State::Aborted] {
            let result = transition(&state, Event::Aborted);

            assert!(
                result.is_err(),
                "Expected Err from {state:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn unexpected_event_is_rejected() {
        let result = transition(&State::Idle, Event::Saved(Ok(())));

        assert!(result.is_err(), "Expected Err, got {result:?}");
    }
}
