//! Runner of the orchestrator: executes the effects requested by the state machine (imperative shell)

use async_trait::async_trait;

use crate::schema::FieldError;
use crate::state_machine::{Effect, Event, State, transition};
use crate::store::Store;

/// Outcome of the user review
#[derive(Debug, Clone, PartialEq)]
pub enum ReviewOutcome {
    /// The user confirmed the reviewed store
    Confirmed(Store),

    /// The user aborted the flow
    Aborted,
}

/// Outcome of the result or failure display
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultOutcome {
    /// The user closed the result or the failure, ending the flow
    Exit,

    /// The user went back to the review of the store
    Back,
}

/// Outcome of a run that did not fail
#[derive(Debug, Clone, PartialEq)]
pub enum RunOutcome {
    /// The flow completed
    Completed,

    /// The user aborted the flow
    Aborted,
}

/// Performs the I/O requested by the state machine effects
#[async_trait]
pub trait EffectHandler: Send + Sync {
    /// Discover the fields's values from the environment
    async fn discover(&self) -> Result<Store, String>;

    /// Guess the fields's values from the discovered ones
    async fn guess(&self, store: Store) -> Result<Store, String>;

    /// Let the user review the store, returns the confirmed store or the user abort,
    /// or the reason of the review failure
    async fn review(&self, store: Store, errors: Vec<FieldError>) -> Result<ReviewOutcome, String>;

    /// Check the integrity of the store
    async fn validate(&self, store: Store) -> Result<(), Vec<FieldError>>;

    /// Save the store to the desired output
    async fn export_to_artifact(&self, store: Store) -> Result<(), String>;

    /// Show the result of the setup, returns whether the user exits or goes back to the review,
    /// or the reason of the result display failure
    async fn show_result(&self) -> Result<ResultOutcome, String>;

    /// Show why the store could not be saved, returns whether the user exits or goes back to the
    /// review, or the reason of the failure display failure
    async fn show_failure(&self, reason: String) -> Result<ResultOutcome, String>;
}

/// Run the state machine until a final state, executing effects with the given handler
pub async fn run(handler: &dyn EffectHandler) -> Result<RunOutcome, String> {
    let (mut state, mut effect) = transition(&State::Idle, Event::Started)?;

    while let Some(current_effect) = effect {
        let event = execute(handler, current_effect).await;
        (state, effect) = transition(&state, event)?;
    }

    match state {
        State::Done => Ok(RunOutcome::Completed),
        State::Aborted => Ok(RunOutcome::Aborted),
        State::Failed(reason) => Err(reason),
        state => Err(format!(
            "Orchestrator stopped in a non final state: {state:?}"
        )),
    }
}

async fn execute(handler: &dyn EffectHandler, effect: Effect) -> Event {
    match effect {
        Effect::Discover => Event::Discovered(handler.discover().await),
        Effect::Guess(store) => Event::Guessed(handler.guess(store).await),
        Effect::Review { store, errors } => match handler.review(store, errors).await {
            Ok(ReviewOutcome::Confirmed(store)) => Event::Reviewed(Ok(store)),
            Ok(ReviewOutcome::Aborted) => Event::Aborted,
            Err(reason) => Event::Reviewed(Err(reason)),
        },
        Effect::Validate(store) => Event::Validated(handler.validate(store).await),
        Effect::Save(store) => Event::Saved(handler.export_to_artifact(store).await),
        Effect::ShowResult => match handler.show_result().await {
            Ok(ResultOutcome::Exit) => Event::ResultShown(Ok(())),
            Ok(ResultOutcome::Back) => Event::WentBack,
            Err(reason) => Event::ResultShown(Err(reason)),
        },
        Effect::ShowFailure(reason) => match handler.show_failure(reason).await {
            Ok(ResultOutcome::Exit) => Event::ResultShown(Ok(())),
            Ok(ResultOutcome::Back) => Event::WentBack,
            Err(reason) => Event::ResultShown(Err(reason)),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use crate::store::Origin;

    use super::*;

    struct FakeHandler {
        discover_result: Result<Store, String>,
        validate_results: Mutex<VecDeque<Result<(), Vec<FieldError>>>>,
        review_aborts: bool,
        review_failure: Option<String>,
        received_review_stores: Mutex<Vec<Store>>,
        received_review_errors: Mutex<Vec<Vec<FieldError>>>,
        save_results: Mutex<VecDeque<Result<(), String>>>,
        /// Outcomes of the result and failure screens, in the order they are shown
        result_outcomes: Mutex<VecDeque<Result<ResultOutcome, String>>>,
        received_failure_reasons: Mutex<Vec<String>>,
    }

    impl FakeHandler {
        fn succeeding() -> Self {
            Self {
                discover_result: Ok(Store::default()),
                validate_results: Mutex::new(VecDeque::new()),
                review_aborts: false,
                review_failure: None,
                received_review_stores: Mutex::new(vec![]),
                received_review_errors: Mutex::new(vec![]),
                save_results: Mutex::new(VecDeque::new()),
                result_outcomes: Mutex::new(VecDeque::new()),
                received_failure_reasons: Mutex::new(vec![]),
            }
        }
    }

    #[async_trait]
    impl EffectHandler for FakeHandler {
        async fn discover(&self) -> Result<Store, String> {
            self.discover_result.clone()
        }

        async fn guess(&self, store: Store) -> Result<Store, String> {
            Ok(store)
        }

        async fn review(
            &self,
            store: Store,
            errors: Vec<FieldError>,
        ) -> Result<ReviewOutcome, String> {
            self.received_review_stores.lock().unwrap().push(store.clone());
            self.received_review_errors.lock().unwrap().push(errors);
            if let Some(reason) = &self.review_failure {
                Err(reason.clone())
            } else if self.review_aborts {
                Ok(ReviewOutcome::Aborted)
            } else {
                // The user edits a value before confirming
                let mut confirmed_store = store;
                confirmed_store.set("edited", "by the user", Origin::User);
                Ok(ReviewOutcome::Confirmed(confirmed_store))
            }
        }

        async fn validate(&self, _store: Store) -> Result<(), Vec<FieldError>> {
            self.validate_results.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }

        async fn export_to_artifact(&self, _store: Store) -> Result<(), String> {
            self.save_results.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }

        async fn show_result(&self) -> Result<ResultOutcome, String> {
            self.next_result_outcome()
        }

        async fn show_failure(&self, reason: String) -> Result<ResultOutcome, String> {
            self.received_failure_reasons.lock().unwrap().push(reason);
            self.next_result_outcome()
        }
    }

    impl FakeHandler {
        fn next_result_outcome(&self) -> Result<ResultOutcome, String> {
            self.result_outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(ResultOutcome::Exit))
        }
    }

    #[tokio::test]
    async fn run_returns_completed_when_all_effects_succeed() {
        let handler = FakeHandler::succeeding();

        let result = run(&handler).await;

        assert_eq!(Ok(RunOutcome::Completed), result);
    }

    #[tokio::test]
    async fn run_returns_aborted_when_the_user_aborts_the_review() {
        let handler = FakeHandler {
            review_aborts: true,
            ..FakeHandler::succeeding()
        };

        let result = run(&handler).await;

        assert_eq!(Ok(RunOutcome::Aborted), result);
    }

    #[tokio::test]
    async fn run_returns_failure_reason_when_the_review_fails() {
        let handler = FakeHandler {
            review_failure: Some("no terminal".to_string()),
            ..FakeHandler::succeeding()
        };

        let result = run(&handler).await;

        assert_eq!(Err("no terminal".to_string()), result);
    }

    #[tokio::test]
    async fn run_returns_failure_reason_when_an_effect_fails() {
        let handler = FakeHandler {
            discover_result: Err("no cardano node".to_string()),
            ..FakeHandler::succeeding()
        };

        let result = run(&handler).await;

        assert_eq!(Err("no cardano node".to_string()), result);
    }

    #[tokio::test]
    async fn run_reviews_again_with_errors_when_validation_fails() {
        let validation_errors = vec![FieldError::new("key", "invalid field")];
        let handler = FakeHandler {
            validate_results: Mutex::new(VecDeque::from([Err(validation_errors.clone())])),
            ..FakeHandler::succeeding()
        };

        let result = run(&handler).await;

        assert_eq!(Ok(RunOutcome::Completed), result);
        assert_eq!(
            vec![vec![], validation_errors],
            *handler.received_review_errors.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn run_reviews_the_confirmed_store_again_when_the_user_goes_back_from_the_result() {
        // Back from the result screen after a save, and from the failure screen after a failed one
        for save_result in [Ok(()), Err("disk full".to_string())] {
            let handler = FakeHandler {
                save_results: Mutex::new(VecDeque::from([save_result.clone()])),
                result_outcomes: Mutex::new(VecDeque::from([Ok(ResultOutcome::Back)])),
                ..FakeHandler::succeeding()
            };

            let result = run(&handler).await;

            assert_eq!(Ok(RunOutcome::Completed), result, "{save_result:?}");
            let received_stores = handler.received_review_stores.lock().unwrap();
            assert_eq!(2, received_stores.len(), "{save_result:?}");
            assert_eq!(None, received_stores[0].get("edited"), "{save_result:?}");
            assert_eq!(
                Some("by the user"),
                received_stores[1].get("edited").map(|entry| entry.value.as_str()),
                "{save_result:?}"
            );
            assert_eq!(
                vec![Vec::<FieldError>::new(), vec![]],
                *handler.received_review_errors.lock().unwrap(),
                "{save_result:?}"
            );
        }
    }

    #[tokio::test]
    async fn run_returns_failure_reason_when_the_result_display_fails() {
        let handler = FakeHandler {
            result_outcomes: Mutex::new(VecDeque::from([Err("no terminal".to_string())])),
            ..FakeHandler::succeeding()
        };

        let result = run(&handler).await;

        assert_eq!(Err("no terminal".to_string()), result);
    }

    #[tokio::test]
    async fn run_returns_the_save_failure_reason_when_the_user_exits_the_failure() {
        let handler = FakeHandler {
            save_results: Mutex::new(VecDeque::from([Err("disk full".to_string())])),
            ..FakeHandler::succeeding()
        };

        let result = run(&handler).await;

        assert_eq!(Err("disk full".to_string()), result);
        assert_eq!(
            vec!["disk full".to_string()],
            *handler.received_failure_reasons.lock().unwrap()
        );
    }
}
