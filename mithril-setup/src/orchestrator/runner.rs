//! Runner of the orchestrator: executes the effects requested by the state machine (imperative shell)

use async_trait::async_trait;

use crate::state_machine::{Effect, Event, State, transition};
use crate::store::Store;

/// Performs the I/O requested by the state machine effects
#[async_trait]
pub trait EffectHandler: Send + Sync {
    /// Discover the fields's values from the environment
    async fn discover(&self) -> Result<Store, String>;

    /// Guess the fields's values from the discovered ones
    async fn guess(&self, store: Store) -> Result<Store, String>;

    /// Let the user review the store, returns the confirmed store
    async fn review(&self, store: Store, errors: Vec<String>) -> Store;

    /// Check the integrity of the store
    async fn validate(&self, store: Store) -> Result<(), Vec<String>>;

    /// Save the store to the desired output
    async fn save(&self, store: Store) -> Result<(), String>;
}

/// Run the state machine until a final state, executing effects with the given handler
pub async fn run(handler: &dyn EffectHandler) -> Result<(), String> {
    let (mut state, mut effect) = transition(&State::Idle, Event::Started)?;

    while let Some(current_effect) = effect {
        let event = execute(handler, current_effect).await;
        (state, effect) = transition(&state, event)?;
    }

    match state {
        State::Done => Ok(()),
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
        Effect::Review { store, errors } => Event::Reviewed(handler.review(store, errors).await),
        Effect::Validate(store) => Event::Validated(handler.validate(store).await),
        Effect::Save(store) => Event::Saved(handler.save(store).await),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    struct FakeHandler {
        discover_result: Result<Store, String>,
        validate_results: Mutex<VecDeque<Result<(), Vec<String>>>>,
        received_review_errors: Mutex<Vec<Vec<String>>>,
    }

    impl FakeHandler {
        fn succeeding() -> Self {
            Self {
                discover_result: Ok(Store::default()),
                validate_results: Mutex::new(VecDeque::new()),
                received_review_errors: Mutex::new(vec![]),
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

        async fn review(&self, store: Store, errors: Vec<String>) -> Store {
            self.received_review_errors.lock().unwrap().push(errors);
            store
        }

        async fn validate(&self, _store: Store) -> Result<(), Vec<String>> {
            self.validate_results.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }

        async fn save(&self, _store: Store) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_returns_ok_when_all_effects_succeed() {
        let handler = FakeHandler::succeeding();

        let result = run(&handler).await;

        assert_eq!(Ok(()), result);
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
        let validation_errors = vec!["invalid field".to_string()];
        let handler = FakeHandler {
            validate_results: Mutex::new(VecDeque::from([Err(validation_errors.clone())])),
            ..FakeHandler::succeeding()
        };

        let result = run(&handler).await;

        assert_eq!(Ok(()), result);
        assert_eq!(
            vec![vec![], validation_errors],
            *handler.received_review_errors.lock().unwrap()
        );
    }
}
