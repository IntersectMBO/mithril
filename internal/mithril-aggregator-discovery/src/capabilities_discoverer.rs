use std::sync::Arc;

use mithril_common::{
    AggregateSignatureType, StdResult,
    entities::{MithrilNetwork, SignedEntityTypeDiscriminants},
    messages::AggregatorCapabilities,
};

use crate::{AggregatorDiscoverer, AggregatorEndpoint, model::AggregatorEndpointWithCapabilities};

/// Required capabilities for an aggregator.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RequiredAggregatorCapabilities {
    /// All
    All,
    /// Signed entity type.
    SignedEntityType(SignedEntityTypeDiscriminants),
    /// Aggregate signature type.
    AggregateSignatureType(AggregateSignatureType),
    /// Logical OR of required capabilities.
    Or(Vec<RequiredAggregatorCapabilities>),
    /// Logical AND of required capabilities.
    And(Vec<RequiredAggregatorCapabilities>),
}

impl From<SignedEntityTypeDiscriminants> for RequiredAggregatorCapabilities {
    fn from(signed_entity_type: SignedEntityTypeDiscriminants) -> Self {
        RequiredAggregatorCapabilities::SignedEntityType(signed_entity_type)
    }
}

impl RequiredAggregatorCapabilities {
    /// Check if the available capabilities match the required capabilities.
    fn matches(&self, available: &AggregatorCapabilities) -> bool {
        match self {
            RequiredAggregatorCapabilities::All => true,
            RequiredAggregatorCapabilities::SignedEntityType(required_signed_entity_type) => {
                available
                    .signed_entity_types
                    .iter()
                    .any(|req| req == required_signed_entity_type)
            }
            RequiredAggregatorCapabilities::AggregateSignatureType(
                required_aggregate_signature_types,
            ) => *required_aggregate_signature_types == available.aggregate_signature_type,
            RequiredAggregatorCapabilities::Or(requirements) => {
                requirements.iter().any(|req| req.matches(available))
            }
            RequiredAggregatorCapabilities::And(requirements) => {
                requirements.iter().all(|req| req.matches(available))
            }
        }
    }
}

/// An aggregator discoverer for specific capabilities.
pub struct CapableAggregatorDiscoverer {
    required_capabilities: RequiredAggregatorCapabilities,
    inner_discoverer: Arc<dyn AggregatorDiscoverer<AggregatorEndpoint>>,
}

impl CapableAggregatorDiscoverer {
    /// Creates a new `CapableAggregatorDiscoverer` instance with the provided capabilities.
    pub fn new(
        capabilities: RequiredAggregatorCapabilities,
        inner_discoverer: Arc<dyn AggregatorDiscoverer<AggregatorEndpoint>>,
    ) -> Self {
        Self {
            required_capabilities: capabilities,
            inner_discoverer,
        }
    }
}

#[async_trait::async_trait]
impl AggregatorDiscoverer<AggregatorEndpointWithCapabilities> for CapableAggregatorDiscoverer {
    async fn get_available_aggregators(
        &self,
        network: MithrilNetwork,
    ) -> StdResult<Box<dyn Iterator<Item = AggregatorEndpointWithCapabilities>>> {
        let aggregator_endpoints = self.inner_discoverer.get_available_aggregators(network).await?;

        Ok(Box::new(CapableAggregatorDiscovererIterator {
            required_capabilities: self.required_capabilities.clone(),
            inner_iterator: aggregator_endpoints,
        }))
    }
}

/// An iterator over aggregator endpoints filtered by capabilities.
struct CapableAggregatorDiscovererIterator {
    required_capabilities: RequiredAggregatorCapabilities,
    inner_iterator: Box<dyn Iterator<Item = AggregatorEndpoint>>,
}

impl Iterator for CapableAggregatorDiscovererIterator {
    type Item = AggregatorEndpointWithCapabilities;

    fn next(&mut self) -> Option<Self::Item> {
        for aggregator_endpoint in self.inner_iterator.by_ref() {
            if let Ok(aggregator_with_capabilities) =
                AggregatorEndpointWithCapabilities::try_from(aggregator_endpoint)
                && self
                    .required_capabilities
                    .matches(aggregator_with_capabilities.capabilities())
            {
                return Some(aggregator_with_capabilities);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use httpmock::MockServer;
    use serde_json::json;

    use mithril_common::{
        AggregateSignatureType::Concatenation,
        entities::SignedEntityTypeDiscriminants::{
            CardanoDatabase, CardanoStakeDistribution, CardanoTransactions,
            MithrilStakeDistribution,
        },
        messages::{
            AggregatorFeaturesMessage, DiscontinuedSignedEntityType,
            SignedEntityTypeDiscriminantsMessage,
        },
    };

    use super::*;

    mod required_capabilities {
        use super::*;

        #[test]
        fn required_capabilities_match_all_success() {
            let required = RequiredAggregatorCapabilities::All;
            let available = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([]),
                cardano_transactions_prover: None,
            };

            assert!(required.matches(&available));
        }

        #[test]
        fn required_capabilities_match_signed_entity_types_success() {
            let required =
                RequiredAggregatorCapabilities::SignedEntityType(CardanoStakeDistribution);
            let available = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoStakeDistribution),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                ]),
                cardano_transactions_prover: None,
            };

            assert!(required.matches(&available));
        }

        #[test]
        fn required_capabilities_match_signed_entity_types_fails_if_no_discriminants_match() {
            let required =
                RequiredAggregatorCapabilities::SignedEntityType(MithrilStakeDistribution);
            let available = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoStakeDistribution),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                ]),
                cardano_transactions_prover: None,
            };

            assert!(!required.matches(&available));
        }

        #[test]
        fn required_capabilities_match_signed_entity_types_fails_if_only_unknown_or_discontinued_discriminants_match()
         {
            let required =
                RequiredAggregatorCapabilities::SignedEntityType(MithrilStakeDistribution);
            let available = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Discontinued(
                        DiscontinuedSignedEntityType::CardanoImmutableFilesFull,
                    ),
                    SignedEntityTypeDiscriminantsMessage::Unknown,
                ]),
                cardano_transactions_prover: None,
            };

            assert!(!required.matches(&available));
        }

        #[test]
        fn required_capabilities_match_signed_aggregate_signature_type_success() {
            let required = RequiredAggregatorCapabilities::AggregateSignatureType(Concatenation);
            let available = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoStakeDistribution),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                ]),
                cardano_transactions_prover: None,
            };

            assert!(required.matches(&available));
        }

        #[test]
        fn required_capabilities_match_or_success() {
            let required = RequiredAggregatorCapabilities::Or(vec![
                RequiredAggregatorCapabilities::SignedEntityType(MithrilStakeDistribution),
                RequiredAggregatorCapabilities::AggregateSignatureType(Concatenation),
            ]);
            let available = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoStakeDistribution),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                ]),
                cardano_transactions_prover: None,
            };

            assert!(required.matches(&available));
        }

        #[test]
        fn required_capabilities_match_and_success() {
            let required = RequiredAggregatorCapabilities::And(vec![
                RequiredAggregatorCapabilities::SignedEntityType(CardanoTransactions),
                RequiredAggregatorCapabilities::SignedEntityType(CardanoStakeDistribution),
                RequiredAggregatorCapabilities::AggregateSignatureType(Concatenation),
            ]);
            let available = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoStakeDistribution),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                ]),
                cardano_transactions_prover: None,
            };

            assert!(required.matches(&available));
        }

        #[test]
        fn required_capabilities_match_and_failure() {
            let required = RequiredAggregatorCapabilities::And(vec![
                RequiredAggregatorCapabilities::SignedEntityType(CardanoTransactions),
                RequiredAggregatorCapabilities::SignedEntityType(CardanoStakeDistribution),
                RequiredAggregatorCapabilities::AggregateSignatureType(Concatenation),
            ]);
            let available = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([SignedEntityTypeDiscriminantsMessage::Known(
                    CardanoTransactions,
                )]),
                cardano_transactions_prover: None,
            };

            assert!(!required.matches(&available));
        }
    }

    mod capable_discoverer {
        use super::*;

        fn create_aggregator_features_message(
            capabilities: AggregatorCapabilities,
        ) -> AggregatorFeaturesMessage {
            AggregatorFeaturesMessage {
                open_api_version: "1.0.0".to_string(),
                documentation_url: "https://docs".to_string(),
                capabilities,
                cardano_database_distribution: None,
            }
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn get_available_aggregators_success() {
            let capabilities = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoStakeDistribution),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoTransactions),
                ]),
                cardano_transactions_prover: None,
            };
            let aggregator_server = MockServer::start();
            let aggregator_server_mock = aggregator_server.mock(|when, then| {
                when.path("/");
                then.status(200)
                    .body(json!(create_aggregator_features_message(capabilities)).to_string());
            });
            let discoverer = CapableAggregatorDiscoverer::new(
                RequiredAggregatorCapabilities::And(vec![
                    RequiredAggregatorCapabilities::SignedEntityType(CardanoTransactions),
                    RequiredAggregatorCapabilities::AggregateSignatureType(Concatenation),
                ]),
                Arc::new(crate::test::double::AggregatorDiscovererFake::new(vec![
                    Ok(vec![AggregatorEndpoint::new(aggregator_server.url("/"))]),
                ])),
            );

            let mut aggregators = discoverer
                .get_available_aggregators(MithrilNetwork::new("release-devnet".into()))
                .await
                .unwrap();

            let next_aggregator = aggregators.next().map(Into::into);
            aggregator_server_mock.assert();
            assert_eq!(
                Some(AggregatorEndpoint::new(aggregator_server.url("/"))),
                next_aggregator
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn get_available_aggregators_succeeds_when_aggregator_capabilities_do_not_match() {
            let capabilities = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([SignedEntityTypeDiscriminantsMessage::Known(
                    CardanoTransactions,
                )]),
                cardano_transactions_prover: None,
            };
            let aggregator_server = MockServer::start();
            let aggregator_server_mock = aggregator_server.mock(|when, then| {
                when.path("/");
                then.status(200)
                    .body(json!(create_aggregator_features_message(capabilities)).to_string());
            });
            let discoverer = CapableAggregatorDiscoverer::new(
                RequiredAggregatorCapabilities::And(vec![
                    RequiredAggregatorCapabilities::SignedEntityType(CardanoDatabase),
                    RequiredAggregatorCapabilities::AggregateSignatureType(Concatenation),
                ]),
                Arc::new(crate::test::double::AggregatorDiscovererFake::new(vec![
                    Ok(vec![AggregatorEndpoint::new(aggregator_server.url("/"))]),
                ])),
            );

            let mut aggregators = discoverer
                .get_available_aggregators(MithrilNetwork::new("release-devnet".into()))
                .await
                .unwrap();

            let next_aggregator = aggregators.next();
            aggregator_server_mock.assert();
            assert!(next_aggregator.is_none());
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn get_available_aggregators_succeeds_when_one_aggregator_returns_an_error() {
            let aggregator_server_1 = MockServer::start();
            let aggregator_server_mock_1 = aggregator_server_1.mock(|when, then| {
                when.path("/");
                then.status(500);
            });
            let capabilities_2 = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoStakeDistribution),
                    SignedEntityTypeDiscriminantsMessage::Known(CardanoDatabase),
                ]),
                cardano_transactions_prover: None,
            };
            let aggregator_server_2 = MockServer::start();
            let aggregator_server_mock_2 = aggregator_server_2.mock(|when, then| {
                when.path("/");
                then.status(200)
                    .body(json!(create_aggregator_features_message(capabilities_2)).to_string());
            });
            let discoverer = CapableAggregatorDiscoverer::new(
                RequiredAggregatorCapabilities::And(vec![
                    RequiredAggregatorCapabilities::SignedEntityType(CardanoDatabase),
                    RequiredAggregatorCapabilities::AggregateSignatureType(Concatenation),
                ]),
                Arc::new(crate::test::double::AggregatorDiscovererFake::new(vec![
                    Ok(vec![
                        AggregatorEndpoint::new(aggregator_server_1.url("/")),
                        AggregatorEndpoint::new(aggregator_server_2.url("/")),
                    ]),
                ])),
            );

            let mut aggregators = discoverer
                .get_available_aggregators(MithrilNetwork::new("release-devnet".into()))
                .await
                .unwrap();

            let next_aggregator = aggregators.next().map(|endpoint| endpoint.into());
            aggregator_server_mock_1.assert();
            aggregator_server_mock_2.assert();
            assert_eq!(
                Some(AggregatorEndpoint::new(aggregator_server_2.url("/"))),
                next_aggregator
            );
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn get_available_aggregators_succeeds_and_makes_minimum_calls_to_aggregators() {
            let aggregator_server_1 = MockServer::start();
            let aggregator_server_mock_1 = aggregator_server_1.mock(|when, then| {
                when.path("/");
                then.status(500);
            });
            let capabilities_2 = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([SignedEntityTypeDiscriminantsMessage::Known(
                    CardanoStakeDistribution,
                )]),
                cardano_transactions_prover: None,
            };
            let aggregator_server_2 = MockServer::start();
            let aggregator_server_mock_2 = aggregator_server_2.mock(|when, then| {
                when.path("/");
                then.status(200)
                    .body(json!(create_aggregator_features_message(capabilities_2)).to_string());
            });
            let capabilities_3 = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([SignedEntityTypeDiscriminantsMessage::Known(
                    CardanoDatabase,
                )]),
                cardano_transactions_prover: None,
            };
            let aggregator_server_3 = MockServer::start();
            let aggregator_server_mock_3 = aggregator_server_3.mock(|when, then| {
                when.path("/");
                then.status(200)
                    .body(json!(create_aggregator_features_message(capabilities_3)).to_string());
            });
            let capabilities_4 = AggregatorCapabilities {
                aggregate_signature_type: Concatenation,
                signed_entity_types: BTreeSet::from([SignedEntityTypeDiscriminantsMessage::Known(
                    CardanoDatabase,
                )]),
                cardano_transactions_prover: None,
            };
            let aggregator_server_4 = MockServer::start();
            let aggregator_server_mock_4 = aggregator_server_4.mock(|when, then| {
                when.path("/");
                then.status(200)
                    .body(json!(create_aggregator_features_message(capabilities_4)).to_string());
            });
            let discoverer = CapableAggregatorDiscoverer::new(
                RequiredAggregatorCapabilities::And(vec![
                    RequiredAggregatorCapabilities::SignedEntityType(CardanoDatabase),
                    RequiredAggregatorCapabilities::AggregateSignatureType(Concatenation),
                ]),
                Arc::new(crate::test::double::AggregatorDiscovererFake::new(vec![
                    Ok(vec![
                        AggregatorEndpoint::new(aggregator_server_1.url("/")),
                        AggregatorEndpoint::new(aggregator_server_2.url("/")),
                        AggregatorEndpoint::new(aggregator_server_3.url("/")),
                        AggregatorEndpoint::new(aggregator_server_4.url("/")),
                    ]),
                ])),
            );

            let mut aggregators = discoverer
                .get_available_aggregators(MithrilNetwork::new("release-devnet".into()))
                .await
                .unwrap();

            let next_aggregator = aggregators.next().map(|endpoint| endpoint.into());
            aggregator_server_mock_1.assert();
            aggregator_server_mock_2.assert();
            aggregator_server_mock_3.assert();
            assert_eq!(0, aggregator_server_mock_4.calls());
            assert_eq!(
                Some(AggregatorEndpoint::new(aggregator_server_3.url("/"))),
                next_aggregator
            );
        }
    }
}
