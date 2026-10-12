use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use slog::Logger;
use tokio::sync::Mutex;

use mithril_common::StdResult;
use mithril_common::entities::BlockNumber;

use crate::chain_reader::ChainBlockReader;
use crate::chain_scanner::block_streamer_with_throttling::BlockStreamerWithThrottling;
use crate::chain_scanner::{BlockScanner, BlockStreamer};
use crate::entities::RawCardanoPoint;

use super::ChainReaderBlockStreamer;

/// Cardano block scanner
///
/// This scanner reads the blocks with a chain block reader
pub struct CardanoBlockScanner {
    chain_reader: Arc<Mutex<dyn ChainBlockReader>>,
    max_roll_forwards_per_poll: usize,
    throttling_interval: Option<Duration>,
    logger: Logger,
}

impl CardanoBlockScanner {
    /// Factory
    pub fn new(
        chain_reader: Arc<Mutex<dyn ChainBlockReader>>,
        max_roll_forwards_per_poll: usize,
        logger: Logger,
    ) -> Self {
        Self {
            chain_reader,
            max_roll_forwards_per_poll,
            throttling_interval: None,
            logger,
        }
    }

    /// Set the optional throttling interval for the block scanner
    ///
    /// This ensures that the scanner will not poll the chain reader more frequently than the
    /// specified interval.
    pub fn set_throttling_interval(mut self, interval: Option<Duration>) -> Self {
        if interval.is_none_or(|i| i.is_zero()) {
            self.throttling_interval = None;
        } else {
            self.throttling_interval = interval;
        }
        self
    }
}

#[async_trait]
impl BlockScanner for CardanoBlockScanner {
    async fn scan(
        &self,
        candidates: Vec<RawCardanoPoint>,
        until: BlockNumber,
    ) -> StdResult<Box<dyn BlockStreamer>> {
        let streamer = Box::new(
            ChainReaderBlockStreamer::try_new(
                self.chain_reader.clone(),
                candidates,
                until,
                self.max_roll_forwards_per_poll,
                self.logger.clone(),
            )
            .await?,
        );

        match self.throttling_interval {
            Some(interval) => Ok(Box::new(BlockStreamerWithThrottling::new(
                streamer, interval,
            ))),
            None => Ok(streamer),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test::TestLogger;
    use crate::test::double::FakeChainReader;

    use super::*;

    #[test]
    fn setting_interval_of_zero_is_same_as_setting_it_to_none() {
        let scanner = CardanoBlockScanner::new(
            Arc::new(Mutex::new(FakeChainReader::new(vec![]))),
            100,
            TestLogger::stdout(),
        );

        assert!(scanner.throttling_interval.is_none());

        let scanner = scanner.set_throttling_interval(Some(Duration::from_secs(0)));
        assert!(scanner.throttling_interval.is_none());
    }
}
