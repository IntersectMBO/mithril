use std::{fs, path::PathBuf};

use anyhow::{Context, anyhow};
use pallas_network::{
    facades::{DEFAULT_HANDSHAKE_TIMEOUT, DmqServer},
    miniprotocols::localmsgnotification::Request,
};
use tokio::{
    join,
    net::UnixListener,
    select,
    sync::{Mutex, MutexGuard, mpsc::UnboundedReceiver, watch::Receiver},
};

use slog::{Logger, debug, error, info, warn};

use mithril_common::{StdResult, logging::LoggerExtensions};

use crate::{DmqConsumerServer, DmqMessage, DmqNetwork};

use super::queue::MessageQueue;

/// A DMQ server implementation for messages notification from a DMQ node.
pub struct DmqConsumerServerPallas {
    socket: PathBuf,
    network: DmqNetwork,
    server: Mutex<Option<DmqServer>>,
    messages_receiver: Mutex<Option<UnboundedReceiver<DmqMessage>>>,
    messages_buffer: MessageQueue,
    stop_rx: Receiver<()>,
    logger: Logger,
}

impl DmqConsumerServerPallas {
    /// Creates a new instance of [DmqConsumerServerPallas].
    pub fn new(
        socket: PathBuf,
        network: DmqNetwork,
        stop_rx: Receiver<()>,
        logger: Logger,
    ) -> Self {
        Self {
            socket,
            network,
            server: Mutex::new(None),
            messages_receiver: Mutex::new(None),
            messages_buffer: MessageQueue::default(),
            stop_rx,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Creates and returns a new `DmqServer` connected to the specified socket.
    async fn new_server(&self) -> StdResult<DmqServer> {
        info!(
            self.logger,
            "Creating a new DMQ consumer server";
            "socket" => ?self.socket,
            "network" => ?self.network
        );
        let magic = self.network.magic_id();
        if self.socket.exists() {
            fs::remove_file(self.socket.clone())?;
        }
        let listener = UnixListener::bind(&self.socket).with_context(|| {
            format!(
                "DmqConsumerServerPallas failed to bind Unix socket at {}",
                self.socket.display()
            )
        })?;

        DmqServer::accept_with_timeout(&listener, magic, DEFAULT_HANDSHAKE_TIMEOUT)
            .await
            .with_context(|| "DmqConsumerServerPallas failed to create a new server")
    }

    /// Gets the cached `DmqServer`, creating a new one if it does not exist.
    async fn get_server(&self) -> StdResult<MutexGuard<'_, Option<DmqServer>>> {
        {
            // Run this in a separate block to avoid dead lock on the Mutex
            let server_lock = self.server.lock().await;
            if server_lock.as_ref().is_some() {
                return Ok(server_lock);
            }
        }

        let mut server_lock = self.server.lock().await;
        *server_lock = Some(self.new_server().await?);

        Ok(server_lock)
    }

    /// Drops the current `DmqServer`, if it exists.
    async fn drop_server(&self) -> StdResult<()> {
        debug!(
            self.logger,
            "Drop existing DMQ server";
            "socket" => ?self.socket,
            "network" => ?self.network
        );
        let mut server_lock = self.server.try_lock()?;
        if let Some(server) = server_lock.take() {
            server.abort().await;
        }

        Ok(())
    }

    /// Registers the receiver for DMQ messages (only one receiver is allowed).
    pub async fn register_receiver(
        &self,
        receiver: UnboundedReceiver<DmqMessage>,
    ) -> StdResult<()> {
        debug!(self.logger, "Register message receiver for DMQ messages");
        let mut receiver_guard = self.messages_receiver.lock().await;
        *receiver_guard = Some(receiver);

        Ok(())
    }

    /// Receives incoming messages into the DMQ consumer server.
    async fn receive_incoming_messages(&self) -> StdResult<()> {
        info!(
            self.logger,
            "Receive incoming messages into DMQ consumer server...";
            "socket" => ?self.socket,
            "network" => ?self.network
        );

        let mut stop_rx = self.stop_rx.clone();
        let mut receiver = self.messages_receiver.lock().await;
        match *receiver {
            Some(ref mut receiver) => loop {
                select! {
                    _ = stop_rx.changed() => {
                        warn!(self.logger, "Stopping DMQ consumer server...");

                        return Ok(());
                    }
                    message = receiver.recv() => {
                        if let Some(message) = message {
                            debug!(self.logger, "Received a message from the DMQ network"; "message" => ?message);
                            self.messages_buffer.enqueue(message).await;
                        } else {
                            warn!(self.logger, "DMQ message receiver channel closed");
                            return Ok(());
                        }

                    }
                }
            },
            None => Err(anyhow!("DMQ message receiver is not registered")),
        }
    }

    /// Serves incoming messages from the DMQ consumer server.
    async fn serve_incoming_messages(&self) -> StdResult<()> {
        info!(
            self.logger,
            "Serve incoming messages from DMQ consumer server...";
            "socket" => ?self.socket,
            "network" => ?self.network
        );

        let mut stop_rx = self.stop_rx.clone();
        loop {
            select! {
                _ = stop_rx.changed() => {
                    warn!(self.logger, "Stopping DMQ consumer server...");

                    return Ok(());
                }
                res = self.process_message() => {
                    match res {
                        Ok(_) => {
                            debug!(self.logger, "Processed a message successfully");
                        }
                        Err(err) => {
                            error!(self.logger, "Failed to process message"; "error" => ?err);
                            if let Err(drop_err) = self.drop_server().await {
                                error!(self.logger, "Failed to drop DMQ consumer server"; "error" => ?drop_err);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl DmqConsumerServer for DmqConsumerServerPallas {
    async fn process_message(&self) -> StdResult<()> {
        debug!(
            self.logger,
            "Waiting for message received from the DMQ network"
        );

        let mut server_guard = self.get_server().await?;
        let server = server_guard.as_mut().with_context(|| "DMQ server does not exist")?;
        let request = server
            .msg_notification()
            .recv_next_request()
            .await
            .with_context(|| "Failed to receive next DMQ message")?;

        match request {
            Request::Blocking => {
                debug!(
                    self.logger,
                    "Blocking notification of messages received from the DMQ network"
                );
                let reply_messages = self.messages_buffer.dequeue_blocking(None).await;
                let reply_messages =
                    reply_messages.into_iter().map(|msg| msg.into()).collect::<Vec<_>>();
                server
                    .msg_notification()
                    .send_reply_messages_blocking(reply_messages.clone())
                    .await?;
                debug!(
                    self.logger,
                    "Messages replied to the DMQ notification client: {:?}", reply_messages
                );
            }
            Request::NonBlocking => {
                debug!(
                    self.logger,
                    "Non blocking notification of messages received from the DMQ network"
                );
                let reply_messages = self.messages_buffer.dequeue_non_blocking(None).await;
                let reply_messages =
                    reply_messages.into_iter().map(|msg| msg.into()).collect::<Vec<_>>();
                let has_more = !self.messages_buffer.is_empty().await;
                server
                    .msg_notification()
                    .send_reply_messages_non_blocking(reply_messages.clone(), has_more)
                    .await?;
                debug!(
                    self.logger,
                    "Messages replied to the DMQ notification client: {:?}", reply_messages
                );
            }
        };

        Ok(())
    }

    async fn run(&self) -> StdResult<()> {
        info!(
            self.logger,
            "Starting DMQ consumer server";
            "socket" => ?self.socket,
            "network" => ?self.network
        );

        let (receive_result, serve_result) = join!(
            self.receive_incoming_messages(),
            self.serve_incoming_messages()
        );
        receive_result?;
        serve_result?;

        Ok(())
    }
}

impl Drop for DmqConsumerServerPallas {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                if let Err(e) = self.drop_server().await {
                    error!(self.logger, "Failed to drop DMQ consumer server: {}", e);
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use pallas_network::{
        facades::DmqClient,
        miniprotocols::{localmsgnotification, localmsgsubmission::DmqMsg},
    };
    use tokio::sync::{mpsc::unbounded_channel, watch};
    use tokio::time::sleep;

    use mithril_common::{current_function, test::TempDir};

    use crate::{test::fake_message::compute_fake_msg, test_tools::TestLogger};

    use super::*;

    fn create_temp_dir(folder_name: &str) -> PathBuf {
        TempDir::create_with_short_path("dmq_consumer_server", folder_name)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pallas_dmq_consumer_server_non_blocking_success() {
        let current_function_name = current_function!();
        let (stop_tx, stop_rx) = watch::channel(());
        let (signature_dmq_tx, signature_dmq_rx) = unbounded_channel::<DmqMessage>();
        let socket_path = create_temp_dir(current_function_name).join("node.socket");
        let dmq_network = DmqNetwork::TestNet(0);
        let dmq_consumer_server = Arc::new(DmqConsumerServerPallas::new(
            socket_path.to_path_buf(),
            dmq_network.to_owned(),
            stop_rx,
            TestLogger::stdout(),
        ));
        dmq_consumer_server.register_receiver(signature_dmq_rx).await.unwrap();
        let message: DmqMsg = compute_fake_msg(b"test", current_function_name).await.into();
        let client = tokio::spawn({
            async move {
                // sleep to avoid refused connection from the server
                tokio::time::sleep(Duration::from_millis(10)).await;

                // client setup
                let mut client = DmqClient::connect(socket_path.clone(), 0).await.unwrap();

                // init local msg notification client
                let client_msg = client.msg_notification();
                assert_eq!(*client_msg.state(), localmsgnotification::State::Idle);

                // client sends a non blocking request to server and waits for a reply from the server
                client_msg.send_request_messages_non_blocking().await.unwrap();
                assert_eq!(
                    *client_msg.state(),
                    localmsgnotification::State::BusyNonBlocking
                );

                let reply = client_msg.recv_next_reply().await.unwrap();
                assert_eq!(*client_msg.state(), localmsgnotification::State::Idle);
                let result = match reply {
                    localmsgnotification::Reply(messages, false) => Ok(messages),
                    _ => Err(anyhow::anyhow!(
                        "Failed to receive blocking reply from DMQ server"
                    )),
                };

                // stop the consumer server
                stop_tx.send(()).unwrap();

                result
            }
        });
        let message_clone = message.clone();
        let _signature_dmq_tx_clone = signature_dmq_tx.clone();
        let recorder = tokio::spawn(async move {
            _signature_dmq_tx_clone.send(message_clone.into()).unwrap();
        });

        let (_, messages_res, _) = tokio::join!(dmq_consumer_server.run(), client, recorder);
        let messages_received: Vec<_> = messages_res.unwrap().unwrap();
        assert_eq!(vec![message], messages_received);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pallas_dmq_consumer_server_blocking_success() {
        let current_function_name = current_function!();
        let (stop_tx, stop_rx) = watch::channel(());
        let (signature_dmq_tx, signature_dmq_rx) = unbounded_channel::<DmqMessage>();
        let socket_path = create_temp_dir(current_function_name).join("node.socket");
        let dmq_network = DmqNetwork::TestNet(0);
        let dmq_consumer_server = Arc::new(DmqConsumerServerPallas::new(
            socket_path.to_path_buf(),
            dmq_network.to_owned(),
            stop_rx,
            TestLogger::stdout(),
        ));
        dmq_consumer_server.register_receiver(signature_dmq_rx).await.unwrap();
        let message: DmqMsg = compute_fake_msg(b"test", current_function_name).await.into();
        let client = tokio::spawn({
            async move {
                // sleep to avoid refused connection from the server
                tokio::time::sleep(Duration::from_millis(10)).await;

                // client setup
                let mut client = DmqClient::connect(socket_path.clone(), 0).await.unwrap();

                // init local msg notification client
                let client_msg = client.msg_notification();
                assert_eq!(*client_msg.state(), localmsgnotification::State::Idle);

                // client sends a blocking request to server and waits for a reply from the server
                client_msg.send_request_messages_blocking().await.unwrap();
                assert_eq!(
                    *client_msg.state(),
                    localmsgnotification::State::BusyBlocking
                );

                let reply = client_msg.recv_next_reply().await.unwrap();
                assert_eq!(*client_msg.state(), localmsgnotification::State::Idle);
                let result = match reply {
                    localmsgnotification::Reply(messages, false) => Ok(messages),
                    _ => Err(anyhow::anyhow!(
                        "Failed to receive blocking reply from DMQ server"
                    )),
                };

                // stop the consumer server
                stop_tx.send(()).unwrap();

                result
            }
        });
        let message_clone = message.clone();
        let _signature_dmq_tx_clone = signature_dmq_tx.clone();
        let recorder = tokio::spawn(async move {
            _signature_dmq_tx_clone.send(message_clone.into()).unwrap();
        });

        let (_, messages_res, _) = tokio::join!(dmq_consumer_server.run(), client, recorder);
        let messages_received: Vec<_> = messages_res.unwrap().unwrap();
        assert_eq!(vec![message], messages_received);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pallas_dmq_consumer_server_blocking_blocks_when_no_message_available() {
        let (_stop_tx, stop_rx) = watch::channel(());
        let (_signature_dmq_tx, signature_dmq_rx) = unbounded_channel::<DmqMessage>();
        let socket_path = create_temp_dir(current_function!()).join("node.socket");
        let dmq_network = DmqNetwork::TestNet(0);
        let dmq_consumer_server = Arc::new(DmqConsumerServerPallas::new(
            socket_path.to_path_buf(),
            dmq_network.to_owned(),
            stop_rx,
            TestLogger::stdout(),
        ));
        dmq_consumer_server.register_receiver(signature_dmq_rx).await.unwrap();
        let client = tokio::spawn({
            async move {
                // sleep to avoid refused connection from the server
                tokio::time::sleep(Duration::from_millis(10)).await;

                // client setup
                let mut client = DmqClient::connect(socket_path.clone(), 0).await.unwrap();

                // init local msg notification client
                let client_msg = client.msg_notification();
                assert_eq!(*client_msg.state(), localmsgnotification::State::Idle);

                // client sends a blocking request to server and waits for a reply from the server
                client_msg.send_request_messages_blocking().await.unwrap();
                assert_eq!(
                    *client_msg.state(),
                    localmsgnotification::State::BusyBlocking
                );

                let _ = client_msg.recv_next_reply().await;
            }
        });

        let result = tokio::select!(
            _res = sleep(Duration::from_millis(100)) => {Err(anyhow!("Timeout"))},
            _res =  dmq_consumer_server.run()  => {Ok(())},
            _res =  client  => {Ok(())},
        );

        result.expect_err("Should have timed out");
    }
}
