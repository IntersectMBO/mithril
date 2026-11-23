use std::{fs, path::PathBuf};

use anyhow::{Context, anyhow};
use pallas_network::{
    facades::{DEFAULT_HANDSHAKE_TIMEOUT, DmqServer},
    miniprotocols::{
        localmsgsubmission::{DmqMsgRejectReason, DmqMsgValidationError},
        localtxsubmission::{Request, Response},
    },
};
use tokio::{
    net::UnixListener,
    select,
    sync::{Mutex, MutexGuard, mpsc::UnboundedSender, watch::Receiver},
};

use slog::{Logger, debug, error, info, warn};

use mithril_common::{StdResult, logging::LoggerExtensions};

use crate::{DmqMessage, DmqNetwork, DmqPublisherServer};

/// A DMQ server implementation for messages publication to a DMQ node.
pub struct DmqPublisherServerPallas {
    socket: PathBuf,
    network: DmqNetwork,
    server: Mutex<Option<DmqServer>>,
    transmitters: Mutex<Vec<UnboundedSender<DmqMessage>>>,
    stop_rx: Receiver<()>,
    logger: Logger,
}

impl DmqPublisherServerPallas {
    /// Creates a new instance of [DmqPublisherServerPallas].
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
            transmitters: Mutex::new(Vec::new()),
            stop_rx,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Creates and returns a new `DmqServer` connected to the specified socket.
    async fn new_server(&self) -> StdResult<DmqServer> {
        info!(
            self.logger,
            "Creating a new DMQ publisher server";
            "socket" => ?self.socket,
            "network" => ?self.network
        );
        let magic = self.network.magic_id();
        if self.socket.exists() {
            fs::remove_file(self.socket.clone())?;
        }
        let listener = UnixListener::bind(&self.socket).with_context(|| {
            format!(
                "DmqPublisherServerPallas failed to bind Unix socket at {}",
                self.socket.display()
            )
        })?;

        DmqServer::accept_with_timeout(&listener, magic, DEFAULT_HANDSHAKE_TIMEOUT)
            .await
            .with_context(|| "DmqPublisherServerPallas failed to create a new server")
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
            "Drop existing DMQ publisher server";
            "socket" => ?self.socket,
            "network" => ?self.network
        );
        let mut server_lock = self.server.try_lock()?;
        if let Some(server) = server_lock.take() {
            server.abort().await;
        }

        Ok(())
    }

    /// Registers a transmitter for DMQ messages.
    pub async fn register_transmitter(
        &self,
        transmitter: UnboundedSender<DmqMessage>,
    ) -> StdResult<()> {
        debug!(self.logger, "Register message transmitter for DMQ messages");
        let mut transmitters_guard = self.transmitters.lock().await;
        transmitters_guard.push(transmitter);

        Ok(())
    }
}

#[async_trait::async_trait]
impl DmqPublisherServer for DmqPublisherServerPallas {
    async fn process_message(&self) -> StdResult<()> {
        debug!(
            self.logger,
            "Waiting for message to publish to the DMQ network";
            "socket" => ?self.socket,
            "network" => ?self.network
        );
        let mut server_guard = self.get_server().await?;
        let server = server_guard
            .as_mut()
            .with_context(|| "DMQ publisher server does not exist")?;

        let request = server
            .msg_submission()
            .recv_next_request()
            .await
            .with_context(|| "Failed to receive next DMQ message")?;
        let (dmq_message, response) = match request {
            Request::Submit(dmq_message) => {
                debug!(self.logger, "Received message to publish to DMQ");
                (Some(dmq_message), Response::Accepted)
            }
            request => {
                error!(
                    self.logger,
                    "Expected a Submit request, but received: {request:?}"
                );
                (
                    None,
                    Response::Rejected(DmqMsgValidationError(DmqMsgRejectReason::Invalid(
                        format!("Expected a Submit request, but received: {request:?}"),
                    ))),
                )
            }
        };
        server
            .msg_submission()
            .send_submit_tx_response(response)
            .await
            .with_context(|| "Failed to send response to DMQ publisher client")?;

        if let Some(dmq_message) = dmq_message {
            for transmitter in self.transmitters.lock().await.iter() {
                if let Err(err) = transmitter.send(dmq_message.to_owned().into()) {
                    error!(
                        self.logger,
                        "Failed to send DMQ message to transmitter";
                        "error" => ?err
                    );
                }
            }
        }

        let request = server
            .msg_submission()
            .recv_next_request()
            .await
            .with_context(|| "Failed to receive next request from DMQ publisher client")?;
        match request {
            Request::Done => {
                debug!(
                    self.logger,
                    "Received Done request from DMQ publisher client"
                );
            }
            _ => {
                error!(
                    self.logger,
                    "Expected a Done request, but received: {request:?}"
                );
                return Err(anyhow!(
                    "Expected a Done request, but received: {request:?}"
                ));
            }
        }

        Ok(())
    }

    async fn run(&self) -> StdResult<()> {
        info!(
            self.logger,
            "Starting DMQ publisher server";
            "socket" => ?self.socket,
            "network" => ?self.network
        );

        let mut stop_rx = self.stop_rx.clone();
        loop {
            select! {
                _ = stop_rx.changed() => {
                    warn!(self.logger, "Stopping DMQ publisher server...");

                    return Ok(());
                }
                res = self.process_message() => {
                    match res {
                        Ok(_) => {
                            debug!(self.logger, "Processed a message successfully");
                        }
                        Err(err) => {
                            error!(self.logger, "Failed to process message"; "error" => ?err);
                        }
                    }
                    if let Err(drop_err) = self.drop_server().await {
                        error!(self.logger, "Failed to drop DMQ publisher server"; "error" => ?drop_err);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pallas_network::{
        facades::DmqClient,
        miniprotocols::{
            localmsgsubmission::{DmqMsg, DmqMsgOperationalCertificate, DmqMsgPayload},
            localtxsubmission,
        },
    };
    use tokio::sync::{mpsc::unbounded_channel, watch};

    use mithril_common::{current_function, test::TempDir};

    use crate::test_tools::TestLogger;

    use super::*;

    fn create_temp_dir(folder_name: &str) -> PathBuf {
        TempDir::create_with_short_path("dmq_publisher_server", folder_name)
    }

    async fn fake_msg() -> DmqMsg {
        DmqMsg {
            msg_id: vec![0, 1],
            msg_payload: DmqMsgPayload {
                msg_body: vec![0, 1, 2],
                kes_period: 10,
                expires_at: 100,
            },
            kes_signature: vec![0, 1, 2, 3],
            operational_certificate: DmqMsgOperationalCertificate {
                kes_vk: vec![12, 13, 14],
                issue_number: 15,
                start_kes_period: 16,
                cert_sig: vec![17],
            },
            cold_verification_key: vec![0, 1, 2, 3, 4, 5],
        }
    }

    #[tokio::test]
    async fn pallas_dmq_publisher_server_success() {
        let (stop_tx, stop_rx) = watch::channel(());
        let (signature_dmq_tx, signature_dmq_rx) = unbounded_channel::<DmqMessage>();
        let socket_path = create_temp_dir(current_function!()).join("node.socket");
        let cardano_network = DmqNetwork::TestNet(0);
        let dmq_publisher_server = Arc::new(DmqPublisherServerPallas::new(
            socket_path.to_path_buf(),
            cardano_network.to_owned(),
            stop_rx,
            TestLogger::stdout(),
        ));
        dmq_publisher_server
            .register_transmitter(signature_dmq_tx)
            .await
            .unwrap();
        let message = fake_msg().await;
        let message_clone = message.clone();
        let client = tokio::spawn({
            async move {
                // client setup
                let mut client = DmqClient::connect(socket_path.clone(), 0).await.unwrap();

                // init local msg submission client
                let client_msg = client.msg_submission();
                assert_eq!(*client_msg.state(), localtxsubmission::State::Idle);

                // client sends a request to server and waits for a reply from the server
                client_msg.send_submit_tx(message_clone).await.unwrap();
                assert_eq!(*client_msg.state(), localtxsubmission::State::Busy);

                let response = client_msg.recv_submit_tx_response().await.unwrap();
                assert_eq!(*client_msg.state(), localtxsubmission::State::Idle);
                assert_eq!(response, localtxsubmission::Response::Accepted);
            }
        });
        let recorder = tokio::spawn(async move {
            let result = {
                let mut signature_dmq_rx = signature_dmq_rx;
                if let Some(message) = signature_dmq_rx.recv().await {
                    return Ok(message);
                }

                Err(anyhow::anyhow!("No message received in recorder"))
            };
            stop_tx
                .send(())
                .expect("Failed to send stop signal to DMQ publisher server");

            result
        });

        let (_, _, message_res) = tokio::join!(dmq_publisher_server.run(), client, recorder);
        let message_received = message_res.unwrap().unwrap();
        assert_eq!(message, message_received.into());
    }
}
