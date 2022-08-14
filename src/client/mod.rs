use std::net::SocketAddr;

use crate::packet::PacketWriter;
use flume::{Receiver, Sender};

use mc_registry::server_bound::handshaking::ServerAddress;
use mc_registry::shared_types::login::IdentifiedKey;
use mc_registry::shared_types::{GameProfile, MCIdentifiedKey};
use mc_serializer::serde::ProtocolVersion;

use crate::server_client_mingle::{ClientAction, ServerAction};

pub mod authentication;
mod client_status_handler;
pub mod draft_join;
pub mod worker;

#[derive(Clone)]
pub struct ConnectionInfo {
    pub(self) socket_address: SocketAddr,
    pub(self) protocol_version: ProtocolVersion,
    pub(self) virtual_host: ServerAddress,
    pub(self) virtual_port: u16,
}

#[derive(Clone)]
pub struct AuthenticatedClient {
    pub(self) connection_info: ConnectionInfo,
    pub(self) profile: GameProfile,
    pub(self) channel_in: Receiver<ServerAction>,
    pub(self) server_in_channel: Sender<ClientAction>,
    pub(self) raw_key: Option<MCIdentifiedKey>,
    pub(self) player_key: Option<IdentifiedKey>,
}

impl AuthenticatedClient {
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.connection_info.protocol_version
    }

    pub async fn emit_server_message(&self, action: ClientAction) -> anyhow::Result<()> {
        self.server_in_channel.send_async(action).await?;
        Ok(())
    }

    pub fn verify_player_signature(
        &self,
        message: &[&[u8]],
        signature: &[u8],
    ) -> anyhow::Result<()> {
        match &self.player_key {
            None => anyhow::bail!("Attempted to send signature without player key."),
            Some(key) => {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                for message_part in message {
                    hasher.update(message_part);
                }
                let hasher = hasher.finalize();
                key.verify_data_signature(signature, &hasher)?;
                Ok(())
            }
        }
    }
}
