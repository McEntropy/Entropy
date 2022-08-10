use std::net::SocketAddr;

use crate::packet::{PacketWriter};
use flume::{Receiver, Sender};
use mc_buffer::buffer::OwnedPacketBuffer;
use mc_buffer::encryption::{Compressor, Encrypt};

use mc_registry::server_bound::handshaking::ServerAddress;
use mc_registry::shared_types::login::IdentifiedKey;
use mc_registry::shared_types::{GameProfile, MCIdentifiedKey};
use mc_serializer::serde::ProtocolVersion;
use tokio::net::tcp::{OwnedWriteHalf};


use crate::server_client_mingle::{ClientAction, ServerAction};

pub mod authentication;
mod client_status_handler;
pub mod worker;

pub struct ConnectionWriter {
    pub(self) write_half: OwnedWriteHalf,
    pub(self) protocol_version: ProtocolVersion,
    pub(self) encryption: Option<Encrypt>,
    pub(self) compression: Option<Compressor>,
}

impl PacketWriter<OwnedWriteHalf> for ConnectionWriter {
    #[inline]
    fn writer(&mut self) -> &mut OwnedWriteHalf {
        &mut self.write_half
    }

    #[inline]
    fn compressor(&self) -> Option<&Compressor> {
        self.compression.as_ref()
    }

    fn encrypt(&mut self, buffer: &mut Vec<u8>) {
        if let Some(encryption) = self.encryption.as_mut() {
            encryption.encrypt(buffer)
        }
    }

    #[inline]
    fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
}

pub struct Connection {
    pub(self) packet_buffer: OwnedPacketBuffer,
    pub(self) connection_writer: ConnectionWriter,
    pub(self) socket_address: SocketAddr,
    pub(self) protocol_version: ProtocolVersion,
    pub(self) virtual_host: ServerAddress,
    pub(self) virtual_port: u16,
}

pub struct AuthenticatedClient {
    pub(self) connection: Connection,
    pub(self) profile: GameProfile,
    pub(self) channel_in: Receiver<ServerAction>,
    pub(self) server_in_channel: Sender<ClientAction>,
    pub(self) raw_key: Option<MCIdentifiedKey>,
    pub(self) player_key: Option<IdentifiedKey>,
}

impl AuthenticatedClient {
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

impl PacketWriter<OwnedWriteHalf> for AuthenticatedClient {
    #[inline]
    fn writer(&mut self) -> &mut OwnedWriteHalf {
        self.connection.connection_writer.writer()
    }

    #[inline]
    fn compressor(&self) -> Option<&Compressor> {
        self.connection.connection_writer.compressor()
    }

    #[inline]
    fn encrypt(&mut self, buffer: &mut Vec<u8>) {
        self.connection.connection_writer.encrypt(buffer)
    }

    #[inline]
    fn protocol_version(&self) -> ProtocolVersion {
        self.connection.protocol_version
    }
}
