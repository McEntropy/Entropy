use crate::client::client_status_handler::handle_status_client;
use crate::client::draft_join::join_client;
use crate::server_client_mingle::ClientAction;
use crate::ServerConfiguration;
use encryption_utils::MCPrivateKey;
use flume::Sender;
use mc_buffer::assign_key;
use mc_buffer::buffer::PacketWriter;
use mc_buffer::engine::{BufferRegistryEngine, BufferRegistryEngineContext, Context};
use mc_chat::Chat;
use mc_registry::client_bound::play::Disconnect;
use mc_registry::create_registry;
use mc_registry::registry::LockedContext;
use mc_registry::server_bound::handshaking::{Handshake, NextState};
use mc_registry_derive::packet_handler;
use mc_serializer::serde::ProtocolVersion;
use std::sync::Arc;
use tokio::net::TcpStream;

assign_key!(HandshakeKey, Handshake);

#[packet_handler]
pub async fn accept_handshake<'registry>(
    packet: Handshake,
    context: LockedContext<BufferRegistryEngineContext<'registry>>,
) {
    Context::insert_data::<HandshakeKey>(context, packet).await;
}

async fn accept_new_client(
    raw_stream: TcpStream,
    address: std::net::SocketAddr,
    server_key: Arc<MCPrivateKey>,
    server_configuration: Arc<ServerConfiguration>,
    server_in_channel: Sender<ClientAction>,
) -> anyhow::Result<()> {
    let mut engine = BufferRegistryEngine::create(raw_stream);

    let handshake = ProtocolVersion::Handshake;
    create_registry! { reg, handshake {
        Handshake, accept_handshake
    }};

    engine
        .read_packets_until(reg, |unhandled, share| {
            if let Some(unhandled) = unhandled {
                log::error!(
                    "Unhandled packet: {} with length {}",
                    unhandled.packet_id,
                    unhandled.bytes.len()
                );
                return true;
            }
            share.contains::<HandshakeKey>()
        })
        .await?;

    let handshake = match engine.clone_data::<HandshakeKey>().await {
        None => {
            log::error!(target: address.to_string().as_str(),"No handshake found but one was expected.");
            return Ok(());
        }
        Some(handshake) => handshake,
    };

    let protocol_version = ProtocolVersion::from(handshake.protocol_version);
    engine.update_protocol(protocol_version);
    engine.clear_data().await;

    match handshake.next_state {
        NextState::Status => {
            handle_status_client(engine, server_configuration, server_in_channel).await
        }
        NextState::Login => {
            let (mut engine, authenticated_client) = server_configuration
                .auth
                .login(
                    engine,
                    address,
                    handshake,
                    server_in_channel.clone(),
                    server_key,
                )
                .await?;

            if let Some(authenticated_client) = authenticated_client {
                join_client(engine, authenticated_client).await?;
            }

            Ok(())
        }
    }
}

pub async fn poll_clients_continuously(
    server_key: Arc<MCPrivateKey>,
    server_configuration: Arc<ServerConfiguration>,
    server_in_channel: Sender<ClientAction>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(server_configuration.bind.to_string()).await?;

    loop {
        let (stream, addr) = listener.accept().await?;
        let (server_key, server_configuration, server_in_channel) = (
            Arc::clone(&server_key),
            Arc::clone(&server_configuration),
            server_in_channel.clone(),
        );

        tokio::spawn(async move {
            if let Err(err) = accept_new_client(
                stream,
                addr,
                server_key,
                server_configuration,
                server_in_channel,
            )
            .await
            {
                log::error!(target: format!("{}", addr).as_str(), "Error in connection stream: {:?}", err);
            } else {
                log::debug!(target: format!("{}", addr).as_str(), "Successfully closed client connection.");
            }
        });
    }
}
