use crate::client::client_status_handler::accept_status_client;
use crate::packet::PacketWriter;
use crate::server_client_mingle::ClientAction;
use crate::ServerConfiguration;
use encryption_utils::MCPrivateKey;
use flume::Sender;
use mc_buffer::buffer::{BorrowedPacketBuffer, PacketBuffer};
use mc_registry::mappings::Mappings;
use mc_registry::registry::{arc_lock, LockedContext, StateRegistry};
use mc_registry::server_bound::handshaking::{Handshake, NextState};
use mc_registry_derive::packet_handler;
use mc_serializer::serde::ProtocolVersion;
use std::sync::Arc;
use tokio::net::TcpStream;

#[derive(Default)]
struct HandshakeContext {
    handshake: Option<Handshake>,
}

#[packet_handler]
pub async fn accept_handshake(packet: Handshake, context: LockedContext<HandshakeContext>) {
    let mut context_write = context.write().await;
    context_write.handshake = Some(packet);
}

async fn accept_new_client(
    mut raw_stream: TcpStream,
    address: std::net::SocketAddr,
    server_key: Arc<MCPrivateKey>,
    server_configuration: Arc<ServerConfiguration>,
    server_in_channel: Sender<ClientAction>,
) -> anyhow::Result<()> {
    let (read, write) = raw_stream.split();
    let mut packet_buffer = BorrowedPacketBuffer::new(read);
    let context = arc_lock(HandshakeContext::default());
    let mut registry = StateRegistry::fail_on_invalid(ProtocolVersion::Handshake);
    crate::simple_attach!(Handshake, registry, accept_handshake);
    let registry = arc_lock(registry);

    let next = packet_buffer.loop_read().await?;
    StateRegistry::emit(registry, Arc::clone(&context), std::io::Cursor::new(next)).await?;

    let context_read = context.read().await;
    let handshake = context_read
        .handshake
        .as_ref()
        .cloned()
        .expect("Handshake should be populated post read.");

    match handshake.next_state {
        NextState::Status => {
            accept_status_client(
                handshake,
                packet_buffer,
                write,
                server_configuration,
                server_in_channel,
            )
            .await
        }
        NextState::Login => {
            let transport = packet_buffer.transport();
            let mut authenticated_client = match server_configuration
                .auth
                .login(
                    raw_stream,
                    address,
                    transport,
                    handshake,
                    server_in_channel,
                    server_key,
                )
                .await
            {
                Ok(authenticated_client) => authenticated_client,
                Err(error) => anyhow::bail!(error), // todo make this nice
            };

            let id = &authenticated_client.profile.id;
            authenticated_client
                .emit_server_message(ClientAction::RemoveClient(*id))
                .await?;

            authenticated_client.disconnect_play("KekW".into()).await?;
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
            }

            log::info!(target: format!("{}", addr).as_str(), "EOF");
        });
    }
}
