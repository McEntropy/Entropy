use crate::server_client_mingle::{ClientAction, StatusAck};
use crate::{ServerConfiguration, ServerList};
use bytes::Buf;
use flume::Sender;
use mc_buffer::buffer::{BorrowedPacketBuffer, PacketBuffer};
use mc_buffer::encryption::Compressor;
use mc_registry::client_bound::status::{Pong, Response, StatusResponse, StatusResponsePlayers};
use mc_registry::mappings::Mappings;
use mc_registry::registry::{arc_lock, LockedContext, StateRegistry};
use mc_registry::server_bound::handshaking::Handshake;
use mc_registry::server_bound::status::{Ping, Request};
use mc_registry_derive::packet_handler;
use mc_serializer::serde::ProtocolVersion;
use std::io::Cursor;

use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{WriteHalf};

async fn send_packet<Packet: Mappings<PacketType = Packet>>(
    protocol_version: ProtocolVersion,
    write_half: &mut WriteHalf<'_>,
    packet: Packet,
) -> anyhow::Result<()> {
    let buffer = Packet::create_packet_buffer(protocol_version, packet)?;
    let buffer = Compressor::uncompressed(buffer)?;
    let mut buffer = Cursor::new(buffer);

    while buffer.has_remaining() {
        write_half.write_buf(&mut buffer).await?;
    }
    Ok(())
}

struct StatusClientContext<'a> {
    write_half: WriteHalf<'a>,
    protocol_version: ProtocolVersion,
    server_configuration: Arc<ServerConfiguration>,
    server_in_channel: Sender<ClientAction>,
    complete: bool,
}

impl<'a> StatusClientContext<'a> {
    async fn send_packet<Packet: Mappings<PacketType = Packet>>(
        &mut self,
        packet: Packet,
    ) -> anyhow::Result<()> {
        send_packet(self.protocol_version, &mut self.write_half, packet).await
    }
}

#[allow(clippy::needless_lifetimes)]
#[packet_handler(Request)]
pub fn handle_status_request<'registry>(context: LockedContext<StatusClientContext<'registry>>) {
    let context_read = context.read().await;

    let previews_chat = context_read
        .server_configuration
        .preview_chat
        .as_ref()
        .cloned();
    let version = if context_read.protocol_version == ProtocolVersion::Unknown {
        context_read.protocol_version
    } else {
        ProtocolVersion::default()
    }
    .into();

    let status_info: StatusAck = {
        let server_in_channel = context_read.server_in_channel.clone();
        let (player_count_sender, player_count_receiver) = flume::unbounded();
        let task = tokio::task::spawn(async move {
            server_in_channel
                .send_async(ClientAction::AckPlayerCount(player_count_sender))
                .await
        });
        let result = player_count_receiver.recv_async().await?;
        task.await??;
        result
    };

    let response = match &context_read.server_configuration.server_list {
        ServerList::TrueAnswer { motd, max_players } => {
            let player_count = status_info.online_players() as i32;

            StatusResponse {
                version,
                players: StatusResponsePlayers {
                    max: *max_players,
                    online: player_count,
                    sample: vec![],
                },
                description: motd.clone(),
                favicon: status_info.favicon(),
                previews_chat,
            }
        }
        ServerList::JustUnder { motd } => {
            let player_count = status_info.online_players() as i32;

            StatusResponse {
                version,
                players: StatusResponsePlayers {
                    max: player_count + 1,
                    online: player_count,
                    sample: vec![],
                },
                description: motd.clone(),
                favicon: status_info.favicon(),
                previews_chat,
            }
        }
        ServerList::StaticInfo {
            motd,
            online_players,
            max_players,
        } => StatusResponse {
            version,
            players: StatusResponsePlayers {
                max: *max_players,
                online: *online_players,
                sample: vec![],
            },
            description: motd.clone(),
            favicon: status_info.favicon(),
            previews_chat,
        },
        ServerList::Custom => todo!(),
    };
    drop(context_read);
    let mut context_write = context.write().await;
    context_write.send_packet(Response(response)).await?;
}

#[allow(clippy::needless_lifetimes)]
#[packet_handler]
pub fn handle_ping<'registry>(
    context: LockedContext<StatusClientContext<'registry>>,
    packet: Ping,
) {
    let mut context_write = context.write().await;
    context_write.send_packet(Pong::from(packet)).await?;
    context_write.complete = true;
}

pub async fn accept_status_client(
    handshake: Handshake,
    mut packet_buffer: BorrowedPacketBuffer<'_>,
    write_half: WriteHalf<'_>,
    server_configuration: Arc<ServerConfiguration>,
    server_in_channel: Sender<ClientAction>,
) -> anyhow::Result<()> {
    let client_context = arc_lock(StatusClientContext {
        protocol_version: ProtocolVersion::from(handshake.protocol_version),
        write_half,
        server_configuration,
        server_in_channel,
        complete: false,
    });

    let mut registry =
        StateRegistry::fail_on_invalid(ProtocolVersion::from(handshake.protocol_version));
    crate::simple_attach!(Request, registry, handle_status_request);
    crate::simple_attach!(Ping, registry, handle_ping);

    let registry = arc_lock(registry);

    while {
        let read = client_context.read().await;
        let pass = !read.complete;
        drop(read);
        pass
    } {
        let next_packet = packet_buffer.loop_read().await?;
        StateRegistry::emit(
            Arc::clone(&registry),
            Arc::clone(&client_context),
            Cursor::new(next_packet),
        )
        .await?;
    }

    Ok(())
}
