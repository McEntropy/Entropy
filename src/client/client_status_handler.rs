use crate::server_client_mingle::{ClientAction, StatusAck};
use crate::{ArcServerConfigurationKey, ProtocolVersionKey, ServerConfiguration, ServerList};
use flume::Sender;
use mc_buffer::buffer::PacketWriter;
use mc_registry::client_bound::status::{Pong, Response, StatusResponse, StatusResponsePlayers};
use mc_registry::registry::LockedContext;
use mc_registry::server_bound::status::{Ping, Request};
use mc_registry_derive::packet_handler;

use crate::server::ClientActionSenderKey;
use mc_buffer::assign_key;
use mc_buffer::engine::{BufferRegistryEngine, BufferRegistryEngineContext, Context};
use mc_registry::create_registry;
use std::sync::Arc;

assign_key!(CompletionKey, bool);

#[allow(clippy::needless_lifetimes)]
#[packet_handler(Request)]
pub fn handle_engine_status_request<'registry>(
    mut context: LockedContext<BufferRegistryEngineContext<'registry>>,
) {
    let server_configuration = Context::clone_data::<ArcServerConfigurationKey>(context.clone())
        .await
        .expect("Server configuration should exist in internal context data.");
    let protocol_version = Context::clone_data::<ProtocolVersionKey>(context.clone())
        .await
        .expect("Protocol version should exist in internal context data.");
    let client_action_channel = Context::clone_data::<ClientActionSenderKey>(context.clone())
        .await
        .expect("Protocol version should exist in internal context data.");

    let status_info: StatusAck = {
        let (player_count_sender, player_count_receiver) = flume::unbounded();
        let task = tokio::task::spawn(async move {
            client_action_channel
                .send_async(ClientAction::AckPlayerCount(player_count_sender))
                .await
        });
        let result = player_count_receiver.recv_async().await?;
        task.await??;
        result
    };

    let previews_chat = server_configuration.preview_chat.as_ref().cloned();

    let response = match &server_configuration.server_list {
        ServerList::TrueAnswer { motd, max_players } => {
            let player_count = status_info.online_players() as i32;

            StatusResponse {
                version: protocol_version.into(),
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
                version: protocol_version.into(),
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
            version: protocol_version.into(),
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
    context.send_packet(Response(response)).await?;
}

#[allow(clippy::needless_lifetimes)]
#[packet_handler]
pub fn handle_engine_ping<'registry>(
    mut context: LockedContext<BufferRegistryEngineContext<'registry>>,
    packet: Ping,
) {
    context.send_packet(Pong::from(packet)).await?;
    Context::insert_data::<CompletionKey>(context, true).await;
}

pub async fn handle_status_client(
    mut engine: BufferRegistryEngine,
    server_configuration: Arc<ServerConfiguration>,
    client_action_sender: Sender<ClientAction>,
) -> anyhow::Result<()> {
    engine
        .insert_data::<ArcServerConfigurationKey>(Arc::clone(&server_configuration))
        .await;
    engine
        .insert_data::<ClientActionSenderKey>(client_action_sender.clone())
        .await;
    engine
        .insert_data::<ProtocolVersionKey>(engine.protocol_version())
        .await;
    engine.insert_data::<CompletionKey>(false).await;
    let protocol_version = engine.protocol_version();

    create_registry! { reg, protocol_version {
        Ping, handle_engine_ping
        Request, handle_engine_status_request
    }};

    engine
        .read_packets_until(reg, |unhandled, share| {
            if let Some(unhandled) = unhandled {
                log::error!(
                    "Unhandled status packet: {} with length {}",
                    unhandled.packet_id,
                    unhandled.bytes.len()
                );
                return true;
            }
            share.get::<CompletionKey>().cloned().unwrap_or(false)
        })
        .await?;

    Ok(())
}
