use crate::server_client_mingle::{ClientAction, ServerAction, StatusAck};
use crate::ServerConfiguration;
use flume::{Receiver, Sender};
use mc_registry::shared_types::login::IdentifiedKey;
use mc_registry::shared_types::{GameProfile, MCIdentifiedKey};
use mc_serializer::serde::ProtocolVersion;
use std::collections::HashMap;
use std::io::{Cursor};
use std::path::Path;
use std::process::exit;
use std::sync::Arc;

#[derive(Default)]
pub struct Clients {
    internal_mappings: HashMap<uuid::Uuid, ServerClient>,
}

impl Clients {
    pub(crate) fn insert_client(&mut self, client: ServerClient) {
        log::info!(target: &client.client_information.profile.name, "Alert client login!");
        log::info!(
            "Profile Json: {}",
            serde_json::to_string_pretty(&client.client_information.profile).unwrap()
        );
        self.internal_mappings
            .insert(client.client_information.profile.id, client);
    }

    pub(crate) fn cleanup_client(&mut self, uuid: &uuid::Uuid) {
        log::info!(target: uuid.to_string().as_str(), "Alert client disconnect!");
        self.internal_mappings.remove(uuid);
    }

    pub(crate) fn len(&self) -> usize {
        self.internal_mappings.len()
    }
}

pub struct Server {
    server_configuration: Arc<ServerConfiguration>,
    clients: Clients,
    read_channel: Receiver<ClientAction>,
    favicon: Option<String>,
}

impl Server {
    pub fn create_server(
        server_configuration: Arc<ServerConfiguration>,
    ) -> anyhow::Result<(Self, Sender<ClientAction>)> {
        let favicon_file = Path::new("./server-icon.png");
        let favicon = if Path::exists(favicon_file) {
            if !Path::is_file(favicon_file) {
                log::warn!("Invalid favicon file, it must be a regular file.");
                None
            } else {
                let base_img = image::open(favicon_file)?;
                let mut buf = Cursor::new(Vec::new());
                base_img.write_to(&mut buf, image::ImageOutputFormat::Png)?;
                let res_base64 = base64::encode(&buf.into_inner());
                Some(format!("data:image/png;base64,{}", res_base64))
            }
        } else {
            None
        };

        let (write_channel, read_channel) = flume::unbounded();
        Ok((
            Self {
                server_configuration,
                clients: Clients::default(),
                read_channel,
                favicon,
            },
            write_channel,
        ))
    }

    pub async fn spin_read(&mut self) {
        loop {
            match self.read_channel.recv_async().await {
                Ok(action) => self.handle_action(action),
                Err(_) => exit(0),
            }
        }
    }

    fn handle_action(&mut self, action: ClientAction) {
        match action {
            ClientAction::AddClient(new_client) => self.clients.insert_client(*new_client),
            ClientAction::RemoveClient(uuid) => self.clients.cleanup_client(&uuid),
            ClientAction::AckPlayerCount(sender) => sender
                .send(StatusAck::new(
                    self.clients.len(),
                    self.favicon.as_ref().cloned(),
                ))
                .unwrap_or(()),
        }
    }
}

pub struct ClientInformation {
    protocol_version: ProtocolVersion,
    profile: GameProfile,
    key_data: Option<MCIdentifiedKey>,
    profile_key: Option<IdentifiedKey>,
}

impl ClientInformation {
    pub(crate) fn new(
        protocol_version: ProtocolVersion,
        profile: GameProfile,
        key_data: Option<MCIdentifiedKey>,
        profile_key: Option<IdentifiedKey>,
    ) -> Self {
        Self {
            protocol_version,
            profile,
            key_data,
            profile_key,
        }
    }
}

pub struct ServerClient {
    write_channel: Sender<ServerAction>,
    client_information: ClientInformation,
}

impl ServerClient {
    pub(crate) fn new(
        write_channel: Sender<ServerAction>,
        client_information: ClientInformation,
    ) -> Self {
        Self {
            write_channel,
            client_information,
        }
    }
}
