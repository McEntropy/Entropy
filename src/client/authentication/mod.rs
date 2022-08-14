mod notchian;

use crate::client::authentication::notchian::NotchianAuthenticationScheme;
use crate::client::AuthenticatedClient;
use crate::server_client_mingle::ClientAction;

use encryption_utils::MCPrivateKey;
use flume::Sender;
use mc_registry::server_bound::handshaking::Handshake;
use std::net::SocketAddr;

use mc_buffer::engine::BufferRegistryEngine;
use std::sync::Arc;
use tokio::net::TcpStream;

const MOJANG_KEY: &[u8] = include_bytes!("yggdrasil_session_pubkey.der");

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
#[serde(untagged)]
pub enum AuthHandler {
    Notchian(NotchianAuthenticationScheme),
}

impl Default for AuthHandler {
    fn default() -> Self {
        Self::Notchian(NotchianAuthenticationScheme::new(
            true,
            1024,
            notchian::default_auth_server(),
        ))
    }
}

impl AuthHandler {
    pub async fn login(
        &self,
        engine: BufferRegistryEngine,
        socket_addr: SocketAddr,
        handshake: Handshake,
        server_in_channel: Sender<ClientAction>,
        server_key: Arc<MCPrivateKey>,
    ) -> anyhow::Result<(BufferRegistryEngine, Option<AuthenticatedClient>)> {
        match self {
            AuthHandler::Notchian(scheme) => {
                scheme
                    .login_internal(
                        engine,
                        socket_addr,
                        handshake,
                        server_in_channel,
                        server_key,
                    )
                    .await
            }
        }
    }
}
