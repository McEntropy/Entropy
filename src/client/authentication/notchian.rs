use crate::client::{AuthenticatedClient, Connection, ConnectionWriter};
use crate::server::{ClientInformation, ServerClient};
use crate::server_client_mingle::ClientAction;
use crate::{simple_attach, ServerConfiguration};
use encryption_utils::MCPrivateKey;
use encryption_utils::{private_key_to_der, sha1_message};
use flume::Sender;
use mc_buffer::buffer::{BorrowedPacketBuffer, BufferTransport, PacketBuffer};
use mc_buffer::encryption::{Codec, Compressor, Decrypt, Encrypt};
use mc_chat::Chat;
use mc_registry::client_bound::login::{
    Disconnect, EncryptionRequest, LoginSuccess, ServerId, SetCompression,
};
use mc_registry::mappings::Mappings;
use mc_registry::registry::{arc_lock, UnhandledContext};
use mc_registry::registry::{LockedContext, StateRegistry, StateRegistryHandle};
use mc_registry::server_bound::handshaking::Handshake;
use mc_registry::server_bound::login::{EncryptionResponse, EncryptionResponseData, LoginStart};
use mc_registry::shared_types::login::{IdentifiedKey, LoginUsername};
use mc_registry::shared_types::{GameProfile, MCIdentifiedKey};
use mc_registry_derive::packet_handler;
use mc_serializer::primitive::VarInt;
use mc_serializer::serde::ProtocolVersion;
use std::any::Any;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::tcp::WriteHalf;
use tokio::net::TcpStream;
use typemap::{Key, ShareMap, TypeMap};

use crate::client::authentication::MOJANG_KEY;
use crate::packet::PacketWriter;
use num_bigint::BigInt;
use rand::RngCore;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

pub struct NotchianLoginClientContext<'a> {
    self_reference: &'a NotchianAuthenticationScheme,
    write_borrow: WriteHalf<'a>,
    compressor: Option<Compressor>,
    encryption_block_mut: Option<&'a mut Encrypt>,
    protocol_version: ProtocolVersion,
    server_key: Arc<MCPrivateKey>,
    info: ShareMap,
}

macro_rules! basic_key {
    ($key_ident:ident, $value_type:ty) => {
        struct $key_ident;
        impl typemap::Key for $key_ident {
            type Value = $value_type;
        }
    };
}

macro_rules! disconnect {
    ($context_write:ident, $reason:expr) => {{
        let mut __chat = Chat::text(format!("{}", $reason));
        __chat.modify_style(|style| style.color("red"));
        $context_write.disconnect_login(__chat).await?;
        anyhow::bail!(format!("{}", $reason));
    }};
}

impl<'a> NotchianLoginClientContext<'a> {
    pub fn insert<K: Key + Send + Sync>(&mut self, value: K::Value)
    where
        K::Value: Any + Send + Sync,
    {
        self.info.insert::<K>(value);
    }

    pub fn query_data<K: Key + Send + Sync>(&self) -> Option<&K::Value>
    where
        K::Value: Any + Send + Sync,
    {
        self.info.get::<K>()
    }
}

impl<'a> PacketWriter<WriteHalf<'a>> for NotchianLoginClientContext<'a> {
    fn writer(&mut self) -> &mut WriteHalf<'a> {
        &mut self.write_borrow
    }

    fn compressor(&self) -> Option<&Compressor> {
        self.compressor.as_ref()
    }

    fn encrypt(&mut self, buffer: &mut Vec<u8>) {
        if let Some(encryption) = self.encryption_block_mut.as_mut() {
            encryption.encrypt(buffer)
        }
    }

    fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
}

pub(super) fn default_auth_server() -> String {
    "https://sessionserver.mojang.com".to_string()
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct NotchianAuthenticationScheme {
    force_key_authentication: bool,
    compression_threshold: i32,
    #[serde(default = "default_auth_server")]
    auth_server_url: String,
}

macro_rules! validate_result {
    ($locked:ident, $res:expr) => {
        match $res {
            Ok(ok) => ok,
            Err(err) => disconnect!($locked, format!("Error validating result. {:?}", err)),
        }
    };
}

macro_rules! validate_optional {
    ($locked:ident, $key:ty) => {
        match $locked.query_data::<$key>().cloned() {
            Some(item) => item,
            None => disconnect!($locked, "Failed to validate profile data."),
        }
    };
}

impl NotchianAuthenticationScheme {
    pub fn new<S: Into<String>>(
        force_key_authentication: bool,
        compression_threshold: i32,
        auth_server_url: S,
    ) -> Self {
        Self {
            force_key_authentication,
            compression_threshold,
            auth_server_url: auth_server_url.into(),
        }
    }

    pub(super) async fn login_internal(
        &self,
        mut stream: TcpStream,
        socket_addr: SocketAddr,
        buffer_transport: BufferTransport,
        handshake: Handshake,
        server_in_channel: Sender<ClientAction>,
        server_key: Arc<MCPrivateKey>,
    ) -> anyhow::Result<AuthenticatedClient> {
        let (read_borrow, write_borrow) = stream.split();
        let mut packet_buffer = buffer_transport.borrowed(read_borrow);
        let protocol_version = ProtocolVersion::from(handshake.protocol_version);
        let login_context = arc_lock(NotchianLoginClientContext {
            self_reference: self,
            write_borrow,
            compressor: None,
            encryption_block_mut: None,
            protocol_version,
            server_key,
            info: ShareMap::custom(),
        });

        let mut registry = StateRegistry::<NotchianLoginClientContext>::new(protocol_version);
        simple_attach!(LoginStart, registry, login_start_handler);
        let registry = arc_lock(registry);

        macro_rules! read_packet {
            () => {{
                let next = match packet_buffer.loop_read().await {
                    Ok(next) => next,
                    Err(err) => {
                        let mut lock = login_context.write().await;
                        disconnect!(lock, format!("Invalid buffer response, {:?}", err))
                    }
                };

                if let Some(unhandled) = StateRegistry::emit(
                    Arc::clone(&registry),
                    Arc::clone(&login_context),
                    Cursor::new(next),
                )
                .await?
                {
                    let UnhandledContext { packet_id, bytes } = unhandled;
                    let mut lock = login_context.write().await;
                    disconnect!(
                        lock,
                        format!("Unknown packet {} with {} bytes.", packet_id, bytes.len())
                    );
                }
            }};
        }

        // pre login start
        read_packet!();
        // post login start

        {
            let mut lock = login_context.write().await;

            let key_der = private_key_to_der(&lock.server_key);
            let mut verify_token = [0, 0, 0, 0];
            rand::thread_rng().fill_bytes(&mut verify_token);

            lock.insert::<VerifyTokenKey>(Vec::from(verify_token));

            let encryption_request = EncryptionRequest {
                server_id: ServerId::from(""),
                public_key: (VarInt::try_from(key_der.len())?, key_der),
                verify_token: (VarInt::from(4), Vec::from(verify_token)),
            };

            validate_result!(lock, lock.send_packet(encryption_request).await);

            drop(lock)
        }

        // update packet to read
        {
            let mut lock = registry.write().await;
            lock.clear_mappings();
            simple_attach!(EncryptionResponse, lock, encryption_response_handler);
        }

        // pre encryption response
        read_packet!();
        // post encryption response, post auth entirely

        let mut locked = login_context.write().await;
        let profile = validate_optional!(locked, ProfileKey);
        let raw_key = validate_optional!(locked, PlayerKey);
        let player_key = validate_optional!(locked, PlayerIdentifiedKey);
        let shared_secret_bytes = validate_optional!(locked, SharedSecretKey);
        drop(locked);

        let buffer_transport = packet_buffer.transport();

        let (read, write) = stream.into_split();
        let mut connection_writer = ConnectionWriter {
            write_half: write,
            protocol_version,
            encryption: None,
            compression: None,
        };

        let mut packet_buffer = buffer_transport.owned(read);

        let (r, w) = validate_result!(connection_writer, Codec::new(&shared_secret_bytes));
        connection_writer.encryption = Some(Encrypt::new(r));
        packet_buffer.enable_decryption(w);

        if self.compression_threshold > 0 {
            connection_writer.compression =
                Some(Compressor::new(VarInt::from(self.compression_threshold)));
            let set_compression = SetCompression {
                threshold: VarInt::from(self.compression_threshold),
            };
            validate_result!(
                connection_writer,
                connection_writer.send_packet(set_compression).await
            );
        }

        let login_success = LoginSuccess {
            uuid: profile.id,
            username: LoginUsername::from(&profile.name),
            properties: (
                VarInt::try_from(profile.properties.len())?,
                profile.properties.iter().map(Into::into).collect(),
            ),
        };

        validate_result!(
            connection_writer,
            connection_writer.send_packet(login_success).await
        );

        let connection = Connection {
            connection_writer,
            packet_buffer,
            socket_address: socket_addr,
            protocol_version,
            virtual_host: handshake.server_address.clone(),
            virtual_port: handshake.server_port,
        };
        let (io_write, channel_in) = flume::unbounded();
        let server_client = ServerClient::new(
            io_write,
            ClientInformation::new(
                protocol_version,
                profile.clone(),
                raw_key.as_ref().cloned(),
                player_key.as_ref().cloned(),
            ),
        );
        server_in_channel
            .send_async(ClientAction::AddClient(Box::new(server_client)))
            .await?;
        let authenticated_client = AuthenticatedClient {
            connection,
            profile: profile.clone(),
            channel_in,
            server_in_channel,
            raw_key,
            player_key,
        };

        Ok(authenticated_client)
    }
}

// utils

fn hash_server_id(server_id: &str, shared_secret: &[u8], public_key: &[u8]) -> String {
    use md5::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(server_id);
    hasher.update(shared_secret);
    hasher.update(public_key);
    let bytes = hasher.finalize();
    let bigint = BigInt::from_signed_bytes_be(bytes.as_slice());
    format!("{:x}", bigint)
}

// packet handlers

basic_key!(UsernameKey, LoginUsername);
basic_key!(PlayerKey, Option<MCIdentifiedKey>);
basic_key!(PlayerIdentifiedKey, Option<IdentifiedKey>);
basic_key!(VerifyTokenKey, Vec<u8>);
basic_key!(SharedSecretKey, Vec<u8>);
basic_key!(ProfileKey, GameProfile);
basic_key!(SharedSecret, Vec<u8>);

#[allow(clippy::needless_lifetimes)]
#[packet_handler]
fn login_start_handler<'registry>(
    context: LockedContext<NotchianLoginClientContext<'registry>>,
    packet: LoginStart,
) {
    let mut write = context.write().await;

    write.insert::<UsernameKey>(packet.name.clone());

    if packet.sig_data.0 {
        let signature = packet
            .sig_data
            .1
            .expect("Signature data expected but not found.");
        if signature.has_expired() {
            disconnect!(write, "Player key was found but expired.");
        }

        let mojang_der = encryption_utils::key_from_der(MOJANG_KEY)?;
        let sig_holder = packet.sig_holder.1;
        let sig_timestamp = signature.timestamp;

        let sig_holder = match sig_holder {
            None => disconnect!(write, "No signature holder found with key."),
            Some(sig) => sig,
        };

        let mut signature_data =
            Cursor::new(Vec::<u8>::with_capacity(signature.public_key.1.len() + 24));

        let (most, least) = sig_holder.as_u64_pair();
        mc_serializer::serde::Serialize::serialize(
            &most,
            &mut signature_data,
            ProtocolVersion::Unknown,
        )?;
        mc_serializer::serde::Serialize::serialize(
            &least,
            &mut signature_data,
            ProtocolVersion::Unknown,
        )?;
        mc_serializer::serde::Serialize::serialize(
            &sig_timestamp,
            &mut signature_data,
            ProtocolVersion::Unknown,
        )?;
        mc_serializer::serde::Serialize::serialize(
            &signature.public_key.1,
            &mut signature_data,
            ProtocolVersion::Unknown,
        )?;

        let inner = signature_data.into_inner();

        if let Err(err) = encryption_utils::verify_signature(
            Some(encryption_utils::SHA1_HASH),
            &mojang_der,
            &signature.signature.1,
            sha1_message(&inner).as_slice(),
        ) {
            disconnect!(write, format!("Key verification error: {:?}", err));
        }

        write.insert::<PlayerKey>(Some(signature.clone()));
        write.insert::<PlayerIdentifiedKey>(Some(IdentifiedKey::new(&signature.public_key.1)?));
    } else if write.self_reference.force_key_authentication {
        disconnect!(write, "Player key was expected but now found.");
    }
}

#[allow(clippy::needless_lifetimes)]
#[packet_handler]
fn encryption_response_handler<'registry>(
    context: LockedContext<NotchianLoginClientContext<'registry>>,
    packet: EncryptionResponse,
) {
    let mut context_write = context.write().await;
    let verify = validate_optional!(context_write, VerifyTokenKey);
    let player_key = validate_optional!(context_write, PlayerIdentifiedKey);
    let server_key = &context_write.server_key;
    if let Some(player_key) = player_key {
        match packet.response_data {
            EncryptionResponseData::VerifyTokenData(_) => {
                disconnect!(context_write, "Salt not found but expected.")
            }
            EncryptionResponseData::MessageSignature {
                salt,
                message_signature: (_, signature),
            } => {
                use sha2::Digest;
                let message = verify.clone();

                let mut hasher = sha2::Sha256::new();
                hasher.update(&message);
                hasher.update(&{
                    let mut value = salt;
                    let mut result = [0u8; 8];
                    for i in 0..8 {
                        result[7 - i] = (value & 255) as u8;
                        value >>= 8;
                    }
                    result
                });
                let hasher = hasher.finalize();

                player_key.verify_data_signature(&signature, &hasher)?;
            }
        }
    } else {
        match packet.response_data {
            EncryptionResponseData::VerifyTokenData((_, data)) => {
                let response =
                    server_key.decrypt(encryption_utils::Padding::PKCS1v15Encrypt, &data)?;
                if verify.ne(&response) {
                    disconnect!(context_write, "Verification mismatch.");
                }
            }
            EncryptionResponseData::MessageSignature { .. } => {
                disconnect!(context_write, "Salt found while player key is not.")
            }
        }
    }

    let shared_secret = server_key.decrypt(
        encryption_utils::Padding::PKCS1v15Encrypt,
        &packet.shared_secret.1,
    )?;

    let _generated_server_id = hash_server_id("", &shared_secret, &private_key_to_der(server_key));

    let _username = match context_write.query_data::<UsernameKey>() {
        None => disconnect!(context_write, "No username sent during EncryptionResponse"),
        Some(username) => username.clone(),
    };
    let _session_server = &context_write.self_reference.auth_server_url;
    let url = format!("{_session_server}/session/minecraft/hasJoined?username={_username}&serverId={_generated_server_id}");

    let response = reqwest::get(url).await?;
    if response.status() == StatusCode::from_u16(204)? {
        disconnect!(context_write, "Failed to authenticate with mojang.");
    } else if response.status() != StatusCode::from_u16(200)? {
        disconnect!(
            context_write,
            format!(
                "Received a {} status code from mojang auth server.",
                response.status().as_u16()
            )
        );
    }

    let game_profile = response.json::<GameProfile>().await?;
    context_write.insert::<ProfileKey>(game_profile);
    context_write.insert::<SharedSecretKey>(shared_secret);
}
