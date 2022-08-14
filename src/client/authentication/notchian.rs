use crate::client::{AuthenticatedClient, ConnectionInfo};
use crate::server::{ClientInformation, ServerClient};
use crate::server_client_mingle::ClientAction;
use crate::ProtocolVersionKey;
use encryption_utils::MCPrivateKey;
use encryption_utils::{private_key_to_der, sha1_message};
use flume::Sender;
use mc_buffer::assign_key;
use mc_buffer::buffer::PacketWriter;
use mc_buffer::encryption::Codec;
use mc_buffer::engine::{BufferRegistryEngine, BufferRegistryEngineContext, Context};
use mc_chat::Chat;
use mc_registry::client_bound::login::{
    Disconnect, EncryptionRequest, LoginSuccess, ServerId, SetCompression,
};
use mc_registry::create_registry;
use mc_registry::registry::LockedContext;
use mc_registry::server_bound::handshaking::Handshake;
use mc_registry::server_bound::login::{EncryptionResponse, EncryptionResponseData, LoginStart};
use mc_registry::shared_types::login::{IdentifiedKey, LoginUsername};
use mc_registry::shared_types::{GameProfile, MCIdentifiedKey};
use mc_registry_derive::packet_handler;
use mc_serializer::primitive::VarInt;
use mc_serializer::serde::ProtocolVersion;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use typemap::Key;

use crate::client::authentication::MOJANG_KEY;
use num_bigint::BigInt;
use rand::RngCore;
use reqwest::StatusCode;

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
        mut engine: BufferRegistryEngine,
        socket_addr: SocketAddr,
        handshake: Handshake,
        server_in_channel: Sender<ClientAction>,
        server_key: Arc<MCPrivateKey>,
    ) -> anyhow::Result<(BufferRegistryEngine, Option<AuthenticatedClient>)> {
        println!("Login internal.");

        macro_rules! insert {
            ($key:ty, $value:expr) => {
                engine.insert_data::<$key>($value).await;
            };
        }

        let protocol_version = engine.protocol_version();

        insert!(State, State::PreLogin);
        insert!(ForceKeyAuthentication, self.force_key_authentication);
        insert!(AuthServerUrl, self.auth_server_url.clone());
        insert!(ServerPersonalKey, server_key.clone());
        insert!(ProtocolVersionKey, protocol_version);

        create_registry! { login_registry, protocol_version {
            LoginStart, login_start_handler
            EncryptionResponse, encryption_response_handler
        }};

        engine
            .read_packets_until(login_registry, |unhandled, share| {
                println!("Post mem share push.");
                if let Some(unhandled) = unhandled {
                    log::warn!(
                        "Unhandled login packet: {} with length {}",
                        unhandled.packet_id,
                        unhandled.bytes.len()
                    );
                    false // custom queries? custom forge crap maybe?
                } else {
                    println!("poll state");
                    let e = matches!(share.get::<State>().cloned().unwrap(), State::Complete);
                    println!("No deadlock pls.");
                    e
                }
            })
            .await?;

        println!("Post read.");

        if !engine.contains_data::<ProfileKey>().await {
            return Ok((engine, None));
        }

        let map_inner = engine.map_inner().await;
        let read_map = map_inner.read().await;
        let profile = read_map.get::<ProfileKey>().unwrap();
        let raw_key = read_map.get::<PlayerKey>().unwrap();
        let player_key = read_map.get::<PlayerIdentifiedKey>().unwrap();
        let shared_secret_bytes = read_map.get::<SharedSecretKey>().unwrap();

        let codec = match Codec::new(shared_secret_bytes) {
            Ok(ok) => ok,
            Err(_) => {
                engine
                    .send_packet(Disconnect {
                        reason: Chat::text("Error creating encryption stream."),
                    })
                    .await?;
                return Ok((engine, None));
            }
        };

        engine.set_codec(codec);

        if self.compression_threshold > 0 {
            engine.set_compression(self.compression_threshold);
            engine
                .send_packet(SetCompression {
                    threshold: VarInt::from(self.compression_threshold),
                })
                .await?;
            return Ok((engine, None));
        }

        let login_success = LoginSuccess {
            uuid: profile.id,
            username: LoginUsername::from(&profile.name),
            properties: (
                VarInt::try_from(profile.properties.len())?,
                profile.properties.iter().map(Into::into).collect(),
            ),
        };

        if (engine.send_packet(login_success).await).is_err() {
            engine
                .send_packet(Disconnect {
                    reason: Chat::text("Failed to encode login success packet."),
                })
                .await?;
            return Ok((engine, None));
        };

        let connection_info = ConnectionInfo {
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
            connection_info,
            profile: profile.clone(),
            channel_in,
            server_in_channel,
            raw_key: raw_key.as_ref().cloned(),
            player_key: player_key.as_ref().cloned(),
        };

        println!("Login internal complete.");
        Ok((engine, Some(authenticated_client)))
    }
}

#[derive(Copy, Clone, Debug)]
pub enum State {
    PreLogin,
    PreEncryption,
    Complete,
}

impl Key for State {
    type Value = State;
}

assign_key!(AuthServerUrl, String);
assign_key!(ForceKeyAuthentication, bool);
assign_key!(UsernameKey, LoginUsername);
assign_key!(PlayerKey, Option<MCIdentifiedKey>);
assign_key!(PlayerIdentifiedKey, Option<IdentifiedKey>);
assign_key!(VerifyTokenKey, Vec<u8>);
assign_key!(SharedSecretKey, Vec<u8>);
assign_key!(ProfileKey, GameProfile);
assign_key!(SharedSecret, Vec<u8>);
assign_key!(ServerPersonalKey, Arc<MCPrivateKey>);

#[inline]
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

pub(super) fn default_auth_server() -> String {
    "https://sessionserver.mojang.com".to_string()
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Clone, Debug)]
pub struct NotchianAuthenticationScheme {
    force_key_authentication: bool,
    compression_threshold: i32,
    #[serde(default = "default_auth_server")]
    auth_server_url: String,
}

pub async fn disconnect<'a, S: Into<String>>(
    mut context: LockedContext<BufferRegistryEngineContext<'a>>,
    message: S,
) {
    let mut reason = Chat::text(message);
    reason.modify_style(|style| style.color("red"));
    context
        .send_packet(Disconnect { reason })
        .await
        .ok()
        .unwrap_or(());
    Context::insert_data::<State>(context, State::Complete).await;
}

#[packet_handler]
fn login_start_handler<'registry>(
    mut context: LockedContext<Context<'registry>>,
    packet: LoginStart,
) -> anyhow::Result<()> {
    let state = Context::clone_data::<State>(context.clone()).await.unwrap();

    if let State::PreLogin = state {
    } else {
        disconnect(context, "Invalid state...").await;
        return Ok(());
    }

    let force_key_authentication = Context::clone_data::<ForceKeyAuthentication>(context.clone())
        .await
        .unwrap_or(false);
    Context::insert_data::<UsernameKey>(context.clone(), packet.name.clone()).await;

    if packet.sig_data.0 {
        let signature = packet
            .sig_data
            .1
            .expect("Signature data expected but not found.");
        if signature.has_expired() {
            disconnect(context.clone(), "Player key was found but expired.").await;
            return Ok(());
        }

        let mojang_der = encryption_utils::key_from_der(MOJANG_KEY)?;
        let sig_holder = packet.sig_holder.1;
        let sig_timestamp = signature.timestamp;

        let sig_holder = match sig_holder {
            None => {
                // we're not adding minor version support, that's stupid
                disconnect(context.clone(), "Signature holder not found .").await;
                return Ok(());
            }
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
            disconnect(
                context.clone(),
                format!("Key verification error: {:?}", err),
            )
            .await;
            return Ok(());
        }

        Context::insert_data::<PlayerKey>(context.clone(), Some(signature.clone())).await;
        Context::insert_data::<PlayerIdentifiedKey>(
            context.clone(),
            Some(IdentifiedKey::new(&signature.public_key.1)?),
        )
        .await;
    } else if force_key_authentication {
        disconnect(context.clone(), "Player key was expected but not found.").await;
    }

    let map_mem_hold = Context::map_inner(context.clone()).await;
    let mut map_inner = map_mem_hold.write().await;
    let server_key = map_inner.get::<ServerPersonalKey>().unwrap();

    let key_der = private_key_to_der(server_key);
    let mut verify_token = [0, 0, 0, 0];
    rand::thread_rng().fill_bytes(&mut verify_token);

    map_inner.insert::<VerifyTokenKey>(Vec::from(verify_token));

    let encryption_request = EncryptionRequest {
        server_id: ServerId::from(""),
        public_key: (VarInt::try_from(key_der.len())?, key_der),
        verify_token: (VarInt::from(4), Vec::from(verify_token)),
    };

    println!("Sending encryption request.");
    context.send_packet(encryption_request).await?;
    println!("Post send packet.");
    map_inner.insert::<State>(State::PreEncryption);
    println!("Onto next...?");
    Ok(())
}

#[packet_handler]
fn encryption_response_handler<'registry>(
    context: LockedContext<Context<'registry>>,
    packet: EncryptionResponse,
) -> anyhow::Result<()> {
    println!("Reading encryption response.");
    let map_mem_hold = Context::map_inner(context.clone()).await;
    let mut map_write = map_mem_hold.write().await;

    let state = map_write.get::<State>().unwrap();

    if !(matches!(state, State::PreEncryption)) {
        disconnect(context, "Invalid state...").await;
        return Ok(());
    }

    let verify = map_write.get::<VerifyTokenKey>().unwrap();
    let player_key = map_write.get::<PlayerIdentifiedKey>().unwrap();
    let server_key = map_write.get::<ServerPersonalKey>().unwrap();
    let _auth_server_url = map_write.get::<AuthServerUrl>().unwrap();

    if let Some(player_key) = player_key {
        match packet.response_data {
            EncryptionResponseData::VerifyTokenData(_) => {
                disconnect(context, "Salt not found but expected.").await;
                return Ok(());
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
                    disconnect(context, "Verification mismatch.").await;
                    return Ok(());
                }
            }
            EncryptionResponseData::MessageSignature { .. } => {
                disconnect(context, "Salt found while player key is not.").await;
                return Ok(());
            }
        }
    }

    let shared_secret = server_key.decrypt(
        encryption_utils::Padding::PKCS1v15Encrypt,
        &packet.shared_secret.1,
    )?;

    let _generated_server_id = hash_server_id("", &shared_secret, &private_key_to_der(server_key));

    let _username = match map_write.get::<UsernameKey>() {
        None => {
            disconnect(
                context.clone(),
                "No username known during encryption response.",
            )
            .await;
            return Ok(());
        }
        Some(username) => username.clone(),
    };
    let url = format!("{_auth_server_url}/session/minecraft/hasJoined?username={_username}&serverId={_generated_server_id}");

    let response = reqwest::get(url).await?;
    if response.status() == StatusCode::from_u16(204)? {
        disconnect(context, "Failed to authenticate with mojang.").await;
    } else if response.status() != StatusCode::from_u16(200)? {
        disconnect(
            context,
            format!(
                "Received a {} status code from mojang auth server.",
                response.status().as_u16()
            ),
        )
        .await;
    }

    let game_profile = response.json::<GameProfile>().await?;
    map_write.insert::<ProfileKey>(game_profile);
    map_write.insert::<SharedSecretKey>(shared_secret);
    map_write.insert::<State>(State::Complete);

    Ok(())
}
