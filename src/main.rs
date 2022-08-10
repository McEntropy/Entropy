extern crate core;

use crate::client::authentication::AuthHandler;
use crate::server::Server;
use crate::ServerList::TrueAnswer;
use log::LevelFilter;
use mc_chat::Chat;
use serde::de::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod client;
pub mod packet;
mod server;
mod server_client_mingle;

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
#[serde(untagged)]
pub enum ServerList {
    TrueAnswer {
        motd: Chat,
        max_players: i32,
    },
    JustUnder {
        motd: Chat,
    },
    StaticInfo {
        motd: Chat,
        online_players: i32,
        max_players: i32,
    },
    Custom,
}

impl Default for ServerList {
    fn default() -> Self {
        TrueAnswer {
            motd: Chat::text("Hello World!"),
            max_players: 100,
        }
    }
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct TimeFormat(String);

impl Default for TimeFormat {
    fn default() -> Self {
        TimeFormat("[%Y-%m-%d][%H:%M:%S]".to_string())
    }
}

impl ToString for TimeFormat {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[inline]
fn info_filter() -> LevelFilter {
    LevelFilter::Info
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct LoggerConfiguration {
    #[serde(default = "info_filter")]
    level: LevelFilter,
    #[serde(skip_serializing_if = "Option::is_none")]
    out_file_handle: Option<PathBuf>,
    #[serde(default)]
    time_format: TimeFormat,
}

impl Default for LoggerConfiguration {
    fn default() -> Self {
        Self {
            level: LevelFilter::Info,
            out_file_handle: None,
            time_format: TimeFormat::default(),
        }
    }
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct BindString(String);

impl Default for BindString {
    fn default() -> Self {
        BindString("0.0.0.0:25565".to_string())
    }
}

impl ToString for BindString {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug, Default)]
pub struct ServerConfiguration {
    #[serde(default)]
    logger: LoggerConfiguration,
    #[serde(default)]
    bind: BindString,
    #[serde(default)]
    server_list: ServerList,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preview_chat: Option<bool>,
    #[serde(default)]
    auth: AuthHandler,
}

impl ServerConfiguration {
    pub fn from_file<P: AsRef<Path>>(path: P) -> serde_json::Result<ServerConfiguration> {
        if !Path::exists(path.as_ref()) {
            println!(
                "Could not find a config file, generating one from scratch in {:?}.",
                path.as_ref()
            );
            let path_parent =
                Path::parent(path.as_ref()).expect("Config does not have an existing parent.");
            if Path::exists(path_parent) && Path::is_file(path_parent) {
                panic!("Cannot create configuration in regular file. This should never happen...")
            } else if !Path::exists(path_parent) {
                std::fs::create_dir_all(path_parent).map_err(|_| {
                    serde_json::Error::custom("Failed to create config parent directory.")
                })?;
            }
            let file_handle = File::create(path)
                .map_err(|_| serde_json::Error::custom("Failed to create config file."))?;
            let config = ServerConfiguration::default();
            serde_json::to_writer_pretty(file_handle, &config)?;
            return Ok(config);
        }

        let file_handle = File::open(path)
            .map_err(|_| serde_json::Error::custom("Failed to open configuration file handle."))?;
        serde_json::from_reader(file_handle)
    }
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let server_configuration = ServerConfiguration::from_file(
        std::env::var("ENTROPY_CONFIG_LOCATION")
            .ok()
            .unwrap_or_else(|| String::from("./config.json")),
    )?;

    let time_format = server_configuration.logger.time_format.to_string();

    let mut dispatch = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} [{}/{}]: {}",
                chrono::Local::now().format(&time_format),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(server_configuration.logger.level)
        .chain(std::io::stdout());

    if let Some(file_out) = server_configuration.logger.out_file_handle.as_ref() {
        dispatch = dispatch.chain(fern::log_file(file_out)?);
    }

    dispatch.apply()?;

    log::info!("Log dispatcher and server configuration successfully loaded.");
    log::info!("Detected server configuration: {:?}", server_configuration);

    let server_private_key = Arc::new(encryption_utils::new_key()?);
    let server_configuration = Arc::new(server_configuration);

    let (mut server, server_in_channel) = Server::create_server(Arc::clone(&server_configuration))?;
    tokio::spawn(async move { server.spin_read().await });

    client::worker::poll_clients_continuously(
        Arc::clone(&server_private_key),
        Arc::clone(&server_configuration),
        server_in_channel,
    )
    .await?;

    Ok(())
}

#[macro_export]
macro_rules! simple_attach {
    ($packet:ty, $registry:ident, $handler:expr) => {
        <$packet>::attach_to_register(&mut $registry, $handler);
    };
}
