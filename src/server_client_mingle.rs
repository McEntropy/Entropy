use crate::server::ServerClient;

pub struct StatusAck {
    online_players: usize,
    favicon: Option<String>,
}

impl StatusAck {
    pub fn new(online_players: usize, favicon: Option<String>) -> Self {
        Self {
            online_players,
            favicon,
        }
    }

    pub fn online_players(&self) -> usize {
        self.online_players
    }

    pub fn favicon(&self) -> Option<String> {
        self.favicon.as_ref().cloned()
    }
}

// C2S info
pub enum ClientAction {
    AddClient(Box<ServerClient>),
    RemoveClient(uuid::Uuid),
    AckPlayerCount(flume::Sender<StatusAck>),
}

// S2C info
pub enum ServerAction {}
