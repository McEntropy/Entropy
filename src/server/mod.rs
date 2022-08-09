use crate::server_client_mingle::{ClientAction, ServerAction};

pub struct Server {
    pub clients: Vec<ServerClient>,
}

pub struct ClientInformation {
    protocol_version:
}

pub struct ServerClient {
    write_channel: flume::Sender<ServerAction>,
    read_channel: flume::Receiver<ClientAction>,
}
