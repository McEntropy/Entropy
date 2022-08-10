use bytes::Buf;
use futures::future::BoxFuture;
use mc_buffer::encryption::{Compressor};
use mc_chat::Chat;
use mc_registry::mappings::Mappings;
use mc_serializer::serde::ProtocolVersion;
use std::io::Cursor;
use tokio::io::{AsyncWrite, AsyncWriteExt};


pub type PacketWriterFuture<'a> = BoxFuture<'a, anyhow::Result<()>>;

pub trait PacketWriter<W: AsyncWrite + Unpin + Send + Sync>: Send + Sync {
    fn writer(&mut self) -> &mut W;

    fn compressor(&self) -> Option<&Compressor>;

    fn encrypt(&mut self, buffer: &mut Vec<u8>);

    fn protocol_version(&self) -> ProtocolVersion;

    fn send_packet<'a, Packet: Mappings<PacketType = Packet> + Send + Sync + 'a>(
        &'a mut self,
        packet: Packet,
    ) -> PacketWriterFuture<'a> {
        Box::pin(async move {
            let buffer = Packet::create_packet_buffer(self.protocol_version(), packet)?;

            let mut buffer = if let Some(compressor) = self.compressor() {
                compressor.compress(buffer)?
            } else {
                Compressor::uncompressed(buffer)?
            };

            self.encrypt(&mut buffer);

            let mut buffer = Cursor::new(buffer);

            while buffer.has_remaining() {
                self.writer().write_buf(&mut buffer).await?;
            }
            Ok(())
        })
    }

    fn disconnect_login(&mut self, reason: Chat) -> PacketWriterFuture {
        self.send_packet(mc_registry::client_bound::login::Disconnect { reason })
    }

    fn disconnect_play(&mut self, reason: Chat) -> PacketWriterFuture {
        self.send_packet(mc_registry::client_bound::play::Disconnect { reason })
    }
}
