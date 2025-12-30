use std::{
    io::{Cursor, ErrorKind},
    net::SocketAddr,
};

use log::{debug, info, warn};
use qube_proto::{
    Handshake, HandshakeIntent, LoginStart, LoginSuccess, Packet, PingRequest, PluginMessage,
    PongResponse, Protocol, ServerStatus, ServerboundPacket, StatusResponse, VersionInfo,
    io::{ReadExt, WriteExt},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub trait AsyncReadVarInt: AsyncReadExt {
    fn read_varint(&mut self) -> impl Future<Output = std::io::Result<i32>>;
}

impl<T: AsyncReadExt + Unpin> AsyncReadVarInt for T {
    async fn read_varint(&mut self) -> std::io::Result<i32> {
        let mut value = 0_i32;

        for i in 0..5 {
            let byte: i32 = self.read_u8().await?.into();
            value |= (byte & 0b0111_1111) << (i * 7);

            if (byte & 0b1000_0000) == 0 {
                return Ok(value);
            }
        }

        Err(invalid_data("Invalid varint"))
    }
}

pub trait AsyncWriteVarInt: AsyncWriteExt {
    fn write_varint(&mut self, value: i32) -> impl Future<Output = std::io::Result<()>>;
}

impl<T: AsyncWriteExt + Unpin> AsyncWriteVarInt for T {
    async fn write_varint(&mut self, mut value: i32) -> std::io::Result<()> {
        loop {
            #[allow(clippy::cast_sign_loss)]
            let mut byte = (value & 0b0111_1111) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0b1000_0000;
            }

            self.write_u8(byte).await?;

            if value == 0 {
                return Ok(());
            }
        }
    }
}

#[derive(Debug)]
struct Client {
    stream: TcpStream,
    protocol: Protocol,
    brand: Option<String>,
}

impl Client {
    /// Sends a `Packet` to the connected peer. The packet is serialized into bytes,
    /// prefixed with its length as a varint, and written to the client's TCP stream.
    async fn send<T: Packet>(&mut self, packet: T) -> std::io::Result<()> {
        debug!("Sending: {packet:?}");

        let mut buffer = Cursor::new(Vec::new());
        WriteExt::write_varint(&mut buffer, T::OPCODE)?;
        packet.write(&mut buffer)?;
        let body = buffer.into_inner();

        let Ok(length) = i32::try_from(body.len()) else {
            return Err(invalid_data("Packet body too long"));
        };

        self.stream.write_varint(length).await?;
        self.stream.write_all(&body).await
    }
}

async fn handle(packet: ServerboundPacket, client: &mut Client) -> std::io::Result<()> {
    match packet {
        ServerboundPacket::Handshake(Handshake { intent, .. }) => {
            client.protocol = match intent {
                HandshakeIntent::Status => Protocol::Status,
                HandshakeIntent::Login | HandshakeIntent::Transfer => Protocol::Login,
            }
        }
        ServerboundPacket::StatusRequest(_) => {
            client
                .send(StatusResponse(ServerStatus {
                    version: VersionInfo {
                        name: "1.21.11".to_string(),
                        protocol: 774,
                    },
                    enforces_secure_chat: false,
                }))
                .await?;
        }
        ServerboundPacket::PingRequest(PingRequest(payload)) => {
            client.send(PongResponse(payload)).await?;
        }
        ServerboundPacket::LoginStart(LoginStart { name, uuid }) => {
            client
                .send(LoginSuccess {
                    uuid,
                    name,
                    properties: Vec::new(),
                })
                .await?;
        }
        ServerboundPacket::LoginAcknowledged(_) => client.protocol = Protocol::Configuration,
        ServerboundPacket::PluginMessage(PluginMessage { channel, data })
            if channel == ("minecraft", "brand") =>
        {
            let mut data = Cursor::new(data);
            let brand = data.read_string()?;
            info!("Client brand: {brand}");
            client.brand = Some(brand);
        }
        ServerboundPacket::PluginMessage(PluginMessage { channel, .. }) => {
            warn!("Unknown plugin channel: {channel}");
        }
    }

    Ok(())
}

fn invalid_data(message: &str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, message)
}

/// Process a client TCP connection, reading framed packets and handling them until the connection ends or an error occurs.
///
/// This function runs the connection loop for a single client: it repeatedly reads a length, reads that many bytes as a packet payload, decodes the packet according to the client's current protocol mode, and dispatches it to the handler which may update the client's state or send responses. It returns an I/O error when socket operations fail or when a decoded length is invalid (e.g., negative).
async fn process_socket(stream: TcpStream, addr: SocketAddr) -> std::io::Result<()> {
    let mut client = Client {
        stream,
        protocol: Protocol::Handshake,
        brand: None,
    };
    info!("Client at {addr} connected");

    loop {
        let length = client.stream.read_varint().await?;
        let Ok(length) = usize::try_from(length) else {
            return Err(invalid_data("Negative length"));
        };

        let mut buffer = vec![0; length];
        client.stream.read_exact(&mut buffer).await?;

        let packet = ServerboundPacket::read(Cursor::new(buffer), client.protocol)?;
        debug!("Received: {packet:?}");

        handle(packet, &mut client).await?;
    }
}

/// Starts the TCP server on 0.0.0.0:25565 and processes incoming client connections.
///
/// The server binds a listener, and spawns a task for each accepted
/// connection that delegates to `process_socket`. Each connection task logs and ignores
/// errors returned from `process_socket`.
#[tokio::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();

    let listener = TcpListener::bind("0.0.0.0:25565").await?;

    info!("Listening on 0.0.0.0:25565");

    loop {
        let (socket, addr) = listener.accept().await?;
        tokio::spawn(async move {
            match process_socket(socket, addr).await {
                Ok(()) => info!("Client at {addr} disconnected"),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    info!("Client at {addr} disconnected");
                }
                Err(e) => warn!("Closed connection to {addr} due to {e}"),
            }
        });
    }
}
