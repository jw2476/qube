use std::{
    fmt::Display,
    io::{Cursor, ErrorKind, Read, Write},
    net::SocketAddr,
};

use log::{debug, info, warn};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

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

pub trait ReadExt: Read {
    fn read_u8(&mut self) -> std::io::Result<u8>;
    fn read_u16(&mut self) -> std::io::Result<u16>;
    fn read_u128(&mut self) -> std::io::Result<u128>;

    fn read_i64(&mut self) -> std::io::Result<i64>;

    fn read_varint(&mut self) -> std::io::Result<i32>;
    fn read_varlong(&mut self) -> std::io::Result<i64>;

    fn read_string(&mut self) -> std::io::Result<String>;
}

impl<T: Read> ReadExt for T {
    fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buffer = [0; 1];
        self.read_exact(&mut buffer)?;
        Ok(u8::from_be_bytes(buffer))
    }

    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut buffer = [0; 2];
        self.read_exact(&mut buffer)?;
        Ok(u16::from_be_bytes(buffer))
    }

    fn read_u128(&mut self) -> std::io::Result<u128> {
        let mut buffer = [0; 16];
        self.read_exact(&mut buffer)?;
        Ok(u128::from_be_bytes(buffer))
    }

    fn read_i64(&mut self) -> std::io::Result<i64> {
        let mut buffer = [0; 8];
        self.read_exact(&mut buffer)?;
        Ok(i64::from_be_bytes(buffer))
    }

    fn read_varint(&mut self) -> std::io::Result<i32> {
        let mut value = 0_i32;

        for i in 0..5 {
            let byte: i32 = self.read_u8()?.into();
            value |= (byte & 0b0111_1111) << (i * 7);

            if (byte & 0b1000_0000) == 0 {
                return Ok(value);
            }
        }

        Err(invalid_data("Invalid varint"))
    }

    fn read_varlong(&mut self) -> std::io::Result<i64> {
        let mut value = 0_i64;

        for i in 0..10 {
            let byte: i64 = self.read_u8()?.into();
            value |= (byte & 0b0111_1111) << (i * 7);

            if (byte & 0b1000_0000) == 0 {
                return Ok(value);
            }
        }

        Err(invalid_data("Invalid varlong"))
    }

    fn read_string(&mut self) -> std::io::Result<String> {
        let Ok(length): Result<usize, _> = self.read_varint()?.try_into() else {
            return Err(invalid_data("Negative string length"));
        };

        let mut buffer = vec![0_u8; length];
        self.read_exact(&mut buffer)?;

        let Ok(string) = String::from_utf8(buffer) else {
            return Err(invalid_data("Non-UTF8 string"));
        };
        Ok(string)
    }
}

pub trait WriteExt: Write {
    fn write_u8(&mut self, value: u8) -> std::io::Result<()>;
    fn write_u16(&mut self, value: u16) -> std::io::Result<()>;
    fn write_u128(&mut self, value: u128) -> std::io::Result<()>;

    fn write_i64(&mut self, value: i64) -> std::io::Result<()>;

    fn write_bool(&mut self, value: bool) -> std::io::Result<()>;

    fn write_varint(&mut self, value: i32) -> std::io::Result<()>;
    fn write_varlong(&mut self, value: i64) -> std::io::Result<()>;

    fn write_string(&mut self, value: &str) -> std::io::Result<()>;
}

impl<T: Write> WriteExt for T {
    fn write_u8(&mut self, value: u8) -> std::io::Result<()> {
        self.write_all(&[value])
    }

    fn write_u16(&mut self, value: u16) -> std::io::Result<()> {
        self.write_all(&value.to_be_bytes())
    }

    fn write_u128(&mut self, value: u128) -> std::io::Result<()> {
        self.write_all(&value.to_be_bytes())
    }

    fn write_i64(&mut self, value: i64) -> std::io::Result<()> {
        self.write_all(&value.to_be_bytes())
    }

    fn write_bool(&mut self, value: bool) -> std::io::Result<()> {
        self.write_u8(if value { 1 } else { 0 })
    }

    fn write_varint(&mut self, mut value: i32) -> std::io::Result<()> {
        loop {
            #[allow(clippy::cast_sign_loss)]
            let mut byte = (value & 0b0111_1111) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0b1000_0000;
            }

            self.write_u8(byte)?;

            if value == 0 {
                return Ok(());
            }
        }
    }

    fn write_varlong(&mut self, mut value: i64) -> std::io::Result<()> {
        loop {
            #[allow(clippy::cast_sign_loss)]
            let mut byte = (value & 0b0111_1111) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0b1000_0000;
            }

            self.write_u8(byte)?;

            if value == 0 {
                return Ok(());
            }
        }
    }

    fn write_string(&mut self, value: &str) -> std::io::Result<()> {
        let Ok(length) = i32::try_from(value.len()) else {
            return Err(invalid_data("String too long"));
        };

        self.write_varint(length)?;
        self.write_all(value.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolMode {
    Handshake = 0,
    Status = 1,
    Login = 2,
    Play = 3,
    Configuration = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeIntent {
    Status = 1,
    Login = 2,
    Transfer = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PingRequest {
    timestamp: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier {
    namespace: String,
    value: String,
}

impl Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.value)
    }
}

impl<T: AsRef<str>> From<T> for Identifier {
    fn from(value: T) -> Self {
        let value = value.as_ref();
        let (namespace, value) = value.split_once(':').unwrap_or(("minecraft", value));
        Self {
            namespace: namespace.to_string(),
            value: value.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerboundPacket {
    Handshake {
        protocol_version: i32,
        server_address: String,
        server_port: u16,
        intent: HandshakeIntent,
    },
    StatusRequest,
    PingRequest(i64),
    LoginStart {
        name: String,
        uuid: Uuid,
    },
    LoginAcknowledged,
    PluginMessage {
        channel: Identifier,
        data: Vec<u8>,
    },
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    name: String,
    protocol: u32,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ServerStatus {
    version: VersionInfo,
    #[serde(rename = "enforcesSecureChat")]
    enforces_secure_chat: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameProfileProperty {
    name: String,
    value: String,
    signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientboundPacket {
    StatusResponse(ServerStatus),
    PongResponse(i64),
    LoginSuccess {
        uuid: Uuid,
        name: String,
        properties: Vec<GameProfileProperty>,
    },
}

/// Decodes a serverbound packet using the Handshake protocol from the provided reader.
fn decode_handshake(mut packet: impl Read) -> std::io::Result<ServerboundPacket> {
    let 0x0 = packet.read_varint()? else {
        return Err(invalid_data("Handshake opcode must be 0x0"));
    };

    let protocol_version = packet.read_varint()?;
    let server_address = packet.read_string()?;
    let server_port = packet.read_u16()?;
    let intent = match packet.read_varint()? {
        1 => Ok(HandshakeIntent::Status),
        2 => Ok(HandshakeIntent::Login),
        3 => Ok(HandshakeIntent::Transfer),
        _ => Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "Invalid handshake intent.",
        )),
    }?;

    Ok(ServerboundPacket::Handshake {
        protocol_version,
        server_address,
        server_port,
        intent,
    })
}

/// Decodes a serverbound packet using the Status protocol from the provided reader.
fn decode_status(mut packet: impl Read) -> std::io::Result<ServerboundPacket> {
    let opcode = packet.read_varint()?;
    match opcode {
        0x0 => Ok(ServerboundPacket::StatusRequest),
        0x1 => packet.read_i64().map(ServerboundPacket::PingRequest),
        other => Err(invalid_data(&format!("Unknown status opcode: {other}"))),
    }
}

fn decode_login(mut packet: impl Read) -> std::io::Result<ServerboundPacket> {
    let opcode = packet.read_varint()?;
    match opcode {
        0x0 => {
            let name = packet.read_string()?;
            let uuid = Uuid::from_u128(packet.read_u128()?);
            Ok(ServerboundPacket::LoginStart { name, uuid })
        }
        0x3 => Ok(ServerboundPacket::LoginAcknowledged),
        other => Err(invalid_data(&format!("Unknown login opcode: {other}"))),
    }
}

fn decode_configuration(mut packet: impl Read) -> std::io::Result<ServerboundPacket> {
    let opcode = packet.read_varint()?;
    match opcode {
        0x02 => {
            let channel = Identifier::from(packet.read_string()?);
            let mut data = Vec::new();
            packet.read_to_end(&mut data)?;
            Ok(ServerboundPacket::PluginMessage { channel, data })
        }
        other => Err(invalid_data(&format!(
            "Unknown configuration opcode: {other}"
        ))),
    }
}

/// Dispatches packet decoding according to the current protocol mode.
fn read_packet(packet: impl Read, protocol: ProtocolMode) -> std::io::Result<ServerboundPacket> {
    match protocol {
        ProtocolMode::Handshake => decode_handshake(packet),
        ProtocolMode::Status => decode_status(packet),
        ProtocolMode::Login => decode_login(packet),
        ProtocolMode::Configuration => decode_configuration(packet),
        _ => Err(invalid_data("Unknown protocol mode")),
    }
}

fn write_packet(mut buffer: impl Write, packet: ClientboundPacket) -> std::io::Result<()> {
    match packet {
        ClientboundPacket::StatusResponse(payload) => {
            buffer.write_varint(0x0)?;
            buffer.write_string(&serde_json::to_string(&payload)?)?;
        }
        ClientboundPacket::PongResponse(payload) => {
            buffer.write_varint(0x1)?;
            buffer.write_i64(payload)?;
        }
        ClientboundPacket::LoginSuccess {
            uuid,
            name,
            properties,
        } => {
            buffer.write_varint(0x2)?;
            buffer.write_u128(uuid.as_u128())?;
            buffer.write_string(&name)?;

            let Ok(properties_len) = i32::try_from(properties.len()) else {
                return Err(invalid_data("Too many game profile properties"));
            };

            buffer.write_varint(properties_len)?;
            for property in properties {
                buffer.write_string(&property.name)?;
                buffer.write_string(&property.value)?;
                buffer.write_bool(property.signature.is_some())?;
                if let Some(signature) = property.signature {
                    buffer.write_string(&signature)?;
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct Client {
    stream: TcpStream,
    protocol_mode: ProtocolMode,
    brand: Option<String>,
}

impl Client {
    /// Sends a `ClientboundPacket` to the connected peer. The packet is serialized into bytes, prefixed with its length as a varint, and written to the client's TCP stream.
    async fn send(&mut self, packet: ClientboundPacket) -> std::io::Result<()> {
        debug!("Sending: {packet:?}");

        let mut buffer = Cursor::new(Vec::new());
        write_packet(&mut buffer, packet)?;
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
        ServerboundPacket::Handshake { intent, .. } => {
            client.protocol_mode = match intent {
                HandshakeIntent::Status => ProtocolMode::Status,
                HandshakeIntent::Login | HandshakeIntent::Transfer => ProtocolMode::Login,
            }
        }
        ServerboundPacket::StatusRequest => {
            client
                .send(ClientboundPacket::StatusResponse(ServerStatus {
                    version: VersionInfo {
                        name: "1.21.11".to_string(),
                        protocol: 774,
                    },
                    enforces_secure_chat: false,
                }))
                .await?;
        }
        ServerboundPacket::PingRequest(payload) => {
            client
                .send(ClientboundPacket::PongResponse(payload))
                .await?;
        }
        ServerboundPacket::LoginStart { name, uuid } => {
            client
                .send(ClientboundPacket::LoginSuccess {
                    uuid,
                    name,
                    properties: Vec::new(),
                })
                .await?;
        }
        ServerboundPacket::LoginAcknowledged => client.protocol_mode = ProtocolMode::Configuration,
        ServerboundPacket::PluginMessage { channel, data }
            if channel == Identifier::from("brand") =>
        {
            let mut data = Cursor::new(data);
            let brand = data.read_string()?;
            info!("Client brand: {brand}");
            client.brand = Some(brand);
        }
        ServerboundPacket::PluginMessage { channel, .. } => {
            warn!("Unknown plugin channel: {channel}")
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
        protocol_mode: ProtocolMode::Handshake,
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

        let packet = read_packet(Cursor::new(buffer), client.protocol_mode)?;
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
