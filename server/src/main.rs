use std::io::{Cursor, ErrorKind, Read, Write};

use log::{debug, info, warn};
use serde::Serialize;
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

        todo!()
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

        todo!()
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

        todo!()
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

    fn write_i64(&mut self, value: i64) -> std::io::Result<()>;

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

    fn write_i64(&mut self, value: i64) -> std::io::Result<()> {
        self.write_all(&value.to_be_bytes())
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
pub enum ServerboundPacket {
    Handshake {
        protocol_version: i32,
        server_address: String,
        server_port: u16,
        intent: HandshakeIntent,
    },
    StatusRequest,
    PingRequest(i64),
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
pub enum ClientboundPacket {
    StatusResponse(ServerStatus),
    PongResponse(i64),
}

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

fn decode_status(mut packet: impl Read) -> std::io::Result<ServerboundPacket> {
    let opcode = packet.read_varint()?;
    match opcode {
        0x0 => Ok(ServerboundPacket::StatusRequest),
        0x1 => packet.read_i64().map(ServerboundPacket::PingRequest),
        _ => todo!(),
    }
}

fn read_packet(packet: impl Read, protocol: ProtocolMode) -> std::io::Result<ServerboundPacket> {
    match protocol {
        ProtocolMode::Handshake => decode_handshake(packet),
        ProtocolMode::Status => decode_status(packet),
        _ => todo!(),
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
    }

    Ok(())
}

#[derive(Debug)]
pub struct Client {
    stream: TcpStream,
    protocol_mode: ProtocolMode,
}

impl Client {
    pub async fn send(&mut self, packet: ClientboundPacket) -> std::io::Result<()> {
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

pub async fn handle(packet: ServerboundPacket, client: &mut Client) -> std::io::Result<()> {
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
    }

    Ok(())
}

fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, message)
}

async fn process_socket(stream: TcpStream) -> std::io::Result<()> {
    let mut client = Client {
        stream,
        protocol_mode: ProtocolMode::Handshake,
    };
    info!("Client connected");

    loop {
        let length = client.stream.read_varint().await?;
        let Ok(length) = usize::try_from(length) else {
            return Err(invalid_data("Negative length"));
        };

        let mut buffer = vec![0; length];
        client.stream.read_exact(&mut buffer).await?;

        let packet = read_packet(Cursor::new(buffer), client.protocol_mode)?;
        debug!("{packet:?}");

        handle(packet, &mut client).await?;
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();

    let listener = TcpListener::bind("0.0.0.0:25565").await?;

    info!("Listening on 0.0.0.0:25565");

    loop {
        let (socket, addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = process_socket(socket).await {
                warn!("Closed connection to {addr} due to {e}");
            }
        })
        .await?;
    }
}
