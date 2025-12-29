use std::{
    fmt::Debug,
    io::{ErrorKind, Read, Write},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::io::{ReadExt, WriteExt};

pub mod identifier;
pub mod io;

pub use identifier::*;

/// Create an invalid data error message.
pub(crate) fn invalid_data(message: &str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, message)
}

pub trait Packet: Sized + Debug + Clone + Eq {
    const OPCODE: i32;

    fn read(r: impl Read) -> std::io::Result<Self>;
    fn write(self, w: impl Write) -> std::io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Handshake,
    Status,
    Login,
    Configuration,
    Play,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeIntent {
    Status = 1,
    Login = 2,
    Transfer = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub intent: HandshakeIntent,
}
impl Packet for Handshake {
    const OPCODE: i32 = 0x0;

    fn read(mut r: impl Read) -> std::io::Result<Self> {
        Ok(Self {
            protocol_version: r.read_varint()?,
            server_address: r.read_string()?,
            server_port: r.read_u16()?,
            intent: match r.read_varint()? {
                1 => Ok(HandshakeIntent::Status),
                2 => Ok(HandshakeIntent::Login),
                3 => Ok(HandshakeIntent::Transfer),
                _ => Err(invalid_data("Invalid handshake intent.")),
            }?,
        })
    }

    fn write(self, mut w: impl Write) -> std::io::Result<()> {
        w.write_varint(self.protocol_version)?;
        w.write_string(&self.server_address)?;
        w.write_u16(self.server_port)?;
        w.write_varint(match self.intent {
            HandshakeIntent::Status => 1,
            HandshakeIntent::Login => 2,
            HandshakeIntent::Transfer => 3,
        })?;

        Ok(())
    }
}

/// A status request packet from the client, the server should respond with a `StatusResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusRequest;
impl Packet for StatusRequest {
    const OPCODE: i32 = 0x0;

    fn read(_: impl Read) -> std::io::Result<Self> {
        Ok(Self)
    }

    fn write(self, _: impl Write) -> std::io::Result<()> {
        Ok(())
    }
}

/// A ping request packet from the client, the server should respond with a `PingResponse` using the
/// same payload value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PingRequest(pub i64);
impl Packet for PingRequest {
    const OPCODE: i32 = 0x1;

    fn read(mut r: impl Read) -> std::io::Result<Self> {
        Ok(Self(r.read_i64()?))
    }

    fn write(self, mut w: impl Write) -> std::io::Result<()> {
        w.write_i64(self.0)
    }
}

/// Information about the server version sent to the client during a status check.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    pub name: String,
    pub protocol: u32,
}

/// Information about the server send to the client during a status check.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ServerStatus {
    pub version: VersionInfo,
    #[serde(rename = "enforcesSecureChat")]
    pub enforces_secure_chat: bool,
}

/// A response to `StatusRequest` containing information about the server status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusResponse(pub ServerStatus);
impl Packet for StatusResponse {
    const OPCODE: i32 = 0x0;

    fn read(mut r: impl Read) -> std::io::Result<Self> {
        let string = r.read_string()?;
        let decoded = serde_json::from_str(&string)?;
        Ok(Self(decoded))
    }

    fn write(self, mut w: impl Write) -> std::io::Result<()> {
        let string = serde_json::to_string(&self.0)?;
        w.write_string(&string)
    }
}

/// A response to `PingRequest` containing the same payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PongResponse(pub i64);
impl Packet for PongResponse {
    const OPCODE: i32 = 0x01;

    fn read(mut r: impl Read) -> std::io::Result<Self> {
        Ok(Self(r.read_i64()?))
    }

    fn write(self, mut w: impl Write) -> std::io::Result<()> {
        w.write_i64(self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginStart {
    pub name: String,
    pub uuid: Uuid,
}

impl Packet for LoginStart {
    const OPCODE: i32 = 0x00;

    fn read(mut r: impl Read) -> std::io::Result<Self> {
        Ok(Self {
            name: r.read_string()?,
            uuid: Uuid::from_u128(r.read_u128()?),
        })
    }

    fn write(self, mut w: impl Write) -> std::io::Result<()> {
        w.write_string(&self.name)?;
        w.write_u128(self.uuid.as_u128())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginAcknowledged;
impl Packet for LoginAcknowledged {
    const OPCODE: i32 = 0x3;

    fn read(_: impl Read) -> std::io::Result<Self> {
        Ok(Self)
    }

    fn write(self, _: impl Write) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameProfileProperty {
    pub name: String,
    pub value: String,
    pub signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginSuccess {
    pub uuid: Uuid,
    pub name: String,
    pub properties: Vec<GameProfileProperty>,
}
impl Packet for LoginSuccess {
    const OPCODE: i32 = 0x2;

    fn read(mut r: impl Read) -> std::io::Result<Self> {
        fn read_property(mut r: impl Read) -> std::io::Result<GameProfileProperty> {
            Ok(GameProfileProperty {
                name: r.read_string()?,
                value: r.read_string()?,
                signature: if r.read_bool()? {
                    Some(r.read_string()?)
                } else {
                    None
                },
            })
        }

        Ok(Self {
            uuid: Uuid::from_u128(r.read_u128()?),
            name: r.read_string()?,
            properties: (0..r.read_varint()?)
                .map(|_| read_property(&mut r))
                .collect::<std::io::Result<Vec<_>>>()?,
        })
    }

    fn write(self, mut w: impl Write) -> std::io::Result<()> {
        w.write_u128(self.uuid.as_u128())?;
        w.write_string(&self.name)?;

        let Ok(property_count) = self.properties.len().try_into() else {
            return Err(invalid_data("Too many game profile properties."));
        };
        w.write_varint(property_count)?;

        for property in self.properties {
            w.write_string(&property.name)?;
            w.write_string(&property.value)?;

            w.write_bool(property.signature.is_some())?;
            if let Some(signature) = property.signature {
                w.write_string(&signature)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginMessage {
    pub channel: Identifier,
    pub data: Vec<u8>,
}
impl Packet for PluginMessage {
    const OPCODE: i32 = 0x2;

    fn read(mut r: impl Read) -> std::io::Result<Self> {
        let channel = Identifier::try_from(r.read_string()?.as_str())
            .map_err(|e| invalid_data(&format!("Invalid identifier due to {e}")))?;
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        Ok(Self { channel, data })
    }

    fn write(self, mut w: impl Write) -> std::io::Result<()> {
        w.write_string(&self.channel.to_string())?;
        w.write_all(&self.data)
    }
}

macro_rules! impl_packet_group {
    (pub enum $name:ident { $($variant:ident($ty:ty) in $protocol:path,)* }) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum $name {
            $($variant($ty),)*
        }

        impl $name {
            /// Read a `$name` using the current protocol.
            pub fn read(mut r: impl Read, protocol: Protocol) -> std::io::Result<Self> {
                let opcode = r.read_varint()?;
                match (protocol, opcode) {
                    $(($protocol, <$ty>::OPCODE) => <$ty>::read(r).map($name::$variant),)*
                    (protocol, opcode) => Err(invalid_data(&format!(
                        "Unknown opcode {opcode} for {protocol:?}"
                    ))),
                }
            }

            /// Write a `$name`.
            pub fn write(self, w: impl Write) -> std::io::Result<()> {
                match self {
                    $($name::$variant(x) => x.write(w),)*
                }
            }
        }
    };
}

impl_packet_group! {
    pub enum ServerboundPacket {
        Handshake(Handshake) in Protocol::Handshake,
        StatusRequest(StatusRequest) in Protocol::Status,
        PingRequest(PingRequest) in Protocol::Status,
        LoginStart(LoginStart) in Protocol::Login,
        LoginAcknowledged(LoginAcknowledged) in Protocol::Login,
        PluginMessage(PluginMessage) in Protocol::Configuration,
    }
}

impl_packet_group! {
    pub enum ClientboundPacket {
        StatusResponse(StatusResponse) in Protocol::Status,
        PongResponse(PongResponse) in Protocol::Status,
        LoginSuccess(LoginSuccess) in Protocol::Login,
        PluginMessage(PluginMessage) in Protocol::Configuration,
    }
}
