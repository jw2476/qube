use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Configuration for the server. Deserialised from a qube.config.toml file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub networking: NetworkingConfig,
    pub status: StatusConfig,
}

/// Networking configuration
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkingConfig {
    pub address: IpAddr,
    pub port: u16,
}

impl NetworkingConfig {
    /// The socket address from the IP address and port number.
    pub fn socket_addr(&self) -> SocketAddr {
        (self.address, self.port).into()
    }
}

impl Default for NetworkingConfig {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::UNSPECIFIED.into(),
            port: 25565,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusConfig {
    pub message: String,
    pub max_players: u32,
}

impl Default for StatusConfig {
    fn default() -> Self {
        Self {
            message: "Hello, Qube!".to_string(),
            max_players: 25,
        }
    }
}
