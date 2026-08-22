//! Stable, IP-free identifiers exposed by Weaver.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A stable application address scoped to one virtual network.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AppAddr([u8; 32]);

impl AppAddr {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A stable identifier for one isolated virtual network.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NetworkId([u8; 32]);

impl NetworkId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetworkId({self})")
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for NetworkId {
    type Err = ParseIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_32_bytes("NetworkId", value)?))
    }
}

impl fmt::Debug for AppAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AppAddr({self})")
    }
}

impl fmt::Display for AppAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for AppAddr {
    type Err = ParseIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_32_bytes("AppAddr", value)?))
    }
}

/// A stable device identity scoped to one application in one virtual network.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A member identity scoped to a virtual network.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MemberId([u8; 32]);

impl MemberId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemberId({self})")
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for MemberId {
    type Err = ParseIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_32_bytes("MemberId", value)?))
    }
}

/// A compact service identifier scoped by an AppAddr.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ServiceId([u8; 16]);

impl ServiceId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceId({})", hex::encode(self.0))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({self})")
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for DeviceId {
    type Err = ParseIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_32_bytes("DeviceId", value)?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScopedVirtualAddr {
    Server { app: AppAddr },
    Client { app: AppAddr, device: DeviceId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerAddr {
    app: AppAddr,
}

impl ServerAddr {
    pub const fn new(app: AppAddr) -> Self {
        Self { app }
    }

    pub const fn app(self) -> AppAddr {
        self.app
    }

    pub const fn scoped(self) -> ScopedVirtualAddr {
        ScopedVirtualAddr::Server { app: self.app }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientAddr {
    app: AppAddr,
    device: DeviceId,
}

impl ClientAddr {
    pub const fn new(app: AppAddr, device: DeviceId) -> Self {
        Self { app, device }
    }

    pub const fn app(self) -> AppAddr {
        self.app
    }

    pub const fn device(self) -> DeviceId {
        self.device
    }

    pub const fn scoped(self) -> ScopedVirtualAddr {
        ScopedVirtualAddr::Client {
            app: self.app,
            device: self.device,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VirtualAddr {
    pub network: NetworkId,
    pub addr: ScopedVirtualAddr,
}

impl VirtualAddr {
    pub const fn server(network: NetworkId, address: ServerAddr) -> Self {
        Self {
            network,
            addr: address.scoped(),
        }
    }

    pub const fn client(network: NetworkId, address: ClientAddr) -> Self {
        Self {
            network,
            addr: address.scoped(),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseIdError {
    #[error("{kind} must be exactly 64 lowercase or uppercase hexadecimal characters")]
    InvalidEncoding { kind: &'static str },
}

fn parse_32_bytes(kind: &'static str, value: &str) -> Result<[u8; 32], ParseIdError> {
    let bytes = hex::decode(value).map_err(|_| ParseIdError::InvalidEncoding { kind })?;
    bytes
        .try_into()
        .map_err(|_| ParseIdError::InvalidEncoding { kind })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_addr_round_trips() {
        let addr = AppAddr::from_bytes([0x42; 32]);
        assert_eq!(addr.to_string().parse(), Ok(addr));
    }

    #[test]
    fn network_id_round_trips() {
        let id = NetworkId::from_bytes([0x21; 32]);
        assert_eq!(id.to_string().parse(), Ok(id));
    }

    #[test]
    fn ids_reject_wrong_lengths() {
        assert!(matches!(
            "00".parse::<DeviceId>(),
            Err(ParseIdError::InvalidEncoding { kind: "DeviceId" })
        ));
    }
}
