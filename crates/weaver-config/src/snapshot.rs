use std::collections::{HashMap, HashSet};
use std::fmt;

use bytes::Bytes;
use thiserror::Error;
use weaver_core::{AppAddr, MemberId, NetworkId, VirtualName};
use weaver_crypto::{
    AdminCertificate, AppBinding, AppRegistration, CertificateError, EndpointBinding,
    MemberCertificate, NetworkRootPublic, VerifiedAdmin, VerifiedApp, VerifiedMember,
};
use zeroize::Zeroizing;

const SNAPSHOT_MAGIC_V1: &[u8; 8] = b"WVRSNP\0\x01";
const SNAPSHOT_MAGIC_V2: &[u8; 8] = b"WVRSNP\0\x02";
const MAX_MEMBERS: usize = 256;
const MAX_APPS: usize = 256;
const MAX_BINDINGS: usize = 1024;
const MAX_VIRTUAL_DNS_RECORDS: usize = 1024;
const MAX_RELAYS: usize = 64;
const MAX_PRESENCE_SERVICES: usize = 64;
const MAX_ADMIN_KEYS: usize = 16;
const MAX_REVOKED_SERIALS: usize = 4096;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_URL_BYTES: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminKey {
    pub certificate: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayRoles(u32);

impl RelayRoles {
    pub const DATA_RELAY: Self = Self(1 << 0);
    pub const BOOTSTRAP: Self = Self(1 << 1);
    pub const PRESENCE: Self = Self(1 << 2);

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayDescriptor {
    pub endpoint_id: [u8; 32],
    pub url: String,
    pub roles: RelayRoles,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceServiceDescriptor {
    pub endpoint_id: [u8; 32],
    pub url: String,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualDnsRecord {
    pub name: VirtualName,
    pub app_addr: AppAddr,
    pub expires_at_ms: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EpochSecrets {
    presence_index_seed: Zeroizing<[u8; 32]>,
    presence_encryption_seed: Zeroizing<[u8; 32]>,
    lan_discovery_seed: Zeroizing<[u8; 32]>,
    relay_access_seed: Zeroizing<[u8; 32]>,
}

impl EpochSecrets {
    pub fn generate() -> Result<Self, SnapshotError> {
        let mut raw = Zeroizing::new([[0_u8; 32]; 4]);
        getrandom::fill(raw.as_mut().as_flattened_mut())
            .map_err(|_| SnapshotError::RandomnessUnavailable)?;
        Ok(Self::from_bytes(*raw))
    }

    pub fn from_bytes(raw: [[u8; 32]; 4]) -> Self {
        Self {
            presence_index_seed: Zeroizing::new(raw[0]),
            presence_encryption_seed: Zeroizing::new(raw[1]),
            lan_discovery_seed: Zeroizing::new(raw[2]),
            relay_access_seed: Zeroizing::new(raw[3]),
        }
    }

    pub fn expose_bytes(&self) -> [[u8; 32]; 4] {
        [
            *self.presence_index_seed,
            *self.presence_encryption_seed,
            *self.lan_discovery_seed,
            *self.relay_access_seed,
        ]
    }
}

impl fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EpochSecrets([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub flags: u32,
    pub max_members: u16,
    pub max_services_per_binding: u16,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            flags: 0,
            max_members: MAX_MEMBERS as u16,
            max_services_per_binding: 64,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfigV1 {
    pub network_id: NetworkId,
    pub epoch: u64,
    pub revision: u64,
    pub previous_hash: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub admin_keys: Vec<AdminKey>,
    pub members: Vec<Bytes>,
    pub endpoint_bindings: Vec<Bytes>,
    pub revoked_serials: Vec<u64>,
    pub apps: Vec<Bytes>,
    pub app_bindings: Vec<Bytes>,
    pub virtual_dns: Vec<VirtualDnsRecord>,
    pub relays: Vec<RelayDescriptor>,
    pub presence_services: Vec<PresenceServiceDescriptor>,
    pub epoch_secrets: EpochSecrets,
    pub policies: NetworkPolicy,
}

impl NetworkConfigV1 {
    pub fn to_bytes(&self) -> Result<Bytes, SnapshotError> {
        self.validate_shape()?;
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC_V2);
        out.extend_from_slice(self.network_id.as_bytes());
        push_u64(&mut out, self.epoch);
        push_u64(&mut out, self.revision);
        out.extend_from_slice(&self.previous_hash);
        push_u64(&mut out, self.issued_at_ms);
        push_u64(&mut out, self.expires_at_ms);

        push_count(&mut out, self.admin_keys.len())?;
        for key in &self.admin_keys {
            push_blob(&mut out, &key.certificate)?;
        }
        push_blobs(&mut out, &self.members)?;
        push_blobs(&mut out, &self.endpoint_bindings)?;
        push_count(&mut out, self.revoked_serials.len())?;
        for serial in &self.revoked_serials {
            push_u64(&mut out, *serial);
        }
        push_blobs(&mut out, &self.apps)?;
        push_blobs(&mut out, &self.app_bindings)?;
        push_count(&mut out, self.virtual_dns.len())?;
        for record in &self.virtual_dns {
            push_string(&mut out, record.name.as_str())?;
            out.extend_from_slice(record.app_addr.as_bytes());
            push_u64(&mut out, record.expires_at_ms);
        }
        push_count(&mut out, self.relays.len())?;
        for relay in &self.relays {
            out.extend_from_slice(&relay.endpoint_id);
            push_string(&mut out, &relay.url)?;
            push_u32(&mut out, relay.roles.bits());
            push_u64(&mut out, relay.expires_at_ms);
        }
        push_count(&mut out, self.presence_services.len())?;
        for service in &self.presence_services {
            out.extend_from_slice(&service.endpoint_id);
            push_string(&mut out, &service.url)?;
            push_u64(&mut out, service.expires_at_ms);
        }
        for secret in self.epoch_secrets.expose_bytes() {
            out.extend_from_slice(&secret);
        }
        push_u32(&mut out, self.policies.flags);
        out.extend_from_slice(&self.policies.max_members.to_be_bytes());
        out.extend_from_slice(&self.policies.max_services_per_binding.to_be_bytes());
        Ok(Bytes::from(out))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotError> {
        let mut decoder = Decoder::new(bytes);
        let has_virtual_dns = if bytes.starts_with(SNAPSHOT_MAGIC_V2) {
            decoder.magic(SNAPSHOT_MAGIC_V2)?;
            true
        } else if bytes.starts_with(SNAPSHOT_MAGIC_V1) {
            decoder.magic(SNAPSHOT_MAGIC_V1)?;
            false
        } else {
            return Err(SnapshotError::MalformedWire);
        };
        let network_id = NetworkId::from_bytes(decoder.array()?);
        let epoch = decoder.u64()?;
        let revision = decoder.u64()?;
        let previous_hash = decoder.array()?;
        let issued_at_ms = decoder.u64()?;
        let expires_at_ms = decoder.u64()?;
        let admin_count = decoder.count(MAX_ADMIN_KEYS)?;
        let mut admin_keys = Vec::with_capacity(admin_count);
        for _ in 0..admin_count {
            admin_keys.push(AdminKey {
                certificate: decoder.blob()?,
            });
        }
        let members = decoder.blobs(MAX_MEMBERS)?;
        let endpoint_bindings = decoder.blobs(MAX_MEMBERS)?;
        let revoked_count = decoder.count(MAX_REVOKED_SERIALS)?;
        let mut revoked_serials = Vec::with_capacity(revoked_count);
        for _ in 0..revoked_count {
            revoked_serials.push(decoder.u64()?);
        }
        let apps = decoder.blobs(MAX_APPS)?;
        let app_bindings = decoder.blobs(MAX_BINDINGS)?;
        let virtual_dns = if has_virtual_dns {
            let virtual_dns_count = decoder.count(MAX_VIRTUAL_DNS_RECORDS)?;
            let mut records = Vec::with_capacity(virtual_dns_count);
            for _ in 0..virtual_dns_count {
                records.push(VirtualDnsRecord {
                    name: VirtualName::new(decoder.string()?)
                        .map_err(|_| SnapshotError::InvalidVirtualName)?,
                    app_addr: AppAddr::from_bytes(decoder.array()?),
                    expires_at_ms: decoder.u64()?,
                });
            }
            records
        } else {
            Vec::new()
        };
        let relay_count = decoder.count(MAX_RELAYS)?;
        let mut relays = Vec::with_capacity(relay_count);
        for _ in 0..relay_count {
            relays.push(RelayDescriptor {
                endpoint_id: decoder.array()?,
                url: decoder.string()?,
                roles: RelayRoles::from_bits(decoder.u32()?),
                expires_at_ms: decoder.u64()?,
            });
        }
        let presence_count = decoder.count(MAX_PRESENCE_SERVICES)?;
        let mut presence_services = Vec::with_capacity(presence_count);
        for _ in 0..presence_count {
            presence_services.push(PresenceServiceDescriptor {
                endpoint_id: decoder.array()?,
                url: decoder.string()?,
                expires_at_ms: decoder.u64()?,
            });
        }
        let epoch_secrets = EpochSecrets::from_bytes([
            decoder.array()?,
            decoder.array()?,
            decoder.array()?,
            decoder.array()?,
        ]);
        let policies = NetworkPolicy {
            flags: decoder.u32()?,
            max_members: decoder.u16()?,
            max_services_per_binding: decoder.u16()?,
        };
        decoder.finish()?;
        let config = Self {
            network_id,
            epoch,
            revision,
            previous_hash,
            issued_at_ms,
            expires_at_ms,
            admin_keys,
            members,
            endpoint_bindings,
            revoked_serials,
            apps,
            app_bindings,
            virtual_dns,
            relays,
            presence_services,
            epoch_secrets,
            policies,
        };
        config.validate_shape()?;
        Ok(config)
    }

    pub fn validate(
        self,
        root: &NetworkRootPublic,
        expected_network: NetworkId,
        now_ms: u64,
    ) -> Result<ValidatedNetworkConfig, SnapshotError> {
        self.validate_shape()?;
        if self.network_id != expected_network || root.network_id() != expected_network {
            return Err(SnapshotError::WrongNetwork);
        }
        if now_ms < self.issued_at_ms {
            return Err(SnapshotError::NotYetValid);
        }
        if now_ms >= self.expires_at_ms {
            return Err(SnapshotError::Expired);
        }
        let revoked: HashSet<_> = self.revoked_serials.iter().copied().collect();
        if revoked.len() != self.revoked_serials.len() {
            return Err(SnapshotError::DuplicateEntry("revoked serial"));
        }
        let mut admins = HashMap::new();
        for key in &self.admin_keys {
            let certificate = AdminCertificate::from_bytes(&key.certificate)?;
            let admin = certificate.verify(root, expected_network, now_ms, &revoked)?;
            if admins.insert(admin.payload().key_id, admin).is_some() {
                return Err(SnapshotError::DuplicateEntry("admin key"));
            }
        }

        let mut members: HashMap<MemberId, VerifiedMember> = HashMap::new();
        for raw in &self.members {
            let certificate = MemberCertificate::from_bytes(raw)?;
            let member = if certificate.payload().issuer_key_id == root.key_id() {
                certificate.verify(root, expected_network, now_ms, &revoked)?
            } else {
                let admin = admins
                    .get(&certificate.payload().issuer_key_id)
                    .ok_or(SnapshotError::UnknownAdmin)?;
                certificate.verify_with_admin(admin, expected_network, now_ms, &revoked)?
            };
            if members.insert(member.payload().member_id, member).is_some() {
                return Err(SnapshotError::DuplicateEntry("member"));
            }
        }
        if members.len() > usize::from(self.policies.max_members) {
            return Err(SnapshotError::PolicyLimitExceeded);
        }

        let mut endpoints = HashSet::new();
        for raw in &self.endpoint_bindings {
            let binding = EndpointBinding::from_bytes(raw)?;
            let payload = binding.payload();
            let member = members
                .get(&payload.member_id)
                .ok_or(SnapshotError::UnknownMember)?;
            binding.verify(member, expected_network, payload.endpoint_id, now_ms)?;
            if !endpoints.insert(payload.endpoint_id) {
                return Err(SnapshotError::DuplicateEntry("endpoint"));
            }
        }

        let mut apps: HashMap<AppAddr, VerifiedApp> = HashMap::new();
        for raw in &self.apps {
            let registration = AppRegistration::from_bytes(raw)?;
            let app = if registration.payload().issuer_key_id == root.key_id() {
                registration.verify(root, expected_network)?
            } else {
                let admin = admins
                    .get(&registration.payload().issuer_key_id)
                    .ok_or(SnapshotError::UnknownAdmin)?;
                registration.verify_with_admin(admin, expected_network)?
            };
            if apps.insert(app.payload().app_addr, app).is_some() {
                return Err(SnapshotError::DuplicateEntry("application"));
            }
        }
        let mut binding_subjects = HashSet::new();
        for raw in &self.app_bindings {
            let binding = AppBinding::from_bytes(raw)?;
            let payload = binding.payload();
            let app = apps
                .get(&payload.app_addr)
                .ok_or(SnapshotError::UnknownApplication)?;
            let member = members
                .get(&payload.subject)
                .ok_or(SnapshotError::UnknownMember)?;
            if payload.services.len() > usize::from(self.policies.max_services_per_binding) {
                return Err(SnapshotError::PolicyLimitExceeded);
            }
            binding.verify(app, member, expected_network, now_ms)?;
            if !binding_subjects.insert((payload.app_addr, payload.subject, payload.role)) {
                return Err(SnapshotError::DuplicateEntry("application binding"));
            }
        }
        let mut virtual_names = HashSet::new();
        for record in &self.virtual_dns {
            if !apps.contains_key(&record.app_addr) {
                return Err(SnapshotError::UnknownApplication);
            }
            if record.expires_at_ms <= self.issued_at_ms
                || record.expires_at_ms > self.expires_at_ms
            {
                return Err(SnapshotError::InvalidValidityWindow);
            }
            if !virtual_names.insert(record.name.clone()) {
                return Err(SnapshotError::DuplicateEntry("virtual DNS name"));
            }
        }
        validate_descriptors(&self.relays, &self.presence_services, now_ms)?;
        Ok(ValidatedNetworkConfig { inner: self })
    }

    fn validate_shape(&self) -> Result<(), SnapshotError> {
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(SnapshotError::InvalidValidityWindow);
        }
        check_len(self.admin_keys.len(), MAX_ADMIN_KEYS)?;
        check_len(self.members.len(), MAX_MEMBERS)?;
        check_len(self.endpoint_bindings.len(), MAX_MEMBERS)?;
        check_len(self.revoked_serials.len(), MAX_REVOKED_SERIALS)?;
        check_len(self.apps.len(), MAX_APPS)?;
        check_len(self.app_bindings.len(), MAX_BINDINGS)?;
        check_len(self.virtual_dns.len(), MAX_VIRTUAL_DNS_RECORDS)?;
        check_len(self.relays.len(), MAX_RELAYS)?;
        check_len(self.presence_services.len(), MAX_PRESENCE_SERVICES)?;
        for raw in self
            .admin_keys
            .iter()
            .map(|key| &key.certificate)
            .chain(self.members.iter())
            .chain(&self.endpoint_bindings)
            .chain(&self.apps)
            .chain(&self.app_bindings)
        {
            if raw.is_empty() || raw.len() > MAX_CREDENTIAL_BYTES {
                return Err(SnapshotError::InvalidLength);
            }
        }
        if self.policies.max_members == 0
            || usize::from(self.policies.max_members) > MAX_MEMBERS
            || self.policies.max_services_per_binding == 0
            || self.policies.max_services_per_binding > 64
        {
            return Err(SnapshotError::PolicyLimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedNetworkConfig {
    inner: NetworkConfigV1,
}

impl ValidatedNetworkConfig {
    pub fn as_config(&self) -> &NetworkConfigV1 {
        &self.inner
    }

    pub fn into_config(self) -> NetworkConfigV1 {
        self.inner
    }

    pub fn resolve_virtual_name(&self, name: &VirtualName, now_ms: u64) -> Option<AppAddr> {
        self.inner
            .virtual_dns
            .iter()
            .find(|record| &record.name == name && record.expires_at_ms > now_ms)
            .map(|record| record.app_addr)
    }

    pub fn verified_admin(
        &self,
        root: &NetworkRootPublic,
        key_id: [u8; 16],
        now_ms: u64,
    ) -> Result<VerifiedAdmin, SnapshotError> {
        let revoked: HashSet<_> = self.inner.revoked_serials.iter().copied().collect();
        for key in &self.inner.admin_keys {
            let certificate = AdminCertificate::from_bytes(&key.certificate)?;
            if certificate.payload().key_id == key_id {
                return certificate
                    .verify(root, self.inner.network_id, now_ms, &revoked)
                    .map_err(Into::into);
            }
        }
        Err(SnapshotError::UnknownAdmin)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotError {
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("configuration snapshot wire bytes are malformed")]
    MalformedWire,
    #[error("configuration snapshot exceeds a bounded collection or field length")]
    InvalidLength,
    #[error("configuration snapshot has an invalid validity window")]
    InvalidValidityWindow,
    #[error("configuration snapshot belongs to another network")]
    WrongNetwork,
    #[error("configuration snapshot is not valid yet")]
    NotYetValid,
    #[error("configuration snapshot has expired")]
    Expired,
    #[error("configuration snapshot contains duplicate {0}")]
    DuplicateEntry(&'static str),
    #[error("configuration references an unknown member")]
    UnknownMember,
    #[error("configuration references an unknown application")]
    UnknownApplication,
    #[error("configuration contains an invalid virtual DNS name")]
    InvalidVirtualName,
    #[error("configuration references an unknown online administrator")]
    UnknownAdmin,
    #[error("configuration violates its declared policy limits")]
    PolicyLimitExceeded,
    #[error("credential verification failed: {0}")]
    Credential(#[from] CertificateError),
}

fn validate_descriptors(
    relays: &[RelayDescriptor],
    presence: &[PresenceServiceDescriptor],
    now_ms: u64,
) -> Result<(), SnapshotError> {
    let mut relay_endpoints = HashSet::new();
    for relay in relays {
        validate_url(&relay.url)?;
        if now_ms >= relay.expires_at_ms {
            return Err(SnapshotError::Expired);
        }
        if !relay_endpoints.insert(relay.endpoint_id) {
            return Err(SnapshotError::DuplicateEntry("relay endpoint"));
        }
    }
    let mut presence_endpoints = HashSet::new();
    for service in presence {
        validate_url(&service.url)?;
        if now_ms >= service.expires_at_ms {
            return Err(SnapshotError::Expired);
        }
        if !presence_endpoints.insert(service.endpoint_id) {
            return Err(SnapshotError::DuplicateEntry("presence endpoint"));
        }
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<(), SnapshotError> {
    if url.is_empty() || url.len() > MAX_URL_BYTES || !url.is_ascii() {
        Err(SnapshotError::InvalidLength)
    } else {
        Ok(())
    }
}

fn check_len(actual: usize, maximum: usize) -> Result<(), SnapshotError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(SnapshotError::InvalidLength)
    }
}

fn push_count(out: &mut Vec<u8>, count: usize) -> Result<(), SnapshotError> {
    let count = u16::try_from(count).map_err(|_| SnapshotError::InvalidLength)?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_blob(out: &mut Vec<u8>, value: &[u8]) -> Result<(), SnapshotError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES {
        return Err(SnapshotError::InvalidLength);
    }
    let len = u16::try_from(value.len()).map_err(|_| SnapshotError::InvalidLength)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn push_blobs(out: &mut Vec<u8>, values: &[Bytes]) -> Result<(), SnapshotError> {
    push_count(out, values.len())?;
    for value in values {
        push_blob(out, value)?;
    }
    Ok(())
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), SnapshotError> {
    validate_url(value)?;
    let len = u16::try_from(value.len()).map_err(|_| SnapshotError::InvalidLength)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SnapshotError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SnapshotError::MalformedWire)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SnapshotError::MalformedWire)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SnapshotError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SnapshotError::MalformedWire)
    }

    fn magic(&mut self, expected: &[u8]) -> Result<(), SnapshotError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(SnapshotError::MalformedWire)
        }
    }

    fn u16(&mut self) -> Result<u16, SnapshotError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, SnapshotError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, SnapshotError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, SnapshotError> {
        let count = usize::from(self.u16()?);
        check_len(count, maximum)?;
        Ok(count)
    }

    fn blobs(&mut self, maximum: usize) -> Result<Vec<Bytes>, SnapshotError> {
        let count = self.count(maximum)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.blob()?);
        }
        Ok(values)
    }

    fn blob(&mut self) -> Result<Bytes, SnapshotError> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > MAX_CREDENTIAL_BYTES {
            return Err(SnapshotError::InvalidLength);
        }
        Ok(Bytes::copy_from_slice(self.take(len)?))
    }

    fn string(&mut self) -> Result<String, SnapshotError> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > MAX_URL_BYTES {
            return Err(SnapshotError::InvalidLength);
        }
        let value =
            std::str::from_utf8(self.take(len)?).map_err(|_| SnapshotError::MalformedWire)?;
        validate_url(value)?;
        Ok(value.to_owned())
    }

    fn finish(self) -> Result<(), SnapshotError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SnapshotError::MalformedWire)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use weaver_core::ServiceId;
    use weaver_crypto::{
        AdminCertificate, AppBinding, AppRole, AppRootKey, MemberRoles, NetworkRootKey,
        OnlineAdminKey, SigningKeypair, derive_device_id,
    };

    struct Fixture {
        root: NetworkRootKey,
        encryption: crate::MemberEncryptionKeypair,
        config: NetworkConfigV1,
    }

    fn fixture() -> Fixture {
        let root = NetworkRootKey::generate().unwrap();
        let network_id = root.public().network_id();
        let member_key = SigningKeypair::generate().unwrap();
        let admin_key = OnlineAdminKey::generate().unwrap();
        let admin_certificate =
            AdminCertificate::issue(&root, admin_key.public_bytes(), u32::MAX, 11, 100, 7_000)
                .unwrap();
        let encryption = crate::MemberEncryptionKeypair::generate().unwrap();
        let member = MemberCertificate::issue(
            &root,
            member_key.public_bytes(),
            encryption.public_bytes(),
            MemberRoles::MEMBER.union(MemberRoles::SERVICE),
            41,
            100,
            10_000,
        )
        .unwrap();
        let endpoint =
            EndpointBinding::issue(&member_key, member.payload(), [0x31; 32], 1, 9_000).unwrap();
        let app_root = AppRootKey::generate().unwrap();
        let app = AppRegistration::issue(&root, &app_root, 0);
        let device = derive_device_id(network_id, app_root.app_addr(), &member_key.public_bytes());
        let app_binding = AppBinding::issue(
            &app_root,
            network_id,
            member.payload().member_id,
            AppRole::Client,
            Some(device),
            9_000,
            vec![ServiceId::from_bytes([0x51; 16])],
        )
        .unwrap();
        Fixture {
            root,
            encryption,
            config: NetworkConfigV1 {
                network_id,
                epoch: 3,
                revision: 9,
                previous_hash: [0x11; 32],
                issued_at_ms: 100,
                expires_at_ms: 8_000,
                admin_keys: vec![AdminKey {
                    certificate: admin_certificate.to_bytes(),
                }],
                members: vec![member.to_bytes()],
                endpoint_bindings: vec![endpoint.to_bytes()],
                revoked_serials: Vec::new(),
                apps: vec![app.to_bytes()],
                app_bindings: vec![app_binding.to_bytes()],
                virtual_dns: vec![VirtualDnsRecord {
                    name: VirtualName::new("weaver.virtual").unwrap(),
                    app_addr: app_root.app_addr(),
                    expires_at_ms: 7_000,
                }],
                relays: vec![RelayDescriptor {
                    endpoint_id: [0x61; 32],
                    url: "https://relay.example.test".to_owned(),
                    roles: RelayRoles::DATA_RELAY.union(RelayRoles::BOOTSTRAP),
                    expires_at_ms: 7_000,
                }],
                presence_services: vec![PresenceServiceDescriptor {
                    endpoint_id: [0x61; 32],
                    url: "https://relay.example.test/presence".to_owned(),
                    expires_at_ms: 7_000,
                }],
                epoch_secrets: EpochSecrets::from_bytes([[0x71; 32]; 4]),
                policies: NetworkPolicy::default(),
            },
        }
    }

    #[test]
    fn snapshot_round_trips_and_validates_complete_chain() {
        let fixture = fixture();
        let encoded = fixture.config.to_bytes().unwrap();
        let decoded = NetworkConfigV1::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, fixture.config);
        let validated = decoded
            .validate(
                &fixture.root.public(),
                fixture.root.public().network_id(),
                500,
            )
            .unwrap();
        assert_eq!(validated.as_config().revision, 9);
        assert_eq!(validated.as_config().relays.len(), 1);
        let name = VirtualName::new("weaver.virtual").unwrap();
        assert_eq!(
            validated.resolve_virtual_name(&name, 500),
            Some(fixture.config.virtual_dns[0].app_addr)
        );
        assert_eq!(validated.resolve_virtual_name(&name, 7_000), None);
    }

    #[test]
    fn legacy_v1_snapshot_opens_with_an_empty_virtual_dns_zone() {
        let mut fixture = fixture();
        fixture.config.virtual_dns.clear();
        let mut encoded = fixture.config.to_bytes().unwrap().to_vec();
        let relay_endpoint = [0x61_u8; 32];
        let endpoint_offset = encoded
            .windows(relay_endpoint.len())
            .position(|window| window == relay_endpoint)
            .unwrap();
        assert_eq!(
            &encoded[endpoint_offset - 4..endpoint_offset],
            &[0, 0, 0, 1]
        );
        encoded.drain(endpoint_offset - 4..endpoint_offset - 2);
        encoded[..SNAPSHOT_MAGIC_V1.len()].copy_from_slice(SNAPSHOT_MAGIC_V1);

        let decoded = NetworkConfigV1::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, fixture.config);
        assert!(decoded.virtual_dns.is_empty());
    }

    #[test]
    fn typed_envelope_round_trips_snapshot_and_checks_metadata() {
        let fixture = fixture();
        let envelope = crate::EncryptedConfigEnvelope::seal_config(
            &fixture.root,
            &fixture.config,
            &[fixture.encryption.public_bytes()],
        )
        .unwrap();
        let network = fixture.root.public().network_id();
        let opened = envelope
            .open_config(
                &fixture.root.public(),
                network,
                &fixture.encryption,
                crate::ChainExpectation::Next(crate::ConfigHead {
                    epoch: 2,
                    revision: 8,
                    hash: fixture.config.previous_hash,
                }),
                500,
            )
            .unwrap();
        assert_eq!(opened.config.as_config(), &fixture.config);
        assert_eq!(opened.head.revision, fixture.config.revision);

        let raw = fixture.config.to_bytes().unwrap();
        let mismatched = crate::EncryptedConfigEnvelope::seal(
            &fixture.root,
            fixture.config.epoch,
            fixture.config.revision + 1,
            fixture.config.previous_hash,
            &raw,
            &[fixture.encryption.public_bytes()],
        )
        .unwrap();
        let result = mismatched.open_config(
            &fixture.root.public(),
            network,
            &fixture.encryption,
            crate::ChainExpectation::Next(crate::ConfigHead {
                epoch: 2,
                revision: 9,
                hash: fixture.config.previous_hash,
            }),
            500,
        );
        assert_eq!(result, Err(crate::ConfigError::EnvelopePayloadMismatch));
    }

    #[test]
    fn snapshot_rejects_revoked_member_and_cross_network_validation() {
        let mut fixture = fixture();
        fixture.config.revoked_serials.push(41);
        assert_eq!(
            fixture.config.clone().validate(
                &fixture.root.public(),
                fixture.root.public().network_id(),
                500
            ),
            Err(SnapshotError::Credential(CertificateError::Revoked))
        );

        let other = NetworkRootKey::generate().unwrap();
        assert_eq!(
            fixture
                .config
                .validate(&other.public(), other.public().network_id(), 500),
            Err(SnapshotError::WrongNetwork)
        );
    }

    #[test]
    fn snapshot_rejects_trailing_bytes_duplicates_and_policy_overflow() {
        let fixture = fixture();
        let mut encoded = fixture.config.to_bytes().unwrap().to_vec();
        encoded.push(0);
        assert_eq!(
            NetworkConfigV1::from_bytes(&encoded),
            Err(SnapshotError::MalformedWire)
        );

        let mut duplicate = fixture.config.clone();
        duplicate.members.push(duplicate.members[0].clone());
        assert_eq!(
            duplicate.validate(
                &fixture.root.public(),
                fixture.root.public().network_id(),
                500
            ),
            Err(SnapshotError::DuplicateEntry("member"))
        );

        let mut policy = fixture.config;
        policy.policies.max_members = 0;
        assert_eq!(policy.to_bytes(), Err(SnapshotError::PolicyLimitExceeded));
    }

    #[test]
    fn snapshot_rejects_duplicate_names_and_unknown_dns_targets() {
        let mut duplicate = fixture();
        duplicate
            .config
            .virtual_dns
            .push(duplicate.config.virtual_dns[0].clone());
        assert_eq!(
            duplicate.config.validate(
                &duplicate.root.public(),
                duplicate.root.public().network_id(),
                500
            ),
            Err(SnapshotError::DuplicateEntry("virtual DNS name"))
        );

        let mut unknown = fixture();
        unknown.config.virtual_dns[0].app_addr = AppAddr::from_bytes([0xee; 32]);
        assert_eq!(
            unknown.config.validate(
                &unknown.root.public(),
                unknown.root.public().network_id(),
                500
            ),
            Err(SnapshotError::UnknownApplication)
        );
    }

    #[test]
    fn epoch_secrets_are_redacted_in_debug_output() {
        let secrets = EpochSecrets::from_bytes([[0xab; 32]; 4]);
        let debug = format!("{secrets:?}");
        assert_eq!(debug, "EpochSecrets([redacted])");
        assert!(!debug.contains("ab"));
    }
}
