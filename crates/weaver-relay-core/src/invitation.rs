use std::{collections::HashSet, net::SocketAddr, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use iroh::EndpointId;
use weaver_config::{EncryptedConfigEnvelope, EpochSecrets};
use weaver_core::{AppAddr, NetworkId, VirtualName};
use weaver_crypto::{
    AdminCertificate, AppBinding, AppRegistration, AppRole, AppRootKey, MemberCertificate,
    MemberRoles, NetworkRootPublic, PreparedJoinRequest, derive_device_id,
};
use weaver_store::{
    AtomicBatch, ExpectedVersion, SecretBytes, SecretStore, StateStore, StoreKey, StoreScope,
};

use crate::{
    Authority, AuthorityError, JoinTicket, KEY_ENVELOPE, KEY_HEAD, active_recipient_keys,
    encode_head, ensure_join_is_unique, history_key, next_serial,
};

const MAGIC: &[u8; 8] = b"WVRINV\0\x01";
const SIGNATURE_LEN: usize = 64;
const MAX_DIRECT_ADDRESSES: usize = 8;
const INVITATION_KEY_PREFIX: &[u8] = b"authority/invitation/v1/";
const CONSUMED_MAGIC: &[u8; 8] = b"WVRUSE\0\x01";
const TEXT_PREFIX: &str = "weaver-invite-v1:";
pub const BOOTSTRAP_ALPN_PREFIX: &[u8] = b"weaver/bootstrap/1/";
const BOOTSTRAP_REQUEST_MAGIC: &[u8; 8] = b"WVRBSR\0\x01";
const BOOTSTRAP_RESPONSE_MAGIC: &[u8; 8] = b"WVRBSP\0\x01";
const MAX_BOOTSTRAP_PAYLOAD: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapRedeemRequest {
    pub invitation: InvitationBundle,
    pub prepared: PreparedJoinRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BootstrapRejectCode {
    Invalid = 1,
    AlreadyUsed = 2,
    Revoked = 3,
    Internal = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapRedeemResponse {
    Accepted(JoinTicket),
    Rejected(BootstrapRejectCode),
}

pub fn bootstrap_alpn(network_id: NetworkId) -> Vec<u8> {
    let mut out = Vec::with_capacity(BOOTSTRAP_ALPN_PREFIX.len() + 32);
    out.extend_from_slice(BOOTSTRAP_ALPN_PREFIX);
    out.extend_from_slice(network_id.as_bytes());
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationBundle {
    pub invitation_id: [u8; 32],
    pub network_id: NetworkId,
    pub root_public_key: [u8; 32],
    pub bootstrap_endpoint_id: [u8; 32],
    pub bootstrap_direct_addresses: Vec<SocketAddr>,
    pub bootstrap_relay: Option<String>,
    pub client_app_addr: AppAddr,
    pub service_name: VirtualName,
    pub expires_at_ms: u64,
    pub admin_certificate: Bytes,
    pub signer_key_id: [u8; 16],
    signed_bytes: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

impl Authority {
    /// Installs the application signing capability used only for online client enrollment.
    /// The key is encrypted by the authority SecretStore and is checked against the signed
    /// application registration before it is accepted.
    pub async fn install_enrollment_app_root(
        &self,
        app_root: &AppRootKey,
    ) -> Result<(), AuthorityError> {
        let registration = self
            .config
            .as_config()
            .apps
            .iter()
            .filter_map(|raw| AppRegistration::from_bytes(raw).ok())
            .find(|registration| registration.payload().app_addr == app_root.app_addr())
            .ok_or(AuthorityError::ApplicationNotFound)?;
        if registration.payload().app_root_public_key != app_root.public_bytes() {
            return Err(AuthorityError::InvalidInvitation);
        }
        self.secrets
            .seal(
                enrollment_secret_id(self.status.network_id, app_root.app_addr()),
                SecretBytes::new(app_root.to_bytes().to_vec()),
            )
            .await?;
        Ok(())
    }

    pub async fn redeem_invitation_online(
        &mut self,
        invitation: &InvitationBundle,
        prepared: &PreparedJoinRequest,
        now_ms: u64,
    ) -> Result<JoinTicket, AuthorityError> {
        let secret = self
            .secrets
            .open(&enrollment_secret_id(
                self.status.network_id,
                invitation.client_app_addr,
            ))
            .await?;
        let bytes: [u8; 32] = secret
            .expose()
            .try_into()
            .map_err(|_| AuthorityError::CorruptState)?;
        let app_root = AppRootKey::from_bytes(&bytes);
        self.redeem_invitation(invitation, prepared, &app_root, now_ms)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_invitation(
        &self,
        bootstrap_endpoint: EndpointId,
        bootstrap_direct_addresses: Vec<SocketAddr>,
        bootstrap_relay: Option<String>,
        client_app_addr: AppAddr,
        service_name: VirtualName,
        now_ms: u64,
        valid_for_ms: u64,
    ) -> Result<InvitationBundle, AuthorityError> {
        let expires_at_ms = now_ms
            .checked_add(valid_for_ms)
            .ok_or(AuthorityError::InvalidInvitation)?
            .min(self.verified_admin.payload().expires_at_ms)
            .min(self.config.as_config().expires_at_ms);
        if valid_for_ms == 0
            || expires_at_ms <= now_ms
            || bootstrap_direct_addresses.len() > MAX_DIRECT_ADDRESSES
            || bootstrap_relay
                .as_ref()
                .is_some_and(|value| value.len() > 2048)
        {
            return Err(AuthorityError::InvalidInvitation);
        }
        let app_registered = self.config.as_config().apps.iter().any(|raw| {
            weaver_crypto::AppRegistration::from_bytes(raw)
                .is_ok_and(|app| app.payload().app_addr == client_app_addr)
        });
        if !app_registered {
            return Err(AuthorityError::ApplicationNotFound);
        }
        let mut invitation_id = [0_u8; 32];
        getrandom::fill(&mut invitation_id).map_err(|_| AuthorityError::InvalidInvitation)?;
        let invitation = InvitationBundle::issue(
            self,
            invitation_id,
            bootstrap_endpoint,
            bootstrap_direct_addresses,
            bootstrap_relay,
            client_app_addr,
            service_name,
            expires_at_ms,
        )?;
        let mut batch = AtomicBatch::new(StoreScope::authority(self.status.network_id));
        batch.put(
            invitation_key(invitation.invitation_id)?,
            invitation.to_bytes(),
            ExpectedVersion::Missing,
        )?;
        self.state.commit(batch).await?;
        Ok(invitation)
    }

    pub async fn redeem_invitation(
        &mut self,
        invitation: &InvitationBundle,
        prepared: &PreparedJoinRequest,
        client_app_root: &AppRootKey,
        now_ms: u64,
    ) -> Result<JoinTicket, AuthorityError> {
        invitation.verify(&self.root_public, now_ms)?;
        if invitation.client_app_addr != client_app_root.app_addr() {
            return Err(AuthorityError::InvalidInvitation);
        }
        prepared.verify(self.status.network_id, now_ms)?;
        let request_hash = *blake3::hash(&prepared.to_bytes()).as_bytes();
        let scope = StoreScope::authority(self.status.network_id);
        let key = invitation_key(invitation.invitation_id)?;
        let record = self
            .state
            .read(scope, &key)
            .await?
            .ok_or(AuthorityError::InvitationRevoked)?;
        if record.bytes.starts_with(CONSUMED_MAGIC) {
            return decode_consumed(&record.bytes, request_hash);
        }
        if record.bytes != invitation.to_bytes() {
            return Err(AuthorityError::InvalidInvitation);
        }

        let request = &prepared.request;
        let endpoint_binding = &prepared.endpoint_binding;
        let request = request.verify(self.status.network_id, now_ms)?;
        ensure_join_is_unique(self.config.as_config(), request.payload())?;
        let expires_at_ms = invitation
            .expires_at_ms
            .min(request.payload().expires_at_ms)
            .min(self.verified_admin.payload().expires_at_ms)
            .min(self.config.as_config().expires_at_ms);
        if expires_at_ms <= now_ms {
            return Err(AuthorityError::InvalidInvitation);
        }
        let serial = next_serial(self.config.as_config())?;
        let member = MemberCertificate::issue_by_admin(
            &self.online_admin,
            self.verified_admin.payload(),
            request.payload().signing_public_key,
            request.payload().encryption_public_key,
            MemberRoles::MEMBER,
            serial,
            now_ms,
            expires_at_ms,
        )?;
        let verified_member = member.verify_with_admin(
            &self.verified_admin,
            self.status.network_id,
            now_ms,
            &HashSet::new(),
        )?;
        endpoint_binding.verify(
            &verified_member,
            self.status.network_id,
            request.payload().endpoint_id,
            now_ms,
        )?;
        let device_id = derive_device_id(
            self.status.network_id,
            invitation.client_app_addr,
            &request.payload().signing_public_key,
        );
        let app_binding = AppBinding::issue(
            client_app_root,
            self.status.network_id,
            request.payload().member_id,
            AppRole::Client,
            Some(device_id),
            expires_at_ms,
            Vec::new(),
        )?;

        let mut next = self.config.as_config().clone();
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AuthorityError::InvalidOptions)?;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::InvalidOptions)?;
        next.previous_hash = self.status.head.hash;
        next.issued_at_ms = now_ms;
        next.epoch_secrets = EpochSecrets::generate()?;
        next.members.push(member.to_bytes());
        next.endpoint_bindings.push(endpoint_binding.to_bytes());
        next.app_bindings.push(app_binding.to_bytes());

        let recipients = active_recipient_keys(&next)?;
        let envelope = EncryptedConfigEnvelope::seal_next_config(
            &self.root_public,
            &self.online_admin,
            &self.config,
            self.status.head,
            &next,
            &recipients,
            now_ms,
        )?;
        let opened = envelope.open_next_config(
            &self.root_public,
            &self.config,
            &self.member_encryption,
            self.status.head,
            now_ms,
        )?;
        let ticket = JoinTicket::issue(
            &self.online_admin,
            self.status.network_id,
            request.payload().nonce,
            expires_at_ms,
            opened.head,
            self.admin_certificate.clone(),
            member.to_bytes(),
            endpoint_binding.to_bytes(),
            envelope.to_bytes(),
        )?;

        let envelope_key = StoreKey::new(KEY_ENVELOPE)?;
        let head_key = StoreKey::new(KEY_HEAD)?;
        let mut batch = AtomicBatch::new(scope);
        batch.put(
            envelope_key.clone(),
            envelope.to_bytes(),
            ExpectedVersion::Exact(self.envelope_record_version),
        )?;
        batch.put(
            head_key.clone(),
            encode_head(opened.head),
            ExpectedVersion::Exact(self.head_record_version),
        )?;
        batch.put(
            history_key(opened.head.revision)?,
            envelope.to_bytes(),
            ExpectedVersion::Missing,
        )?;
        batch.put(
            key,
            encode_consumed(request_hash, &ticket)?,
            ExpectedVersion::Exact(record.version),
        )?;
        self.state.commit(batch).await?;

        let envelope_record = self
            .state
            .read(scope, &envelope_key)
            .await?
            .ok_or(AuthorityError::CorruptState)?;
        let head_record = self
            .state
            .read(scope, &head_key)
            .await?
            .ok_or(AuthorityError::CorruptState)?;
        self.envelope_record_version = envelope_record.version;
        self.head_record_version = head_record.version;
        self.config = opened.config;
        self.status.head = opened.head;
        Ok(ticket)
    }

    pub async fn revoke_invitation(&self, invitation_id: [u8; 32]) -> Result<(), AuthorityError> {
        let scope = StoreScope::authority(self.status.network_id);
        let key = invitation_key(invitation_id)?;
        let record = self
            .state
            .read(scope, &key)
            .await?
            .ok_or(AuthorityError::InvitationRevoked)?;
        if record.bytes.starts_with(CONSUMED_MAGIC) {
            return Err(AuthorityError::InvitationAlreadyUsed);
        }
        let mut batch = AtomicBatch::new(scope);
        batch.delete(key, ExpectedVersion::Exact(record.version))?;
        self.state.commit(batch).await?;
        Ok(())
    }
}

fn enrollment_secret_id(network_id: NetworkId, app_addr: AppAddr) -> weaver_store::SecretId {
    let mut hasher = blake3::Hasher::new_derive_key("weaver.authority.enrollment-app-root.v1");
    hasher.update(network_id.as_bytes());
    hasher.update(app_addr.as_bytes());
    weaver_store::SecretId::from_bytes(*hasher.finalize().as_bytes())
}

impl InvitationBundle {
    #[allow(clippy::too_many_arguments)]
    fn issue(
        authority: &Authority,
        invitation_id: [u8; 32],
        bootstrap_endpoint: EndpointId,
        bootstrap_direct_addresses: Vec<SocketAddr>,
        bootstrap_relay: Option<String>,
        client_app_addr: AppAddr,
        service_name: VirtualName,
        expires_at_ms: u64,
    ) -> Result<Self, AuthorityError> {
        let mut invitation = Self {
            invitation_id,
            network_id: authority.status.network_id,
            root_public_key: authority.root_public.as_bytes(),
            bootstrap_endpoint_id: *bootstrap_endpoint.as_bytes(),
            bootstrap_direct_addresses,
            bootstrap_relay,
            client_app_addr,
            service_name,
            expires_at_ms,
            admin_certificate: authority.admin_certificate.clone(),
            signer_key_id: authority.online_admin.key_id(),
            signed_bytes: Bytes::new(),
            signature: [0; SIGNATURE_LEN],
        };
        invitation.signed_bytes = Bytes::from(invitation.encode_signed()?);
        invitation.signature = authority.online_admin.sign_bytes(&invitation.signed_bytes);
        Ok(invitation)
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut out = Vec::with_capacity(self.signed_bytes.len() + SIGNATURE_LEN);
        out.extend_from_slice(&self.signed_bytes);
        out.extend_from_slice(&self.signature);
        Bytes::from(out)
    }

    pub fn to_text(&self) -> String {
        format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(value: &str) -> Result<Self, AuthorityError> {
        let encoded = value
            .trim()
            .strip_prefix(TEXT_PREFIX)
            .ok_or(AuthorityError::InvalidInvitation)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| AuthorityError::InvalidInvitation)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        if bytes.len() < MAGIC.len() + SIGNATURE_LEN {
            return Err(AuthorityError::InvalidInvitation);
        }
        let signed_len = bytes.len() - SIGNATURE_LEN;
        let signed_bytes = Bytes::copy_from_slice(&bytes[..signed_len]);
        let signature = bytes[signed_len..]
            .try_into()
            .map_err(|_| AuthorityError::InvalidInvitation)?;
        let mut decoder = Decoder::new(&signed_bytes);
        decoder.magic(MAGIC)?;
        let invitation_id = decoder.array()?;
        let network_id = NetworkId::from_bytes(decoder.array()?);
        let root_public_key = decoder.array()?;
        let bootstrap_endpoint_id = decoder.array()?;
        let address_count = usize::from(decoder.u8()?);
        if address_count > MAX_DIRECT_ADDRESSES {
            return Err(AuthorityError::InvalidInvitation);
        }
        let mut bootstrap_direct_addresses = Vec::with_capacity(address_count);
        for _ in 0..address_count {
            bootstrap_direct_addresses.push(
                SocketAddr::from_str(&decoder.string(128)?)
                    .map_err(|_| AuthorityError::InvalidInvitation)?,
            );
        }
        let bootstrap_relay = match decoder.u8()? {
            0 => None,
            1 => Some(decoder.string(2048)?),
            _ => return Err(AuthorityError::InvalidInvitation),
        };
        let client_app_addr = AppAddr::from_bytes(decoder.array()?);
        let service_name = VirtualName::from_str(&decoder.string(255)?)
            .map_err(|_| AuthorityError::InvalidInvitation)?;
        let expires_at_ms = decoder.u64()?;
        let admin_certificate = decoder.blob(16 * 1024)?;
        let signer_key_id = decoder.array()?;
        decoder.finish()?;
        Ok(Self {
            invitation_id,
            network_id,
            root_public_key,
            bootstrap_endpoint_id,
            bootstrap_direct_addresses,
            bootstrap_relay,
            client_app_addr,
            service_name,
            expires_at_ms,
            admin_certificate,
            signer_key_id,
            signed_bytes,
            signature,
        })
    }

    pub fn verify(
        &self,
        expected_root: &NetworkRootPublic,
        now_ms: u64,
    ) -> Result<(), AuthorityError> {
        if self.root_public_key != expected_root.as_bytes()
            || self.network_id != expected_root.network_id()
            || now_ms >= self.expires_at_ms
            || EndpointId::from_bytes(&self.bootstrap_endpoint_id).is_err()
        {
            return Err(AuthorityError::InvalidInvitation);
        }
        let certificate = AdminCertificate::from_bytes(&self.admin_certificate)?;
        let admin = certificate.verify(expected_root, self.network_id, now_ms, &HashSet::new())?;
        if admin.payload().key_id != self.signer_key_id {
            return Err(AuthorityError::InvalidInvitation);
        }
        admin.verify_bytes(&self.signed_bytes, &self.signature)?;
        Ok(())
    }

    fn encode_signed(&self) -> Result<Vec<u8>, AuthorityError> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.invitation_id);
        out.extend_from_slice(self.network_id.as_bytes());
        out.extend_from_slice(&self.root_public_key);
        out.extend_from_slice(&self.bootstrap_endpoint_id);
        out.push(
            u8::try_from(self.bootstrap_direct_addresses.len())
                .map_err(|_| AuthorityError::InvalidInvitation)?,
        );
        for address in &self.bootstrap_direct_addresses {
            push_string(&mut out, &address.to_string())?;
        }
        match &self.bootstrap_relay {
            Some(relay) => {
                out.push(1);
                push_string(&mut out, relay)?;
            }
            None => out.push(0),
        }
        out.extend_from_slice(self.client_app_addr.as_bytes());
        push_string(&mut out, self.service_name.as_str())?;
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        push_blob(&mut out, &self.admin_certificate)?;
        out.extend_from_slice(&self.signer_key_id);
        Ok(out)
    }
}

impl BootstrapRedeemRequest {
    pub fn to_bytes(&self) -> Result<Bytes, AuthorityError> {
        let invitation = self.invitation.to_bytes();
        let prepared = self.prepared.to_bytes();
        if invitation.len() > MAX_BOOTSTRAP_PAYLOAD || prepared.len() > MAX_BOOTSTRAP_PAYLOAD {
            return Err(AuthorityError::InvalidInvitation);
        }
        let mut out = Vec::with_capacity(
            BOOTSTRAP_REQUEST_MAGIC.len() + 8 + invitation.len() + prepared.len(),
        );
        out.extend_from_slice(BOOTSTRAP_REQUEST_MAGIC);
        push_u32_blob(&mut out, &invitation)?;
        push_u32_blob(&mut out, &prepared)?;
        Ok(Bytes::from(out))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let mut decoder = WideDecoder::new(bytes);
        decoder.magic(BOOTSTRAP_REQUEST_MAGIC)?;
        let invitation = InvitationBundle::from_bytes(decoder.blob(MAX_BOOTSTRAP_PAYLOAD)?)?;
        let prepared = PreparedJoinRequest::from_bytes(decoder.blob(MAX_BOOTSTRAP_PAYLOAD)?)?;
        decoder.finish()?;
        Ok(Self {
            invitation,
            prepared,
        })
    }
}

impl BootstrapRedeemResponse {
    pub fn to_bytes(&self) -> Result<Bytes, AuthorityError> {
        let mut out = Vec::new();
        out.extend_from_slice(BOOTSTRAP_RESPONSE_MAGIC);
        match self {
            Self::Accepted(ticket) => {
                out.push(0);
                push_u32_blob(&mut out, &ticket.to_bytes())?;
            }
            Self::Rejected(code) => {
                out.push(*code as u8);
                out.extend_from_slice(&0_u32.to_be_bytes());
            }
        }
        Ok(Bytes::from(out))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let mut decoder = WideDecoder::new(bytes);
        decoder.magic(BOOTSTRAP_RESPONSE_MAGIC)?;
        let status = decoder.u8()?;
        let payload = decoder.blob_allow_empty(MAX_BOOTSTRAP_PAYLOAD)?;
        decoder.finish()?;
        match status {
            0 => Ok(Self::Accepted(JoinTicket::from_bytes(payload)?)),
            1 if payload.is_empty() => Ok(Self::Rejected(BootstrapRejectCode::Invalid)),
            2 if payload.is_empty() => Ok(Self::Rejected(BootstrapRejectCode::AlreadyUsed)),
            3 if payload.is_empty() => Ok(Self::Rejected(BootstrapRejectCode::Revoked)),
            4 if payload.is_empty() => Ok(Self::Rejected(BootstrapRejectCode::Internal)),
            _ => Err(AuthorityError::InvalidInvitation),
        }
    }
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), AuthorityError> {
    push_blob(out, value.as_bytes())
}

fn push_blob(out: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthorityError> {
    let len = u16::try_from(value.len()).map_err(|_| AuthorityError::InvalidInvitation)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn push_u32_blob(out: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthorityError> {
    let len = u32::try_from(value.len()).map_err(|_| AuthorityError::InvalidInvitation)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn invitation_key(invitation_id: [u8; 32]) -> Result<StoreKey, AuthorityError> {
    let mut key = Vec::with_capacity(INVITATION_KEY_PREFIX.len() + invitation_id.len());
    key.extend_from_slice(INVITATION_KEY_PREFIX);
    key.extend_from_slice(&invitation_id);
    Ok(StoreKey::new(key)?)
}

fn encode_consumed(request_hash: [u8; 32], ticket: &JoinTicket) -> Result<Bytes, AuthorityError> {
    let ticket = ticket.to_bytes();
    let mut out = Vec::with_capacity(CONSUMED_MAGIC.len() + 32 + 4 + ticket.len());
    out.extend_from_slice(CONSUMED_MAGIC);
    out.extend_from_slice(&request_hash);
    let len = u32::try_from(ticket.len()).map_err(|_| AuthorityError::InvalidJoinTicket)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&ticket);
    Ok(Bytes::from(out))
}

fn decode_consumed(
    bytes: &[u8],
    expected_request_hash: [u8; 32],
) -> Result<JoinTicket, AuthorityError> {
    if bytes.len() < CONSUMED_MAGIC.len() + 32 + 4
        || &bytes[..CONSUMED_MAGIC.len()] != CONSUMED_MAGIC
    {
        return Err(AuthorityError::InvalidInvitation);
    }
    let hash_offset = CONSUMED_MAGIC.len();
    let len_offset = hash_offset + 32;
    if bytes[hash_offset..len_offset] != expected_request_hash {
        return Err(AuthorityError::InvitationAlreadyUsed);
    }
    let ticket_len = u32::from_be_bytes(
        bytes[len_offset..len_offset + 4]
            .try_into()
            .map_err(|_| AuthorityError::InvalidInvitation)?,
    ) as usize;
    let ticket = bytes
        .get(len_offset + 4..)
        .filter(|value| value.len() == ticket_len)
        .ok_or(AuthorityError::InvalidInvitation)?;
    JoinTicket::from_bytes(ticket)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

struct WideDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WideDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], AuthorityError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(AuthorityError::InvalidInvitation)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AuthorityError::InvalidInvitation)?;
        self.offset = end;
        Ok(value)
    }
    fn magic(&mut self, expected: &[u8]) -> Result<(), AuthorityError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(AuthorityError::InvalidInvitation)
        }
    }
    fn u8(&mut self) -> Result<u8, AuthorityError> {
        Ok(self.take(1)?[0])
    }
    fn blob(&mut self, max: usize) -> Result<&'a [u8], AuthorityError> {
        let value = self.blob_allow_empty(max)?;
        if value.is_empty() {
            Err(AuthorityError::InvalidInvitation)
        } else {
            Ok(value)
        }
    }
    fn blob_allow_empty(&mut self, max: usize) -> Result<&'a [u8], AuthorityError> {
        let len = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| AuthorityError::InvalidInvitation)?,
        ) as usize;
        if len > max {
            return Err(AuthorityError::InvalidInvitation);
        }
        self.take(len)
    }
    fn finish(self) -> Result<(), AuthorityError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AuthorityError::InvalidInvitation)
        }
    }
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], AuthorityError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(AuthorityError::InvalidInvitation)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AuthorityError::InvalidInvitation)?;
        self.offset = end;
        Ok(value)
    }
    fn magic(&mut self, expected: &[u8]) -> Result<(), AuthorityError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(AuthorityError::InvalidInvitation)
        }
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], AuthorityError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AuthorityError::InvalidInvitation)
    }
    fn u8(&mut self) -> Result<u8, AuthorityError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, AuthorityError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, AuthorityError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn blob(&mut self, max: usize) -> Result<Bytes, AuthorityError> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > max {
            return Err(AuthorityError::InvalidInvitation);
        }
        Ok(Bytes::copy_from_slice(self.take(len)?))
    }
    fn string(&mut self, max: usize) -> Result<String, AuthorityError> {
        String::from_utf8(self.blob(max)?.to_vec()).map_err(|_| AuthorityError::InvalidInvitation)
    }
    fn finish(self) -> Result<(), AuthorityError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AuthorityError::InvalidInvitation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use tempfile::tempdir;
    use weaver_config::MemberEncryptionKeypair;
    use weaver_crypto::{AppRegistrationRequest, SigningKeypair};

    async fn authority_with_app(now_ms: u64) -> (Authority, AppRootKey, NetworkRootPublic) {
        let temp = tempdir().unwrap();
        let data_dir = temp.keep().join("authority");
        let initialized = Authority::initialize(crate::AuthorityInit {
            data_dir: data_dir.clone(),
            relay_url: "http://127.0.0.1:3340".to_string(),
            now_ms,
            valid_for_ms: 86_400_000,
            master_key: [7; 32],
            recovery_root_out: None,
        })
        .await
        .unwrap();
        let root = NetworkRootPublic::from_bytes(&initialized.status.root_public_key).unwrap();
        let mut authority = Authority::open(data_dir, [7; 32], now_ms).await.unwrap();
        let app_root = AppRootKey::generate().unwrap();
        authority
            .register_app(
                &AppRegistrationRequest::create(&app_root, root.network_id(), 0),
                now_ms + 1,
            )
            .await
            .unwrap();
        (authority, app_root, root)
    }

    fn prepared(network_id: NetworkId, expires_at_ms: u64) -> PreparedJoinRequest {
        let signing = SigningKeypair::generate().unwrap();
        let encryption = MemberEncryptionKeypair::generate().unwrap();
        let endpoint = SecretKey::generate();
        PreparedJoinRequest::create(
            network_id,
            &signing,
            encryption.public_bytes(),
            *endpoint.public().as_bytes(),
            [9; 32],
            MemberRoles::MEMBER,
            expires_at_ms,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn invitation_round_trip_and_same_request_retry_are_idempotent() {
        let now = 10_000;
        let (mut authority, app_root, root) = authority_with_app(now).await;
        let invitation = authority
            .create_invitation(
                SecretKey::generate().public(),
                vec!["127.0.0.1:4040".parse().unwrap()],
                Some("https://bootstrap.example".to_string()),
                app_root.app_addr(),
                VirtualName::from_str("remi.virtual").unwrap(),
                now + 2,
                60_000,
            )
            .await
            .unwrap();
        let decoded = InvitationBundle::from_bytes(&invitation.to_bytes()).unwrap();
        assert_eq!(
            InvitationBundle::from_text(&invitation.to_text()).unwrap(),
            decoded
        );
        decoded.verify(&root, now + 3).unwrap();
        let prepared = prepared(root.network_id(), now + 50_000);
        let first = authority
            .redeem_invitation(&decoded, &prepared, &app_root, now + 4)
            .await
            .unwrap();
        let revision = authority.status().head.revision;
        let retried = authority
            .redeem_invitation(&decoded, &prepared, &app_root, now + 5)
            .await
            .unwrap();
        assert_eq!(first.to_bytes(), retried.to_bytes());
        assert_eq!(authority.status().head.revision, revision);
    }

    #[tokio::test]
    async fn invitation_rejects_tamper_cross_device_replay_and_revocation() {
        let now = 20_000;
        let (mut authority, app_root, root) = authority_with_app(now).await;
        let invitation = authority
            .create_invitation(
                SecretKey::generate().public(),
                Vec::new(),
                None,
                app_root.app_addr(),
                VirtualName::from_str("remi.virtual").unwrap(),
                now + 2,
                60_000,
            )
            .await
            .unwrap();
        let mut tampered = invitation.to_bytes().to_vec();
        tampered[40] ^= 1;
        let tampered = InvitationBundle::from_bytes(&tampered).unwrap();
        assert!(tampered.verify(&root, now + 3).is_err());
        assert!(invitation.verify(&root, now + 60_003).is_err());

        let cross_network = prepared(NetworkId::from_bytes([0x44; 32]), now + 50_000);
        assert!(
            authority
                .redeem_invitation(&invitation, &cross_network, &app_root, now + 3)
                .await
                .is_err()
        );

        let first = prepared(root.network_id(), now + 50_000);
        authority
            .redeem_invitation(&invitation, &first, &app_root, now + 4)
            .await
            .unwrap();
        let second = prepared(root.network_id(), now + 50_000);
        assert!(matches!(
            authority
                .redeem_invitation(&invitation, &second, &app_root, now + 5)
                .await,
            Err(AuthorityError::InvitationAlreadyUsed)
        ));

        let revoked = authority
            .create_invitation(
                SecretKey::generate().public(),
                Vec::new(),
                None,
                app_root.app_addr(),
                VirtualName::from_str("remi.virtual").unwrap(),
                now + 6,
                60_000,
            )
            .await
            .unwrap();
        authority
            .revoke_invitation(revoked.invitation_id)
            .await
            .unwrap();
        assert!(matches!(
            authority
                .redeem_invitation(
                    &revoked,
                    &prepared(root.network_id(), now + 50_000),
                    &app_root,
                    now + 7
                )
                .await,
            Err(AuthorityError::InvitationRevoked)
        ));
    }
}
