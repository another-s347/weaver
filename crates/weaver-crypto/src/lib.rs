//! Weaver's network-scoped certificate and application authorization chain.
//!
//! Verification always covers the exact received payload bytes. Parsed structures are
//! never re-encoded before signature verification.

use std::{collections::HashSet, fmt};

use bytes::Bytes;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;
use weaver_core::{AppAddr, DeviceId, MemberId, NetworkId, ServiceId};

const MEMBER_MAGIC: &[u8; 8] = b"WVRMEM\0\x01";
const ADMIN_MAGIC: &[u8; 8] = b"WVRADM\0\x01";
const ENDPOINT_MAGIC: &[u8; 8] = b"WVREND\0\x01";
const APP_REG_MAGIC: &[u8; 8] = b"WVRAPP\0\x01";
const APP_REG_REQUEST_MAGIC: &[u8; 8] = b"WVRAPR\0\x01";
const APP_BIND_MAGIC: &[u8; 8] = b"WVRBND\0\x01";
const JOIN_REQUEST_MAGIC: &[u8; 8] = b"WVRJNR\0\x01";
const PREPARED_JOIN_MAGIC: &[u8; 8] = b"WVRPJR\0\x01";
const SIGNATURE_LEN: usize = 64;
const MEMBER_PAYLOAD_LEN: usize = 8 + 32 + 32 + 32 + 32 + 4 + 8 + 8 + 8 + 16;
const ADMIN_PAYLOAD_LEN: usize = 8 + 32 + 16 + 32 + 4 + 8 + 8 + 8 + 16;
const ENDPOINT_PAYLOAD_LEN: usize = 8 + 32 + 32 + 32 + 8 + 8;
const APP_REG_REQUEST_PAYLOAD_LEN: usize = 8 + 32 + 32 + 32 + 4;
const APP_REG_PAYLOAD_LEN: usize = APP_REG_REQUEST_PAYLOAD_LEN + 16;
const APP_BIND_FIXED_LEN: usize = 8 + 32 + 32 + 32 + 1 + 1 + 32 + 8 + 2;
const JOIN_REQUEST_PAYLOAD_LEN: usize = 8 + 32 + 32 + 32 + 32 + 32 + 32 + 4 + 8;
pub const MAX_SERVICES_PER_BINDING: usize = 64;
pub const ADMIN_PERMISSION_CONFIG_WRITE: u32 = 1 << 0;
pub const ADMIN_PERMISSION_ISSUE_MEMBER: u32 = 1 << 1;
pub const ADMIN_PERMISSION_REVOKE: u32 = 1 << 2;
pub const ADMIN_PERMISSION_REGISTER_APP: u32 = 1 << 3;
pub const ADMIN_PERMISSION_ALL: u32 = ADMIN_PERMISSION_CONFIG_WRITE
    | ADMIN_PERMISSION_ISSUE_MEMBER
    | ADMIN_PERMISSION_REVOKE
    | ADMIN_PERMISSION_REGISTER_APP;

pub struct SigningKeypair(SigningKey);

impl SigningKeypair {
    pub fn generate() -> Result<Self, CertificateError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| CertificateError::RandomnessUnavailable)?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    fn sign(&self, payload: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(payload).to_bytes()
    }

    /// Signs an exact runtime presence payload under a protocol-specific domain.
    pub fn sign_presence(&self, exact_payload: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.sign(&presence_signature_transcript(exact_payload))
    }
}

impl fmt::Debug for SigningKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeypair")
            .field("public", &hexless(&self.public_bytes()))
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct NetworkRootPublic {
    verifying_key: VerifyingKey,
    network_id: NetworkId,
    key_id: [u8; 16],
}

impl NetworkRootPublic {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CertificateError> {
        let verifying_key =
            VerifyingKey::from_bytes(bytes).map_err(|_| CertificateError::MalformedKey)?;
        Ok(Self {
            verifying_key,
            network_id: derive_network_id(bytes),
            key_id: derive_key_id("weaver.network-root-key-id.v1", bytes),
        })
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    pub fn verify_bytes(
        &self,
        payload: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CertificateError> {
        verify_signature(&self.verifying_key, payload, signature)
    }
}

pub struct NetworkRootKey(SigningKeypair);

impl NetworkRootKey {
    pub fn generate() -> Result<Self, CertificateError> {
        SigningKeypair::generate().map(Self)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKeypair::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> NetworkRootPublic {
        NetworkRootPublic::from_bytes(&self.0.public_bytes()).expect("generated key is valid")
    }

    pub fn sign_bytes(&self, payload: &[u8]) -> [u8; 64] {
        self.0.sign(payload)
    }
}

impl fmt::Debug for NetworkRootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkRootKey")
            .field("network_id", &self.public().network_id())
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Online authority key used for ordinary configuration commits.
///
/// Its public key is authorized by a root-signed [`AdminCertificate`]. The network root
/// is only required for genesis, recovery and administrator-key rotation.
pub struct OnlineAdminKey(SigningKeypair);

impl OnlineAdminKey {
    pub fn generate() -> Result<Self, CertificateError> {
        SigningKeypair::generate().map(Self)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKeypair::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.public_bytes()
    }

    pub fn key_id(&self) -> [u8; 16] {
        derive_key_id("weaver.online-admin-key-id.v1", &self.public_bytes())
    }

    pub fn sign_bytes(&self, payload: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(payload)
    }
}

impl fmt::Debug for OnlineAdminKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnlineAdminKey")
            .field("key_id", &hexless(&self.key_id()))
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminCertificatePayload {
    pub network_id: NetworkId,
    pub key_id: [u8; 16],
    pub public_key: [u8; 32],
    pub permissions: u32,
    pub serial: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub issuer_key_id: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct AdminCertificate {
    payload: AdminCertificatePayload,
    signed_payload: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

impl AdminCertificate {
    pub fn issue(
        root: &NetworkRootKey,
        admin_public_key: [u8; 32],
        permissions: u32,
        serial: u64,
        not_before_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, CertificateError> {
        if expires_at_ms <= not_before_ms {
            return Err(CertificateError::InvalidValidityWindow);
        }
        VerifyingKey::from_bytes(&admin_public_key).map_err(|_| CertificateError::MalformedKey)?;
        let root_public = root.public();
        let payload = AdminCertificatePayload {
            network_id: root_public.network_id(),
            key_id: derive_key_id("weaver.online-admin-key-id.v1", &admin_public_key),
            public_key: admin_public_key,
            permissions,
            serial,
            not_before_ms,
            expires_at_ms,
            issuer_key_id: root_public.key_id(),
        };
        let signed_payload = Bytes::from(encode_admin_payload(&payload));
        let signature = root.0.sign(&signed_payload);
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.len() != ADMIN_PAYLOAD_LEN + SIGNATURE_LEN {
            return Err(CertificateError::MalformedWire);
        }
        let signed_payload = Bytes::copy_from_slice(&bytes[..ADMIN_PAYLOAD_LEN]);
        let payload = decode_admin_payload(&signed_payload)?;
        let signature = bytes[ADMIN_PAYLOAD_LEN..]
            .try_into()
            .map_err(|_| CertificateError::MalformedWire)?;
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        append_signature(&self.signed_payload, &self.signature)
    }

    pub fn payload(&self) -> &AdminCertificatePayload {
        &self.payload
    }

    pub fn verify(
        &self,
        root: &NetworkRootPublic,
        expected_network: NetworkId,
        now_ms: u64,
        revoked_serials: &HashSet<u64>,
    ) -> Result<VerifiedAdmin, CertificateError> {
        if root.network_id() != expected_network || self.payload.network_id != expected_network {
            return Err(CertificateError::WrongNetwork);
        }
        if self.payload.issuer_key_id != root.key_id() {
            return Err(CertificateError::WrongIssuer);
        }
        if derive_key_id("weaver.online-admin-key-id.v1", &self.payload.public_key)
            != self.payload.key_id
        {
            return Err(CertificateError::DerivedIdentityMismatch);
        }
        validate_time(
            self.payload.not_before_ms,
            self.payload.expires_at_ms,
            now_ms,
        )?;
        if revoked_serials.contains(&self.payload.serial) {
            return Err(CertificateError::Revoked);
        }
        verify_signature(&root.verifying_key, &self.signed_payload, &self.signature)?;
        let verifying_key = VerifyingKey::from_bytes(&self.payload.public_key)
            .map_err(|_| CertificateError::MalformedKey)?;
        Ok(VerifiedAdmin {
            payload: self.payload.clone(),
            verifying_key,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdmin {
    payload: AdminCertificatePayload,
    verifying_key: VerifyingKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequestPayload {
    pub network_id: NetworkId,
    pub member_id: MemberId,
    pub signing_public_key: [u8; 32],
    pub encryption_public_key: [u8; 32],
    pub endpoint_id: [u8; 32],
    pub nonce: [u8; 32],
    pub requested_roles: MemberRoles,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    payload: JoinRequestPayload,
    signed_payload: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

impl JoinRequest {
    pub fn create(
        network_id: NetworkId,
        member_signing: &SigningKeypair,
        encryption_public_key: [u8; 32],
        endpoint_id: [u8; 32],
        nonce: [u8; 32],
        requested_roles: MemberRoles,
        expires_at_ms: u64,
    ) -> Result<Self, CertificateError> {
        if encryption_public_key == [0; 32] || endpoint_id == [0; 32] || nonce == [0; 32] {
            return Err(CertificateError::MalformedKey);
        }
        let signing_public_key = member_signing.public_bytes();
        let payload = JoinRequestPayload {
            network_id,
            member_id: derive_member_id(network_id, &signing_public_key),
            signing_public_key,
            encryption_public_key,
            endpoint_id,
            nonce,
            requested_roles,
            expires_at_ms,
        };
        let signed_payload = Bytes::from(encode_join_request_payload(&payload));
        let signature = member_signing.sign(&signed_payload);
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.len() != JOIN_REQUEST_PAYLOAD_LEN + SIGNATURE_LEN {
            return Err(CertificateError::MalformedWire);
        }
        let signed_payload = Bytes::copy_from_slice(&bytes[..JOIN_REQUEST_PAYLOAD_LEN]);
        let payload = decode_join_request_payload(&signed_payload)?;
        let signature = bytes[JOIN_REQUEST_PAYLOAD_LEN..]
            .try_into()
            .map_err(|_| CertificateError::MalformedWire)?;
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        append_signature(&self.signed_payload, &self.signature)
    }

    pub fn payload(&self) -> &JoinRequestPayload {
        &self.payload
    }

    pub fn verify(
        &self,
        expected_network: NetworkId,
        now_ms: u64,
    ) -> Result<VerifiedJoinRequest, CertificateError> {
        if self.payload.network_id != expected_network {
            return Err(CertificateError::WrongNetwork);
        }
        if now_ms >= self.payload.expires_at_ms {
            return Err(CertificateError::Expired);
        }
        if self.payload.encryption_public_key == [0; 32]
            || self.payload.endpoint_id == [0; 32]
            || self.payload.nonce == [0; 32]
        {
            return Err(CertificateError::MalformedKey);
        }
        if derive_member_id(expected_network, &self.payload.signing_public_key)
            != self.payload.member_id
        {
            return Err(CertificateError::DerivedIdentityMismatch);
        }
        let key = VerifyingKey::from_bytes(&self.payload.signing_public_key)
            .map_err(|_| CertificateError::MalformedKey)?;
        verify_signature(&key, &self.signed_payload, &self.signature)?;
        Ok(VerifiedJoinRequest(self.payload.clone()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedJoinRequest(JoinRequestPayload);

impl VerifiedJoinRequest {
    pub fn payload(&self) -> &JoinRequestPayload {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedJoinRequest {
    pub request: JoinRequest,
    pub endpoint_binding: EndpointBinding,
}

impl PreparedJoinRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        network_id: NetworkId,
        member_signing: &SigningKeypair,
        encryption_public_key: [u8; 32],
        endpoint_id: [u8; 32],
        nonce: [u8; 32],
        requested_roles: MemberRoles,
        expires_at_ms: u64,
    ) -> Result<Self, CertificateError> {
        Ok(Self {
            request: JoinRequest::create(
                network_id,
                member_signing,
                encryption_public_key,
                endpoint_id,
                nonce,
                requested_roles,
                expires_at_ms,
            )?,
            endpoint_binding: EndpointBinding::issue_for_join(
                member_signing,
                network_id,
                endpoint_id,
                0,
                expires_at_ms,
            )?,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        let request = self.request.to_bytes();
        let endpoint = self.endpoint_binding.to_bytes();
        let mut out = Vec::with_capacity(8 + 4 + request.len() + 4 + endpoint.len());
        out.extend_from_slice(PREPARED_JOIN_MAGIC);
        out.extend_from_slice(&(request.len() as u32).to_be_bytes());
        out.extend_from_slice(&request);
        out.extend_from_slice(&(endpoint.len() as u32).to_be_bytes());
        out.extend_from_slice(&endpoint);
        Bytes::from(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateError> {
        let mut decoder = Decoder::new(bytes);
        decoder.magic(PREPARED_JOIN_MAGIC)?;
        let request_len = decoder.u32()? as usize;
        if request_len != JOIN_REQUEST_PAYLOAD_LEN + SIGNATURE_LEN {
            return Err(CertificateError::MalformedWire);
        }
        let request = JoinRequest::from_bytes(decoder.take(request_len)?)?;
        let endpoint_len = decoder.u32()? as usize;
        if endpoint_len != ENDPOINT_PAYLOAD_LEN + SIGNATURE_LEN {
            return Err(CertificateError::MalformedWire);
        }
        let endpoint_binding = EndpointBinding::from_bytes(decoder.take(endpoint_len)?)?;
        decoder.finish()?;
        Ok(Self {
            request,
            endpoint_binding,
        })
    }

    pub fn verify(
        &self,
        expected_network: NetworkId,
        now_ms: u64,
    ) -> Result<VerifiedJoinRequest, CertificateError> {
        let request = self.request.verify(expected_network, now_ms)?;
        self.endpoint_binding
            .verify_for_join(&request, expected_network, now_ms)?;
        Ok(request)
    }
}

impl VerifiedAdmin {
    pub fn payload(&self) -> &AdminCertificatePayload {
        &self.payload
    }

    pub fn verify_bytes(
        &self,
        payload: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<(), CertificateError> {
        verify_signature(&self.verifying_key, payload, signature)
    }
}

pub struct AppRootKey(SigningKeypair);

impl AppRootKey {
    pub fn generate() -> Result<Self, CertificateError> {
        SigningKeypair::generate().map(Self)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKeypair::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.public_bytes()
    }

    pub fn app_addr(&self) -> AppAddr {
        derive_app_addr(&self.public_bytes())
    }
}

impl fmt::Debug for AppRootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppRootKey")
            .field("app_addr", &self.app_addr())
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberRoles(u32);

impl MemberRoles {
    pub const MEMBER: Self = Self(1 << 0);
    pub const SERVICE: Self = Self(1 << 1);
    pub const RELAY: Self = Self(1 << 2);
    pub const BOOTSTRAP: Self = Self(1 << 3);
    pub const AUTHORITY: Self = Self(1 << 4);

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
pub struct MemberCertificatePayload {
    pub network_id: NetworkId,
    pub member_id: MemberId,
    pub signing_public_key: [u8; 32],
    pub encryption_public_key: [u8; 32],
    pub roles: MemberRoles,
    pub serial: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub issuer_key_id: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberCertificate {
    payload: MemberCertificatePayload,
    signed_payload: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

impl MemberCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        root: &NetworkRootKey,
        member_signing_public: [u8; 32],
        encryption_public_key: [u8; 32],
        roles: MemberRoles,
        serial: u64,
        not_before_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, CertificateError> {
        if expires_at_ms <= not_before_ms {
            return Err(CertificateError::InvalidValidityWindow);
        }
        let root_public = root.public();
        let payload = MemberCertificatePayload {
            network_id: root_public.network_id(),
            member_id: derive_member_id(root_public.network_id(), &member_signing_public),
            signing_public_key: member_signing_public,
            encryption_public_key,
            roles,
            serial,
            not_before_ms,
            expires_at_ms,
            issuer_key_id: root_public.key_id(),
        };
        let signed_payload = Bytes::from(encode_member_payload(&payload));
        let signature = root.0.sign(&signed_payload);
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.len() != MEMBER_PAYLOAD_LEN + SIGNATURE_LEN {
            return Err(CertificateError::MalformedWire);
        }
        let signed_payload = Bytes::copy_from_slice(&bytes[..MEMBER_PAYLOAD_LEN]);
        let payload = decode_member_payload(&signed_payload)?;
        let signature = bytes[MEMBER_PAYLOAD_LEN..]
            .try_into()
            .map_err(|_| CertificateError::MalformedWire)?;
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_by_admin(
        admin: &OnlineAdminKey,
        admin_certificate: &AdminCertificatePayload,
        member_signing_public: [u8; 32],
        encryption_public_key: [u8; 32],
        roles: MemberRoles,
        serial: u64,
        not_before_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, CertificateError> {
        if admin.public_bytes() != admin_certificate.public_key
            || admin.key_id() != admin_certificate.key_id
        {
            return Err(CertificateError::KeyMismatch);
        }
        if admin_certificate.permissions & ADMIN_PERMISSION_ISSUE_MEMBER == 0 {
            return Err(CertificateError::PermissionDenied);
        }
        if expires_at_ms <= not_before_ms
            || not_before_ms < admin_certificate.not_before_ms
            || expires_at_ms > admin_certificate.expires_at_ms
        {
            return Err(CertificateError::InvalidValidityWindow);
        }
        let payload = MemberCertificatePayload {
            network_id: admin_certificate.network_id,
            member_id: derive_member_id(admin_certificate.network_id, &member_signing_public),
            signing_public_key: member_signing_public,
            encryption_public_key,
            roles,
            serial,
            not_before_ms,
            expires_at_ms,
            issuer_key_id: admin_certificate.key_id,
        };
        let signed_payload = Bytes::from(encode_member_payload(&payload));
        let signature = admin.sign_bytes(&signed_payload);
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        append_signature(&self.signed_payload, &self.signature)
    }

    pub fn payload(&self) -> &MemberCertificatePayload {
        &self.payload
    }

    /// Verifies a runtime presence signature after this certificate came from a
    /// fully validated network configuration.
    pub fn verify_presence(
        &self,
        exact_payload: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<(), CertificateError> {
        let key = VerifyingKey::from_bytes(&self.payload.signing_public_key)
            .map_err(|_| CertificateError::MalformedKey)?;
        verify_signature(
            &key,
            &presence_signature_transcript(exact_payload),
            signature,
        )
    }

    pub fn verify(
        &self,
        root: &NetworkRootPublic,
        expected_network: NetworkId,
        now_ms: u64,
        revoked_serials: &HashSet<u64>,
    ) -> Result<VerifiedMember, CertificateError> {
        if root.network_id() != expected_network || self.payload.network_id != expected_network {
            return Err(CertificateError::WrongNetwork);
        }
        if self.payload.issuer_key_id != root.key_id() {
            return Err(CertificateError::WrongIssuer);
        }
        if derive_member_id(expected_network, &self.payload.signing_public_key)
            != self.payload.member_id
        {
            return Err(CertificateError::DerivedIdentityMismatch);
        }
        validate_time(
            self.payload.not_before_ms,
            self.payload.expires_at_ms,
            now_ms,
        )?;
        if revoked_serials.contains(&self.payload.serial) {
            return Err(CertificateError::Revoked);
        }
        verify_signature(&root.verifying_key, &self.signed_payload, &self.signature)?;
        Ok(VerifiedMember(self.payload.clone()))
    }

    pub fn verify_with_admin(
        &self,
        admin: &VerifiedAdmin,
        expected_network: NetworkId,
        now_ms: u64,
        revoked_serials: &HashSet<u64>,
    ) -> Result<VerifiedMember, CertificateError> {
        if admin.payload.network_id != expected_network
            || self.payload.network_id != expected_network
        {
            return Err(CertificateError::WrongNetwork);
        }
        if admin.payload.permissions & ADMIN_PERMISSION_ISSUE_MEMBER == 0 {
            return Err(CertificateError::PermissionDenied);
        }
        if self.payload.issuer_key_id != admin.payload.key_id {
            return Err(CertificateError::WrongIssuer);
        }
        if self.payload.not_before_ms < admin.payload.not_before_ms
            || self.payload.expires_at_ms > admin.payload.expires_at_ms
        {
            return Err(CertificateError::InvalidValidityWindow);
        }
        if derive_member_id(expected_network, &self.payload.signing_public_key)
            != self.payload.member_id
        {
            return Err(CertificateError::DerivedIdentityMismatch);
        }
        validate_time(
            self.payload.not_before_ms,
            self.payload.expires_at_ms,
            now_ms,
        )?;
        if revoked_serials.contains(&self.payload.serial) {
            return Err(CertificateError::Revoked);
        }
        admin.verify_bytes(&self.signed_payload, &self.signature)?;
        Ok(VerifiedMember(self.payload.clone()))
    }
}

fn presence_signature_transcript(payload: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(37 + payload.len());
    transcript.extend_from_slice(b"weaver.member-presence-signature.v1\0");
    transcript.extend_from_slice(payload);
    transcript
}

#[derive(Clone, Debug)]
pub struct VerifiedMember(MemberCertificatePayload);

impl VerifiedMember {
    pub fn payload(&self) -> &MemberCertificatePayload {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointBindingPayload {
    pub network_id: NetworkId,
    pub member_id: MemberId,
    pub endpoint_id: [u8; 32],
    pub sequence: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointBinding {
    payload: EndpointBindingPayload,
    signed_payload: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

impl EndpointBinding {
    pub fn issue(
        member_key: &SigningKeypair,
        member: &MemberCertificatePayload,
        endpoint_id: [u8; 32],
        sequence: u64,
        expires_at_ms: u64,
    ) -> Result<Self, CertificateError> {
        if member_key.public_bytes() != member.signing_public_key {
            return Err(CertificateError::KeyMismatch);
        }
        let payload = EndpointBindingPayload {
            network_id: member.network_id,
            member_id: member.member_id,
            endpoint_id,
            sequence,
            expires_at_ms,
        };
        let signed_payload = Bytes::from(encode_endpoint_payload(&payload));
        let signature = member_key.sign(&signed_payload);
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn issue_for_join(
        member_key: &SigningKeypair,
        network_id: NetworkId,
        endpoint_id: [u8; 32],
        sequence: u64,
        expires_at_ms: u64,
    ) -> Result<Self, CertificateError> {
        if endpoint_id == [0; 32] {
            return Err(CertificateError::MalformedKey);
        }
        let payload = EndpointBindingPayload {
            network_id,
            member_id: derive_member_id(network_id, &member_key.public_bytes()),
            endpoint_id,
            sequence,
            expires_at_ms,
        };
        let signed_payload = Bytes::from(encode_endpoint_payload(&payload));
        let signature = member_key.sign(&signed_payload);
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.len() != ENDPOINT_PAYLOAD_LEN + SIGNATURE_LEN {
            return Err(CertificateError::MalformedWire);
        }
        let signed_payload = Bytes::copy_from_slice(&bytes[..ENDPOINT_PAYLOAD_LEN]);
        let payload = decode_endpoint_payload(&signed_payload)?;
        let signature = bytes[ENDPOINT_PAYLOAD_LEN..]
            .try_into()
            .map_err(|_| CertificateError::MalformedWire)?;
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        append_signature(&self.signed_payload, &self.signature)
    }

    pub fn payload(&self) -> &EndpointBindingPayload {
        &self.payload
    }

    pub fn verify(
        &self,
        member: &VerifiedMember,
        expected_network: NetworkId,
        expected_endpoint: [u8; 32],
        now_ms: u64,
    ) -> Result<(), CertificateError> {
        if self.payload.network_id != expected_network || member.0.network_id != expected_network {
            return Err(CertificateError::WrongNetwork);
        }
        if self.payload.member_id != member.0.member_id
            || self.payload.endpoint_id != expected_endpoint
        {
            return Err(CertificateError::BindingMismatch);
        }
        if now_ms >= self.payload.expires_at_ms {
            return Err(CertificateError::Expired);
        }
        let key = VerifyingKey::from_bytes(&member.0.signing_public_key)
            .map_err(|_| CertificateError::MalformedKey)?;
        verify_signature(&key, &self.signed_payload, &self.signature)
    }

    pub fn verify_for_join(
        &self,
        request: &VerifiedJoinRequest,
        expected_network: NetworkId,
        now_ms: u64,
    ) -> Result<(), CertificateError> {
        if self.payload.network_id != expected_network
            || request.payload().network_id != expected_network
        {
            return Err(CertificateError::WrongNetwork);
        }
        if self.payload.member_id != request.payload().member_id
            || self.payload.endpoint_id != request.payload().endpoint_id
            || self.payload.sequence != 0
            || self.payload.expires_at_ms != request.payload().expires_at_ms
        {
            return Err(CertificateError::BindingMismatch);
        }
        if now_ms >= self.payload.expires_at_ms {
            return Err(CertificateError::Expired);
        }
        let key = VerifyingKey::from_bytes(&request.payload().signing_public_key)
            .map_err(|_| CertificateError::MalformedKey)?;
        verify_signature(&key, &self.signed_payload, &self.signature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRegistrationPayload {
    pub network_id: NetworkId,
    pub app_addr: AppAddr,
    pub app_root_public_key: [u8; 32],
    pub policy: u32,
    pub issuer_key_id: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRegistrationRequestPayload {
    pub network_id: NetworkId,
    pub app_addr: AppAddr,
    pub app_root_public_key: [u8; 32],
    pub policy: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRegistrationRequest {
    payload: AppRegistrationRequestPayload,
    signed_payload: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

impl AppRegistrationRequest {
    pub fn create(app_root: &AppRootKey, network_id: NetworkId, policy: u32) -> Self {
        let payload = AppRegistrationRequestPayload {
            network_id,
            app_addr: app_root.app_addr(),
            app_root_public_key: app_root.public_bytes(),
            policy,
        };
        let signed_payload = Bytes::from(encode_app_registration_request_payload(&payload));
        let signature = app_root.0.sign(&signed_payload);
        Self {
            payload,
            signed_payload,
            signature,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.len() != APP_REG_REQUEST_PAYLOAD_LEN + SIGNATURE_LEN {
            return Err(CertificateError::MalformedWire);
        }
        let signed_payload = Bytes::copy_from_slice(&bytes[..APP_REG_REQUEST_PAYLOAD_LEN]);
        let payload = decode_app_registration_request_payload(&signed_payload)?;
        let signature = bytes[APP_REG_REQUEST_PAYLOAD_LEN..]
            .try_into()
            .map_err(|_| CertificateError::MalformedWire)?;
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        append_signature(&self.signed_payload, &self.signature)
    }

    pub fn verify(
        &self,
        expected_network: NetworkId,
    ) -> Result<VerifiedAppRegistrationRequest, CertificateError> {
        if self.payload.network_id != expected_network {
            return Err(CertificateError::WrongNetwork);
        }
        if derive_app_addr(&self.payload.app_root_public_key) != self.payload.app_addr {
            return Err(CertificateError::DerivedIdentityMismatch);
        }
        let key = VerifyingKey::from_bytes(&self.payload.app_root_public_key)
            .map_err(|_| CertificateError::MalformedKey)?;
        verify_signature(&key, &self.signed_payload, &self.signature)?;
        Ok(VerifiedAppRegistrationRequest(self.payload.clone()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAppRegistrationRequest(AppRegistrationRequestPayload);

impl VerifiedAppRegistrationRequest {
    pub fn payload(&self) -> &AppRegistrationRequestPayload {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct AppRegistration {
    payload: AppRegistrationPayload,
    signed_payload: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

impl AppRegistration {
    pub fn issue(root: &NetworkRootKey, app_root: &AppRootKey, policy: u32) -> Self {
        let payload = AppRegistrationPayload {
            network_id: root.public().network_id(),
            app_addr: app_root.app_addr(),
            app_root_public_key: app_root.public_bytes(),
            policy,
            issuer_key_id: root.public().key_id(),
        };
        let signed_payload = Bytes::from(encode_app_registration_payload(&payload));
        let signature = root.0.sign(&signed_payload);
        Self {
            payload,
            signed_payload,
            signature,
        }
    }

    pub fn issue_by_admin(
        admin: &OnlineAdminKey,
        admin_certificate: &AdminCertificatePayload,
        request: &VerifiedAppRegistrationRequest,
    ) -> Result<Self, CertificateError> {
        if admin.public_bytes() != admin_certificate.public_key
            || admin.key_id() != admin_certificate.key_id
        {
            return Err(CertificateError::KeyMismatch);
        }
        if admin_certificate.permissions & ADMIN_PERMISSION_REGISTER_APP == 0 {
            return Err(CertificateError::PermissionDenied);
        }
        if request.payload().network_id != admin_certificate.network_id {
            return Err(CertificateError::WrongNetwork);
        }
        let payload = AppRegistrationPayload {
            network_id: request.payload().network_id,
            app_addr: request.payload().app_addr,
            app_root_public_key: request.payload().app_root_public_key,
            policy: request.payload().policy,
            issuer_key_id: admin_certificate.key_id,
        };
        let signed_payload = Bytes::from(encode_app_registration_payload(&payload));
        let signature = admin.sign_bytes(&signed_payload);
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.len() != APP_REG_PAYLOAD_LEN + SIGNATURE_LEN {
            return Err(CertificateError::MalformedWire);
        }
        let signed_payload = Bytes::copy_from_slice(&bytes[..APP_REG_PAYLOAD_LEN]);
        let payload = decode_app_registration_payload(&signed_payload)?;
        let signature = bytes[APP_REG_PAYLOAD_LEN..]
            .try_into()
            .map_err(|_| CertificateError::MalformedWire)?;
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        append_signature(&self.signed_payload, &self.signature)
    }

    pub fn payload(&self) -> &AppRegistrationPayload {
        &self.payload
    }

    pub fn verify(
        &self,
        root: &NetworkRootPublic,
        expected_network: NetworkId,
    ) -> Result<VerifiedApp, CertificateError> {
        if root.network_id() != expected_network || self.payload.network_id != expected_network {
            return Err(CertificateError::WrongNetwork);
        }
        if self.payload.issuer_key_id != root.key_id() {
            return Err(CertificateError::WrongIssuer);
        }
        if derive_app_addr(&self.payload.app_root_public_key) != self.payload.app_addr {
            return Err(CertificateError::DerivedIdentityMismatch);
        }
        verify_signature(&root.verifying_key, &self.signed_payload, &self.signature)?;
        Ok(VerifiedApp(self.payload.clone()))
    }

    pub fn verify_with_admin(
        &self,
        admin: &VerifiedAdmin,
        expected_network: NetworkId,
    ) -> Result<VerifiedApp, CertificateError> {
        if admin.payload.network_id != expected_network
            || self.payload.network_id != expected_network
        {
            return Err(CertificateError::WrongNetwork);
        }
        if admin.payload.permissions & ADMIN_PERMISSION_REGISTER_APP == 0 {
            return Err(CertificateError::PermissionDenied);
        }
        if self.payload.issuer_key_id != admin.payload.key_id {
            return Err(CertificateError::WrongIssuer);
        }
        if derive_app_addr(&self.payload.app_root_public_key) != self.payload.app_addr {
            return Err(CertificateError::DerivedIdentityMismatch);
        }
        admin.verify_bytes(&self.signed_payload, &self.signature)?;
        Ok(VerifiedApp(self.payload.clone()))
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedApp(AppRegistrationPayload);

impl VerifiedApp {
    pub fn payload(&self) -> &AppRegistrationPayload {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppRole {
    Server,
    Client,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppBindingPayload {
    pub network_id: NetworkId,
    pub app_addr: AppAddr,
    pub subject: MemberId,
    pub role: AppRole,
    pub device_id: Option<DeviceId>,
    pub expires_at_ms: u64,
    pub services: Vec<ServiceId>,
}

#[derive(Clone, Debug)]
pub struct AppBinding {
    payload: AppBindingPayload,
    signed_payload: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

impl AppBinding {
    pub fn issue(
        app_root: &AppRootKey,
        network_id: NetworkId,
        subject: MemberId,
        role: AppRole,
        device_id: Option<DeviceId>,
        expires_at_ms: u64,
        services: Vec<ServiceId>,
    ) -> Result<Self, CertificateError> {
        validate_app_role(role, device_id)?;
        if services.len() > MAX_SERVICES_PER_BINDING {
            return Err(CertificateError::TooManyServices);
        }
        let payload = AppBindingPayload {
            network_id,
            app_addr: app_root.app_addr(),
            subject,
            role,
            device_id,
            expires_at_ms,
            services,
        };
        let signed_payload = Bytes::from(encode_app_binding_payload(&payload));
        let signature = app_root.0.sign(&signed_payload);
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateError> {
        if bytes.len() < APP_BIND_FIXED_LEN + SIGNATURE_LEN {
            return Err(CertificateError::MalformedWire);
        }
        let payload_len = bytes.len() - SIGNATURE_LEN;
        let signed_payload = Bytes::copy_from_slice(&bytes[..payload_len]);
        let payload = decode_app_binding_payload(&signed_payload)?;
        let signature = bytes[payload_len..]
            .try_into()
            .map_err(|_| CertificateError::MalformedWire)?;
        Ok(Self {
            payload,
            signed_payload,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        append_signature(&self.signed_payload, &self.signature)
    }

    pub fn payload(&self) -> &AppBindingPayload {
        &self.payload
    }

    pub fn verify(
        &self,
        app: &VerifiedApp,
        member: &VerifiedMember,
        expected_network: NetworkId,
        now_ms: u64,
    ) -> Result<(), CertificateError> {
        if self.payload.network_id != expected_network
            || app.0.network_id != expected_network
            || member.0.network_id != expected_network
        {
            return Err(CertificateError::WrongNetwork);
        }
        if self.payload.app_addr != app.0.app_addr || self.payload.subject != member.0.member_id {
            return Err(CertificateError::BindingMismatch);
        }
        validate_app_role(self.payload.role, self.payload.device_id)?;
        if now_ms >= self.payload.expires_at_ms {
            return Err(CertificateError::Expired);
        }
        let key = VerifyingKey::from_bytes(&app.0.app_root_public_key)
            .map_err(|_| CertificateError::MalformedKey)?;
        verify_signature(&key, &self.signed_payload, &self.signature)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertificateError {
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("malformed public key")]
    MalformedKey,
    #[error("malformed certificate wire bytes")]
    MalformedWire,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("certificate belongs to a different network")]
    WrongNetwork,
    #[error("certificate issuer does not match network root")]
    WrongIssuer,
    #[error("certificate is not valid yet")]
    NotYetValid,
    #[error("certificate or binding is expired")]
    Expired,
    #[error("member certificate was revoked")]
    Revoked,
    #[error("derived identity does not match encoded identity")]
    DerivedIdentityMismatch,
    #[error("private/public key does not match certificate")]
    KeyMismatch,
    #[error("binding does not match authenticated member or endpoint")]
    BindingMismatch,
    #[error("invalid certificate validity window")]
    InvalidValidityWindow,
    #[error("client bindings require DeviceId; server bindings forbid it")]
    InvalidAppRole,
    #[error("app binding exceeds service limit")]
    TooManyServices,
    #[error("administrator certificate lacks the required permission")]
    PermissionDenied,
}

pub fn derive_network_id(root_public_key: &[u8; 32]) -> NetworkId {
    NetworkId::from_bytes(blake3::derive_key("weaver.network.v1", root_public_key))
}

pub fn derive_member_id(network_id: NetworkId, signing_public_key: &[u8; 32]) -> MemberId {
    let mut hasher = blake3::Hasher::new_derive_key("weaver.member.v1");
    hasher.update(network_id.as_bytes());
    hasher.update(signing_public_key);
    MemberId::from_bytes(*hasher.finalize().as_bytes())
}

pub fn derive_app_addr(app_root_public_key: &[u8; 32]) -> AppAddr {
    AppAddr::from_bytes(blake3::derive_key("weaver.app.v1", app_root_public_key))
}

pub fn derive_device_id(
    network_id: NetworkId,
    app_addr: AppAddr,
    member_signing_public_key: &[u8; 32],
) -> DeviceId {
    let mut hasher = blake3::Hasher::new_derive_key("weaver.device.v1");
    hasher.update(network_id.as_bytes());
    hasher.update(app_addr.as_bytes());
    hasher.update(member_signing_public_key);
    DeviceId::from_bytes(*hasher.finalize().as_bytes())
}

fn derive_key_id(context: &'static str, key: &[u8; 32]) -> [u8; 16] {
    blake3::derive_key(context, key)[..16]
        .try_into()
        .expect("fixed length")
}

fn validate_time(not_before: u64, expires: u64, now: u64) -> Result<(), CertificateError> {
    if now < not_before {
        Err(CertificateError::NotYetValid)
    } else if now >= expires {
        Err(CertificateError::Expired)
    } else {
        Ok(())
    }
}

fn validate_app_role(role: AppRole, device: Option<DeviceId>) -> Result<(), CertificateError> {
    match (role, device) {
        (AppRole::Server, None) | (AppRole::Client, Some(_)) => Ok(()),
        _ => Err(CertificateError::InvalidAppRole),
    }
}

fn verify_signature(
    key: &VerifyingKey,
    payload: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), CertificateError> {
    key.verify(payload, &Signature::from_bytes(signature))
        .map_err(|_| CertificateError::InvalidSignature)
}

fn append_signature(payload: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Bytes {
    let mut bytes = Vec::with_capacity(payload.len() + signature.len());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(signature);
    Bytes::from(bytes)
}

fn encode_admin_payload(payload: &AdminCertificatePayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(ADMIN_PAYLOAD_LEN);
    out.extend_from_slice(ADMIN_MAGIC);
    out.extend_from_slice(payload.network_id.as_bytes());
    out.extend_from_slice(&payload.key_id);
    out.extend_from_slice(&payload.public_key);
    out.extend_from_slice(&payload.permissions.to_be_bytes());
    out.extend_from_slice(&payload.serial.to_be_bytes());
    out.extend_from_slice(&payload.not_before_ms.to_be_bytes());
    out.extend_from_slice(&payload.expires_at_ms.to_be_bytes());
    out.extend_from_slice(&payload.issuer_key_id);
    out
}

fn decode_admin_payload(bytes: &[u8]) -> Result<AdminCertificatePayload, CertificateError> {
    let mut decoder = Decoder::new(bytes);
    decoder.magic(ADMIN_MAGIC)?;
    let payload = AdminCertificatePayload {
        network_id: NetworkId::from_bytes(decoder.array()?),
        key_id: decoder.array()?,
        public_key: decoder.array()?,
        permissions: decoder.u32()?,
        serial: decoder.u64()?,
        not_before_ms: decoder.u64()?,
        expires_at_ms: decoder.u64()?,
        issuer_key_id: decoder.array()?,
    };
    decoder.finish()?;
    Ok(payload)
}

fn encode_join_request_payload(payload: &JoinRequestPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(JOIN_REQUEST_PAYLOAD_LEN);
    out.extend_from_slice(JOIN_REQUEST_MAGIC);
    out.extend_from_slice(payload.network_id.as_bytes());
    out.extend_from_slice(payload.member_id.as_bytes());
    out.extend_from_slice(&payload.signing_public_key);
    out.extend_from_slice(&payload.encryption_public_key);
    out.extend_from_slice(&payload.endpoint_id);
    out.extend_from_slice(&payload.nonce);
    out.extend_from_slice(&payload.requested_roles.bits().to_be_bytes());
    out.extend_from_slice(&payload.expires_at_ms.to_be_bytes());
    out
}

fn decode_join_request_payload(bytes: &[u8]) -> Result<JoinRequestPayload, CertificateError> {
    let mut decoder = Decoder::new(bytes);
    decoder.magic(JOIN_REQUEST_MAGIC)?;
    let payload = JoinRequestPayload {
        network_id: NetworkId::from_bytes(decoder.array()?),
        member_id: MemberId::from_bytes(decoder.array()?),
        signing_public_key: decoder.array()?,
        encryption_public_key: decoder.array()?,
        endpoint_id: decoder.array()?,
        nonce: decoder.array()?,
        requested_roles: MemberRoles::from_bits(decoder.u32()?),
        expires_at_ms: decoder.u64()?,
    };
    decoder.finish()?;
    Ok(payload)
}

fn encode_member_payload(payload: &MemberCertificatePayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(MEMBER_PAYLOAD_LEN);
    out.extend_from_slice(MEMBER_MAGIC);
    out.extend_from_slice(payload.network_id.as_bytes());
    out.extend_from_slice(payload.member_id.as_bytes());
    out.extend_from_slice(&payload.signing_public_key);
    out.extend_from_slice(&payload.encryption_public_key);
    out.extend_from_slice(&payload.roles.bits().to_be_bytes());
    out.extend_from_slice(&payload.serial.to_be_bytes());
    out.extend_from_slice(&payload.not_before_ms.to_be_bytes());
    out.extend_from_slice(&payload.expires_at_ms.to_be_bytes());
    out.extend_from_slice(&payload.issuer_key_id);
    out
}

fn decode_member_payload(bytes: &[u8]) -> Result<MemberCertificatePayload, CertificateError> {
    let mut decoder = Decoder::new(bytes);
    decoder.magic(MEMBER_MAGIC)?;
    let payload = MemberCertificatePayload {
        network_id: NetworkId::from_bytes(decoder.array()?),
        member_id: MemberId::from_bytes(decoder.array()?),
        signing_public_key: decoder.array()?,
        encryption_public_key: decoder.array()?,
        roles: MemberRoles::from_bits(decoder.u32()?),
        serial: decoder.u64()?,
        not_before_ms: decoder.u64()?,
        expires_at_ms: decoder.u64()?,
        issuer_key_id: decoder.array()?,
    };
    decoder.finish()?;
    Ok(payload)
}

fn encode_endpoint_payload(payload: &EndpointBindingPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENDPOINT_PAYLOAD_LEN);
    out.extend_from_slice(ENDPOINT_MAGIC);
    out.extend_from_slice(payload.network_id.as_bytes());
    out.extend_from_slice(payload.member_id.as_bytes());
    out.extend_from_slice(&payload.endpoint_id);
    out.extend_from_slice(&payload.sequence.to_be_bytes());
    out.extend_from_slice(&payload.expires_at_ms.to_be_bytes());
    out
}

fn decode_endpoint_payload(bytes: &[u8]) -> Result<EndpointBindingPayload, CertificateError> {
    let mut decoder = Decoder::new(bytes);
    decoder.magic(ENDPOINT_MAGIC)?;
    let payload = EndpointBindingPayload {
        network_id: NetworkId::from_bytes(decoder.array()?),
        member_id: MemberId::from_bytes(decoder.array()?),
        endpoint_id: decoder.array()?,
        sequence: decoder.u64()?,
        expires_at_ms: decoder.u64()?,
    };
    decoder.finish()?;
    Ok(payload)
}

fn encode_app_registration_payload(payload: &AppRegistrationPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(APP_REG_PAYLOAD_LEN);
    out.extend_from_slice(APP_REG_MAGIC);
    out.extend_from_slice(payload.network_id.as_bytes());
    out.extend_from_slice(payload.app_addr.as_bytes());
    out.extend_from_slice(&payload.app_root_public_key);
    out.extend_from_slice(&payload.policy.to_be_bytes());
    out.extend_from_slice(&payload.issuer_key_id);
    out
}

fn decode_app_registration_payload(
    bytes: &[u8],
) -> Result<AppRegistrationPayload, CertificateError> {
    let mut decoder = Decoder::new(bytes);
    decoder.magic(APP_REG_MAGIC)?;
    let payload = AppRegistrationPayload {
        network_id: NetworkId::from_bytes(decoder.array()?),
        app_addr: AppAddr::from_bytes(decoder.array()?),
        app_root_public_key: decoder.array()?,
        policy: decoder.u32()?,
        issuer_key_id: decoder.array()?,
    };
    decoder.finish()?;
    Ok(payload)
}

fn encode_app_registration_request_payload(payload: &AppRegistrationRequestPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(APP_REG_REQUEST_PAYLOAD_LEN);
    out.extend_from_slice(APP_REG_REQUEST_MAGIC);
    out.extend_from_slice(payload.network_id.as_bytes());
    out.extend_from_slice(payload.app_addr.as_bytes());
    out.extend_from_slice(&payload.app_root_public_key);
    out.extend_from_slice(&payload.policy.to_be_bytes());
    out
}

fn decode_app_registration_request_payload(
    bytes: &[u8],
) -> Result<AppRegistrationRequestPayload, CertificateError> {
    let mut decoder = Decoder::new(bytes);
    decoder.magic(APP_REG_REQUEST_MAGIC)?;
    let payload = AppRegistrationRequestPayload {
        network_id: NetworkId::from_bytes(decoder.array()?),
        app_addr: AppAddr::from_bytes(decoder.array()?),
        app_root_public_key: decoder.array()?,
        policy: decoder.u32()?,
    };
    decoder.finish()?;
    Ok(payload)
}

fn encode_app_binding_payload(payload: &AppBindingPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(APP_BIND_FIXED_LEN + payload.services.len() * 16);
    out.extend_from_slice(APP_BIND_MAGIC);
    out.extend_from_slice(payload.network_id.as_bytes());
    out.extend_from_slice(payload.app_addr.as_bytes());
    out.extend_from_slice(payload.subject.as_bytes());
    out.push(match payload.role {
        AppRole::Server => 0,
        AppRole::Client => 1,
    });
    out.push(u8::from(payload.device_id.is_some()));
    out.extend_from_slice(
        payload
            .device_id
            .map(|device| *device.as_bytes())
            .unwrap_or([0; 32])
            .as_slice(),
    );
    out.extend_from_slice(&payload.expires_at_ms.to_be_bytes());
    out.extend_from_slice(&(payload.services.len() as u16).to_be_bytes());
    for service in &payload.services {
        out.extend_from_slice(service.as_bytes());
    }
    out
}

fn decode_app_binding_payload(bytes: &[u8]) -> Result<AppBindingPayload, CertificateError> {
    let mut decoder = Decoder::new(bytes);
    decoder.magic(APP_BIND_MAGIC)?;
    let network_id = NetworkId::from_bytes(decoder.array()?);
    let app_addr = AppAddr::from_bytes(decoder.array()?);
    let subject = MemberId::from_bytes(decoder.array()?);
    let role = match decoder.u8()? {
        0 => AppRole::Server,
        1 => AppRole::Client,
        _ => return Err(CertificateError::MalformedWire),
    };
    let device_present = decoder.u8()?;
    let device_bytes = decoder.array()?;
    let device_id = match device_present {
        0 if device_bytes == [0; 32] => None,
        1 => Some(DeviceId::from_bytes(device_bytes)),
        _ => return Err(CertificateError::MalformedWire),
    };
    let expires_at_ms = decoder.u64()?;
    let service_count = decoder.u16()? as usize;
    if service_count > MAX_SERVICES_PER_BINDING {
        return Err(CertificateError::TooManyServices);
    }
    let mut services = Vec::with_capacity(service_count);
    for _ in 0..service_count {
        services.push(ServiceId::from_bytes(decoder.array()?));
    }
    decoder.finish()?;
    validate_app_role(role, device_id)?;
    Ok(AppBindingPayload {
        network_id,
        app_addr,
        subject,
        role,
        device_id,
        expires_at_ms,
        services,
    })
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CertificateError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CertificateError::MalformedWire)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CertificateError::MalformedWire)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CertificateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CertificateError::MalformedWire)
    }

    fn magic(&mut self, expected: &[u8]) -> Result<(), CertificateError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(CertificateError::MalformedWire)
        }
    }

    fn u8(&mut self) -> Result<u8, CertificateError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, CertificateError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CertificateError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CertificateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), CertificateError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CertificateError::MalformedWire)
        }
    }
}

fn hexless(bytes: &[u8]) -> String {
    format!("{:02x?}…", &bytes[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue_member(root: &NetworkRootKey, member_key: &SigningKeypair) -> MemberCertificate {
        MemberCertificate::issue(
            root,
            member_key.public_bytes(),
            [0xe1; 32],
            MemberRoles::MEMBER.union(MemberRoles::SERVICE),
            7,
            100,
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn full_certificate_chain_round_trips_and_verifies() {
        let root = NetworkRootKey::generate().unwrap();
        let root_public = root.public();
        let network_id = root_public.network_id();
        let member_key = SigningKeypair::generate().unwrap();
        let member = issue_member(&root, &member_key);
        let member = MemberCertificate::from_bytes(&member.to_bytes()).unwrap();
        let verified_member = member
            .verify(&root_public, network_id, 500, &HashSet::new())
            .unwrap();

        let endpoint =
            EndpointBinding::issue(&member_key, member.payload(), [0xaa; 32], 3, 900).unwrap();
        let endpoint = EndpointBinding::from_bytes(&endpoint.to_bytes()).unwrap();
        endpoint
            .verify(&verified_member, network_id, [0xaa; 32], 500)
            .unwrap();

        let app_root = AppRootKey::generate().unwrap();
        let registration = AppRegistration::issue(&root, &app_root, 0x10);
        let registration = AppRegistration::from_bytes(&registration.to_bytes()).unwrap();
        let verified_app = registration.verify(&root_public, network_id).unwrap();
        let device_id =
            derive_device_id(network_id, app_root.app_addr(), &member_key.public_bytes());
        let binding = AppBinding::issue(
            &app_root,
            network_id,
            member.payload().member_id,
            AppRole::Client,
            Some(device_id),
            900,
            vec![ServiceId::from_bytes([0x55; 16])],
        )
        .unwrap();
        let binding = AppBinding::from_bytes(&binding.to_bytes()).unwrap();
        binding
            .verify(&verified_app, &verified_member, network_id, 500)
            .unwrap();
    }

    #[test]
    fn root_authorizes_online_admin_without_exposing_root_signing() {
        let root = NetworkRootKey::generate().unwrap();
        let admin = OnlineAdminKey::generate().unwrap();
        let certificate =
            AdminCertificate::issue(&root, admin.public_bytes(), 0xffff, 19, 100, 1_000).unwrap();
        let certificate = AdminCertificate::from_bytes(&certificate.to_bytes()).unwrap();
        let verified = certificate
            .verify(
                &root.public(),
                root.public().network_id(),
                500,
                &HashSet::new(),
            )
            .unwrap();
        assert_eq!(verified.payload().key_id, admin.key_id());
        let payload = b"configuration revision one";
        verified
            .verify_bytes(payload, &admin.sign_bytes(payload))
            .unwrap();

        let other_admin = OnlineAdminKey::generate().unwrap();
        assert_eq!(
            verified.verify_bytes(payload, &other_admin.sign_bytes(payload)),
            Err(CertificateError::InvalidSignature)
        );
    }

    #[test]
    fn admin_certificate_rejects_tampering_revocation_and_wrong_network() {
        let root = NetworkRootKey::generate().unwrap();
        let other_root = NetworkRootKey::generate().unwrap();
        let admin = OnlineAdminKey::generate().unwrap();
        let certificate =
            AdminCertificate::issue(&root, admin.public_bytes(), 1, 23, 100, 1_000).unwrap();
        let mut wire = certificate.to_bytes().to_vec();
        let permissions_offset = 8 + 32 + 16 + 32;
        wire[permissions_offset + 3] ^= 1;
        let tampered = AdminCertificate::from_bytes(&wire).unwrap();
        assert_eq!(
            tampered.verify(
                &root.public(),
                root.public().network_id(),
                500,
                &HashSet::new()
            ),
            Err(CertificateError::InvalidSignature)
        );
        assert_eq!(
            certificate.verify(
                &root.public(),
                root.public().network_id(),
                500,
                &HashSet::from([23])
            ),
            Err(CertificateError::Revoked)
        );
        assert_eq!(
            certificate.verify(
                &other_root.public(),
                other_root.public().network_id(),
                500,
                &HashSet::new()
            ),
            Err(CertificateError::WrongNetwork)
        );
    }

    #[test]
    fn online_admin_issues_bounded_member_certificate_chain() {
        let root = NetworkRootKey::generate().unwrap();
        let admin = OnlineAdminKey::generate().unwrap();
        let admin_certificate = AdminCertificate::issue(
            &root,
            admin.public_bytes(),
            ADMIN_PERMISSION_ISSUE_MEMBER,
            30,
            100,
            1_000,
        )
        .unwrap();
        let verified_admin = admin_certificate
            .verify(
                &root.public(),
                root.public().network_id(),
                500,
                &HashSet::new(),
            )
            .unwrap();
        let member_key = SigningKeypair::generate().unwrap();
        let member = MemberCertificate::issue_by_admin(
            &admin,
            admin_certificate.payload(),
            member_key.public_bytes(),
            [0x44; 32],
            MemberRoles::MEMBER,
            31,
            200,
            900,
        )
        .unwrap();
        member
            .verify_with_admin(
                &verified_admin,
                root.public().network_id(),
                500,
                &HashSet::new(),
            )
            .unwrap();
        assert_eq!(
            MemberCertificate::issue_by_admin(
                &admin,
                admin_certificate.payload(),
                member_key.public_bytes(),
                [0x44; 32],
                MemberRoles::MEMBER,
                32,
                200,
                1_001,
            ),
            Err(CertificateError::InvalidValidityWindow)
        );
    }

    #[test]
    fn join_request_binds_all_candidate_keys_network_and_expiry() {
        let root = NetworkRootKey::generate().unwrap();
        let other = NetworkRootKey::generate().unwrap();
        let signing = SigningKeypair::generate().unwrap();
        let request = JoinRequest::create(
            root.public().network_id(),
            &signing,
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            MemberRoles::MEMBER,
            1_000,
        )
        .unwrap();
        let request = JoinRequest::from_bytes(&request.to_bytes()).unwrap();
        let verified = request.verify(root.public().network_id(), 500).unwrap();
        assert_eq!(verified.payload(), request.payload());
        assert_eq!(
            request.verify(other.public().network_id(), 500),
            Err(CertificateError::WrongNetwork)
        );
        assert_eq!(
            request.verify(root.public().network_id(), 1_000),
            Err(CertificateError::Expired)
        );

        let mut wire = request.to_bytes().to_vec();
        let endpoint_offset = 8 + 32 + 32 + 32 + 32;
        wire[endpoint_offset] ^= 1;
        let tampered = JoinRequest::from_bytes(&wire).unwrap();
        assert_eq!(
            tampered.verify(root.public().network_id(), 500),
            Err(CertificateError::InvalidSignature)
        );

        let prepared = PreparedJoinRequest::create(
            root.public().network_id(),
            &signing,
            [0x61; 32],
            [0x62; 32],
            [0x63; 32],
            MemberRoles::MEMBER,
            1_000,
        )
        .unwrap();
        let prepared = PreparedJoinRequest::from_bytes(&prepared.to_bytes()).unwrap();
        prepared.verify(root.public().network_id(), 500).unwrap();
        let mut mismatched = prepared.clone();
        mismatched.endpoint_binding = EndpointBinding::issue_for_join(
            &signing,
            root.public().network_id(),
            [0x64; 32],
            0,
            1_000,
        )
        .unwrap();
        assert_eq!(
            mismatched.verify(root.public().network_id(), 500),
            Err(CertificateError::BindingMismatch)
        );
    }

    #[test]
    fn app_owner_request_is_authorized_by_online_admin() {
        let root = NetworkRootKey::generate().unwrap();
        let admin = OnlineAdminKey::generate().unwrap();
        let admin_certificate = AdminCertificate::issue(
            &root,
            admin.public_bytes(),
            ADMIN_PERMISSION_REGISTER_APP,
            70,
            100,
            1_000,
        )
        .unwrap();
        let verified_admin = admin_certificate
            .verify(
                &root.public(),
                root.public().network_id(),
                500,
                &HashSet::new(),
            )
            .unwrap();
        let app_root = AppRootKey::generate().unwrap();
        let request = AppRegistrationRequest::create(&app_root, root.public().network_id(), 0x55);
        let request = AppRegistrationRequest::from_bytes(&request.to_bytes()).unwrap();
        let verified_request = request.verify(root.public().network_id()).unwrap();
        let registration =
            AppRegistration::issue_by_admin(&admin, admin_certificate.payload(), &verified_request)
                .unwrap();
        let registration = AppRegistration::from_bytes(&registration.to_bytes()).unwrap();
        let verified_app = registration
            .verify_with_admin(&verified_admin, root.public().network_id())
            .unwrap();
        assert_eq!(verified_app.payload().app_addr, app_root.app_addr());
        assert_eq!(verified_app.payload().policy, 0x55);

        let mut tampered = request.to_bytes().to_vec();
        tampered[40] ^= 1;
        let tampered = AppRegistrationRequest::from_bytes(&tampered).unwrap();
        assert_eq!(
            tampered.verify(root.public().network_id()),
            Err(CertificateError::DerivedIdentityMismatch)
        );
    }

    #[test]
    fn exact_received_payload_is_verified_and_tampering_fails() {
        let root = NetworkRootKey::generate().unwrap();
        let member_key = SigningKeypair::generate().unwrap();
        let member = issue_member(&root, &member_key);
        let mut wire = member.to_bytes().to_vec();
        let roles_offset = 8 + 32 + 32 + 32 + 32;
        wire[roles_offset + 3] ^= 0x40;
        let tampered = MemberCertificate::from_bytes(&wire).unwrap();
        assert!(matches!(
            tampered.verify(
                &root.public(),
                root.public().network_id(),
                500,
                &HashSet::new()
            ),
            Err(CertificateError::InvalidSignature)
        ));
    }

    #[test]
    fn wrong_network_revocation_and_time_fail_closed() {
        let root = NetworkRootKey::generate().unwrap();
        let other_root = NetworkRootKey::generate().unwrap();
        let member_key = SigningKeypair::generate().unwrap();
        let member = issue_member(&root, &member_key);
        assert!(matches!(
            member.verify(
                &root.public(),
                other_root.public().network_id(),
                500,
                &HashSet::new()
            ),
            Err(CertificateError::WrongNetwork)
        ));
        assert!(matches!(
            member.verify(
                &root.public(),
                root.public().network_id(),
                500,
                &HashSet::from([7])
            ),
            Err(CertificateError::Revoked)
        ));
        assert!(matches!(
            member.verify(
                &root.public(),
                root.public().network_id(),
                1_000,
                &HashSet::new()
            ),
            Err(CertificateError::Expired)
        ));
        assert!(matches!(
            member.verify(
                &root.public(),
                root.public().network_id(),
                99,
                &HashSet::new()
            ),
            Err(CertificateError::NotYetValid)
        ));
    }

    #[test]
    fn endpoint_and_app_bindings_cannot_be_retargeted() {
        let root = NetworkRootKey::generate().unwrap();
        let network = root.public().network_id();
        let member_key = SigningKeypair::generate().unwrap();
        let member = issue_member(&root, &member_key);
        let verified_member = member
            .verify(&root.public(), network, 500, &HashSet::new())
            .unwrap();
        let endpoint =
            EndpointBinding::issue(&member_key, member.payload(), [1; 32], 1, 900).unwrap();
        assert_eq!(
            endpoint.verify(&verified_member, network, [2; 32], 500),
            Err(CertificateError::BindingMismatch)
        );

        let app_root = AppRootKey::generate().unwrap();
        assert_eq!(
            AppBinding::issue(
                &app_root,
                network,
                member.payload().member_id,
                AppRole::Client,
                None,
                900,
                Vec::new(),
            )
            .unwrap_err(),
            CertificateError::InvalidAppRole
        );
        assert_eq!(
            AppBinding::issue(
                &app_root,
                network,
                member.payload().member_id,
                AppRole::Server,
                Some(DeviceId::from_bytes([3; 32])),
                900,
                Vec::new(),
            )
            .unwrap_err(),
            CertificateError::InvalidAppRole
        );
    }
}
