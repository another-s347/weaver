//! Signed, encrypted Weaver network configuration envelopes.
//!
//! Envelopes preserve and verify their exact received bytes, form a monotonic hash
//! chain, encrypt configuration payloads with XChaCha20-Poly1305 and anonymously wrap
//! each content key to active members with RFC 9180 HPKE.

use std::{collections::HashSet, fmt};

mod snapshot;

pub use snapshot::{
    AdminKey, EpochSecrets, NetworkConfigV1, NetworkPolicy, PresenceServiceDescriptor,
    RelayDescriptor, RelayRoles, SnapshotError, ValidatedNetworkConfig,
};

use bytes::Bytes;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305 as HpkeAead, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver,
    setup_sender,
};
use thiserror::Error;
use weaver_core::NetworkId;
use weaver_crypto::{CertificateError, NetworkRootKey, NetworkRootPublic, OnlineAdminKey};
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type HpkeSuiteAead = HpkeAead;

const ENVELOPE_MAGIC: &[u8; 8] = b"WVRCFG\0\x01";
const FORMAT_VERSION: u16 = 1;
const CONTENT_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SIGNATURE_LEN: usize = 64;
const MAX_CONFIG_PLAINTEXT: usize = 1024 * 1024;
const MAX_CIPHERTEXT: usize = MAX_CONFIG_PLAINTEXT + 32;
const MAX_KEY_WRAPS: usize = 256;
const MAX_WRAP_PART: usize = 1024;
const HPKE_INFO: &[u8] = b"weaver.config-key-wrap.v1";
const UPDATE_BATCH_MAGIC: &[u8; 8] = b"WVRUPD\0\x01";
const MAX_UPDATE_ENVELOPES: usize = 1024;
const MAX_UPDATE_BATCH_BYTES: usize = 16 * 1024 * 1024;
pub use weaver_crypto::ADMIN_PERMISSION_CONFIG_WRITE;

pub struct MemberEncryptionKeypair {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl MemberEncryptionKeypair {
    pub fn generate() -> Result<Self, ConfigError> {
        let (secret, public) = Kem::gen_keypair();
        let secret: [u8; 32] = secret
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| ConfigError::InvalidMemberKey)?;
        let public: [u8; 32] = public
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| ConfigError::InvalidMemberKey)?;
        Ok(Self {
            secret: Zeroizing::new(secret),
            public,
        })
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Result<Self, ConfigError> {
        let secret_key = <Kem as KemTrait>::PrivateKey::from_bytes(&secret)
            .map_err(|_| ConfigError::InvalidMemberKey)?;
        let public_key = Kem::sk_to_pk(&secret_key);
        let public = public_key
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| ConfigError::InvalidMemberKey)?;
        Ok(Self {
            secret: Zeroizing::new(secret),
            public,
        })
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        *self.secret
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }
}

impl fmt::Debug for MemberEncryptionKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemberEncryptionKeypair")
            .field("public", &format_args!("{:02x?}…", &self.public[..4]))
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyWrap {
    pub encapsulated_key: Bytes,
    pub ciphertext: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedConfigEnvelope {
    pub format_version: u16,
    pub network_id: NetworkId,
    pub epoch: u64,
    pub revision: u64,
    pub previous_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Bytes,
    pub member_key_wraps: Vec<KeyWrap>,
    pub signer_key_id: [u8; 16],
    signed_bytes: Bytes,
    signature: [u8; SIGNATURE_LEN],
}

impl EncryptedConfigEnvelope {
    pub fn seal_config(
        root: &NetworkRootKey,
        config: &NetworkConfigV1,
        recipients: &[[u8; 32]],
    ) -> Result<Self, ConfigError> {
        let root_public = root.public();
        config
            .clone()
            .validate(&root_public, root_public.network_id(), config.issued_at_ms)?;
        validate_recipient_set(config, recipients)?;
        let plaintext = config.to_bytes()?;
        Self::seal(
            root,
            config.epoch,
            config.revision,
            config.previous_hash,
            &plaintext,
            recipients,
        )
    }

    pub fn seal_next_config(
        root: &NetworkRootPublic,
        admin: &OnlineAdminKey,
        current_config: &ValidatedNetworkConfig,
        current_head: ConfigHead,
        next_config: &NetworkConfigV1,
        recipients: &[[u8; 32]],
        now_ms: u64,
    ) -> Result<Self, ConfigError> {
        if current_config.as_config().network_id != root.network_id()
            || current_config.as_config().revision != current_head.revision
            || current_config.as_config().epoch != current_head.epoch
        {
            return Err(ConfigError::EnvelopePayloadMismatch);
        }
        let verified_admin = current_config.verified_admin(root, admin.key_id(), now_ms)?;
        if verified_admin.payload().public_key != admin.public_bytes() {
            return Err(ConfigError::WrongSigner);
        }
        if verified_admin.payload().permissions & ADMIN_PERMISSION_CONFIG_WRITE == 0 {
            return Err(ConfigError::PermissionDenied);
        }
        if next_config.network_id != root.network_id()
            || next_config.revision
                != current_head
                    .revision
                    .checked_add(1)
                    .ok_or(ConfigError::ChainMismatch)?
            || next_config.previous_hash != current_head.hash
            || next_config.epoch < current_head.epoch
        {
            return Err(ConfigError::ChainMismatch);
        }
        next_config
            .clone()
            .validate(root, root.network_id(), next_config.issued_at_ms)?;
        validate_recipient_set(next_config, recipients)?;
        let plaintext = next_config.to_bytes()?;
        Self::seal_with_signer(
            root.network_id(),
            admin.key_id(),
            |payload| admin.sign_bytes(payload),
            next_config.epoch,
            next_config.revision,
            next_config.previous_hash,
            &plaintext,
            recipients,
        )
    }

    pub fn seal(
        root: &NetworkRootKey,
        epoch: u64,
        revision: u64,
        previous_hash: [u8; 32],
        plaintext: &[u8],
        recipients: &[[u8; 32]],
    ) -> Result<Self, ConfigError> {
        let public = root.public();
        Self::seal_with_signer(
            public.network_id(),
            public.key_id(),
            |payload| root.sign_bytes(payload),
            epoch,
            revision,
            previous_hash,
            plaintext,
            recipients,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_with_signer(
        network_id: NetworkId,
        signer_key_id: [u8; 16],
        sign: impl FnOnce(&[u8]) -> [u8; SIGNATURE_LEN],
        epoch: u64,
        revision: u64,
        previous_hash: [u8; 32],
        plaintext: &[u8],
        recipients: &[[u8; 32]],
    ) -> Result<Self, ConfigError> {
        if plaintext.len() > MAX_CONFIG_PLAINTEXT {
            return Err(ConfigError::PayloadTooLarge);
        }
        if recipients.is_empty() || recipients.len() > MAX_KEY_WRAPS {
            return Err(ConfigError::InvalidRecipientCount);
        }
        let payload_hash = *blake3::hash(plaintext).as_bytes();
        let mut content_key = Zeroizing::new([0; CONTENT_KEY_LEN]);
        let mut nonce = [0; NONCE_LEN];
        getrandom::fill(content_key.as_mut()).map_err(|_| ConfigError::RandomnessUnavailable)?;
        getrandom::fill(&mut nonce).map_err(|_| ConfigError::RandomnessUnavailable)?;
        let aad = envelope_aad(network_id, epoch, revision, previous_hash, payload_hash);
        let cipher = XChaCha20Poly1305::new_from_slice(content_key.as_ref())
            .map_err(|_| ConfigError::EncryptionFailed)?;
        let xnonce = XNonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &xnonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ConfigError::EncryptionFailed)?;

        let mut member_key_wraps = recipients
            .iter()
            .map(|recipient| wrap_content_key(recipient, &content_key, &aad))
            .collect::<Result<Vec<_>, _>>()?;
        shuffle(&mut member_key_wraps)?;
        let mut envelope = Self {
            format_version: FORMAT_VERSION,
            network_id,
            epoch,
            revision,
            previous_hash,
            payload_hash,
            nonce,
            ciphertext: Bytes::from(ciphertext),
            member_key_wraps,
            signer_key_id,
            signed_bytes: Bytes::new(),
            signature: [0; SIGNATURE_LEN],
        };
        envelope.signed_bytes = Bytes::from(envelope.encode_signed_bytes()?);
        envelope.signature = sign(&envelope.signed_bytes);
        Ok(envelope)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() < SIGNATURE_LEN {
            return Err(ConfigError::MalformedWire);
        }
        let signed_len = bytes.len() - SIGNATURE_LEN;
        let signed_bytes = Bytes::copy_from_slice(&bytes[..signed_len]);
        let signature = bytes[signed_len..]
            .try_into()
            .map_err(|_| ConfigError::MalformedWire)?;
        let mut decoder = Decoder::new(&signed_bytes);
        decoder.magic(ENVELOPE_MAGIC)?;
        let format_version = decoder.u16()?;
        if format_version != FORMAT_VERSION {
            return Err(ConfigError::UnsupportedVersion(format_version));
        }
        let network_id = NetworkId::from_bytes(decoder.array()?);
        let epoch = decoder.u64()?;
        let revision = decoder.u64()?;
        let previous_hash = decoder.array()?;
        let payload_hash = decoder.array()?;
        let nonce = decoder.array()?;
        let ciphertext_len = decoder.u32()? as usize;
        if ciphertext_len > MAX_CIPHERTEXT {
            return Err(ConfigError::PayloadTooLarge);
        }
        let ciphertext = Bytes::copy_from_slice(decoder.take(ciphertext_len)?);
        let wrap_count = decoder.u16()? as usize;
        if wrap_count == 0 || wrap_count > MAX_KEY_WRAPS {
            return Err(ConfigError::InvalidRecipientCount);
        }
        let mut member_key_wraps = Vec::with_capacity(wrap_count);
        for _ in 0..wrap_count {
            let enc_len = decoder.u16()? as usize;
            if enc_len == 0 || enc_len > MAX_WRAP_PART {
                return Err(ConfigError::MalformedWire);
            }
            let encapsulated_key = Bytes::copy_from_slice(decoder.take(enc_len)?);
            let wrapped_len = decoder.u16()? as usize;
            if wrapped_len == 0 || wrapped_len > MAX_WRAP_PART {
                return Err(ConfigError::MalformedWire);
            }
            let ciphertext = Bytes::copy_from_slice(decoder.take(wrapped_len)?);
            member_key_wraps.push(KeyWrap {
                encapsulated_key,
                ciphertext,
            });
        }
        let signer_key_id = decoder.array()?;
        decoder.finish()?;
        Ok(Self {
            format_version,
            network_id,
            epoch,
            revision,
            previous_hash,
            payload_hash,
            nonce,
            ciphertext,
            member_key_wraps,
            signer_key_id,
            signed_bytes,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = Vec::with_capacity(self.signed_bytes.len() + SIGNATURE_LEN);
        bytes.extend_from_slice(&self.signed_bytes);
        bytes.extend_from_slice(&self.signature);
        Bytes::from(bytes)
    }

    pub fn envelope_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.to_bytes()).as_bytes()
    }

    pub fn open(
        &self,
        root: &NetworkRootPublic,
        expected_network: NetworkId,
        recipient: &MemberEncryptionKeypair,
        chain: ChainExpectation,
    ) -> Result<OpenedConfig, ConfigError> {
        if self.network_id != expected_network || root.network_id() != expected_network {
            return Err(ConfigError::WrongNetwork);
        }
        if self.signer_key_id != root.key_id() {
            return Err(ConfigError::WrongSigner);
        }
        root.verify_bytes(&self.signed_bytes, &self.signature)
            .map_err(ConfigError::Signature)?;
        self.open_after_verified_signature(expected_network, recipient, chain)
    }

    pub fn open_next_config(
        &self,
        root: &NetworkRootPublic,
        current_config: &ValidatedNetworkConfig,
        recipient: &MemberEncryptionKeypair,
        current_head: ConfigHead,
        now_ms: u64,
    ) -> Result<OpenedNetworkConfig, ConfigError> {
        if root.network_id() != self.network_id
            || current_config.as_config().network_id != self.network_id
        {
            return Err(ConfigError::WrongNetwork);
        }
        let admin = current_config.verified_admin(root, self.signer_key_id, now_ms)?;
        self.open_config_with_verified_admin(
            root,
            &admin,
            recipient,
            ChainExpectation::Next(current_head),
            now_ms,
        )
    }

    pub fn open_config_with_verified_admin(
        &self,
        root: &NetworkRootPublic,
        admin: &weaver_crypto::VerifiedAdmin,
        recipient: &MemberEncryptionKeypair,
        chain: ChainExpectation,
        now_ms: u64,
    ) -> Result<OpenedNetworkConfig, ConfigError> {
        if root.network_id() != self.network_id || admin.payload().network_id != self.network_id {
            return Err(ConfigError::WrongNetwork);
        }
        if self.signer_key_id != admin.payload().key_id {
            return Err(ConfigError::WrongSigner);
        }
        if admin.payload().permissions & ADMIN_PERMISSION_CONFIG_WRITE == 0 {
            return Err(ConfigError::PermissionDenied);
        }
        admin
            .verify_bytes(&self.signed_bytes, &self.signature)
            .map_err(ConfigError::Signature)?;
        let opened = self.open_after_verified_signature(self.network_id, recipient, chain)?;
        self.decode_and_validate_opened(root, opened, now_ms)
    }

    fn open_after_verified_signature(
        &self,
        expected_network: NetworkId,
        recipient: &MemberEncryptionKeypair,
        chain: ChainExpectation,
    ) -> Result<OpenedConfig, ConfigError> {
        if self.network_id != expected_network {
            return Err(ConfigError::WrongNetwork);
        }
        validate_chain(self, chain)?;
        let aad = envelope_aad(
            self.network_id,
            self.epoch,
            self.revision,
            self.previous_hash,
            self.payload_hash,
        );
        let mut content_key = None;
        for wrap in &self.member_key_wraps {
            if let Ok(key) = unwrap_content_key(recipient, wrap, &aad) {
                content_key = Some(key);
                break;
            }
        }
        let content_key = Zeroizing::new(content_key.ok_or(ConfigError::NoRecipientWrap)?);
        let cipher = XChaCha20Poly1305::new_from_slice(content_key.as_ref())
            .map_err(|_| ConfigError::DecryptionFailed)?;
        let xnonce = XNonce::from(self.nonce);
        let plaintext = cipher
            .decrypt(
                &xnonce,
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ConfigError::DecryptionFailed)?;
        if blake3::hash(&plaintext).as_bytes() != &self.payload_hash {
            return Err(ConfigError::PayloadHashMismatch);
        }
        Ok(OpenedConfig {
            plaintext: Bytes::from(plaintext),
            head: ConfigHead {
                epoch: self.epoch,
                revision: self.revision,
                hash: self.envelope_hash(),
            },
        })
    }

    pub fn open_config(
        &self,
        root: &NetworkRootPublic,
        expected_network: NetworkId,
        recipient: &MemberEncryptionKeypair,
        chain: ChainExpectation,
        now_ms: u64,
    ) -> Result<OpenedNetworkConfig, ConfigError> {
        let opened = self.open(root, expected_network, recipient, chain)?;
        self.decode_and_validate_opened(root, opened, now_ms)
    }

    fn decode_and_validate_opened(
        &self,
        root: &NetworkRootPublic,
        opened: OpenedConfig,
        now_ms: u64,
    ) -> Result<OpenedNetworkConfig, ConfigError> {
        let config = NetworkConfigV1::from_bytes(&opened.plaintext)?;
        if config.network_id != self.network_id
            || config.epoch != self.epoch
            || config.revision != self.revision
            || config.previous_hash != self.previous_hash
        {
            return Err(ConfigError::EnvelopePayloadMismatch);
        }
        let config = config.validate(root, self.network_id, now_ms)?;
        Ok(OpenedNetworkConfig {
            config,
            head: opened.head,
        })
    }

    fn encode_signed_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        if self.ciphertext.len() > u32::MAX as usize
            || self.member_key_wraps.len() > u16::MAX as usize
        {
            return Err(ConfigError::MalformedWire);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ENVELOPE_MAGIC);
        bytes.extend_from_slice(&self.format_version.to_be_bytes());
        bytes.extend_from_slice(self.network_id.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        bytes.extend_from_slice(&self.previous_hash);
        bytes.extend_from_slice(&self.payload_hash);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&(self.member_key_wraps.len() as u16).to_be_bytes());
        for wrap in &self.member_key_wraps {
            if wrap.encapsulated_key.len() > u16::MAX as usize
                || wrap.ciphertext.len() > u16::MAX as usize
            {
                return Err(ConfigError::MalformedWire);
            }
            bytes.extend_from_slice(&(wrap.encapsulated_key.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&wrap.encapsulated_key);
            bytes.extend_from_slice(&(wrap.ciphertext.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&wrap.ciphertext);
        }
        bytes.extend_from_slice(&self.signer_key_id);
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigHead {
    pub epoch: u64,
    pub revision: u64,
    pub hash: [u8; 32],
}

/// A bounded, exact-byte sequence of encrypted configuration revisions.
///
/// Each envelope remains independently signed and encrypted. The batch is only a
/// transport container; consumers must open every envelope with
/// [`ChainExpectation::Next`] before committing the resulting head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigUpdateBatch {
    pub network_id: NetworkId,
    pub base_head: ConfigHead,
    pub envelopes: Vec<Bytes>,
}

impl ConfigUpdateBatch {
    pub fn new(
        network_id: NetworkId,
        base_head: ConfigHead,
        envelopes: Vec<Bytes>,
    ) -> Result<Self, ConfigError> {
        if envelopes.len() > MAX_UPDATE_ENVELOPES {
            return Err(ConfigError::UpdateBatchTooLarge);
        }
        let mut expected_revision = base_head
            .revision
            .checked_add(1)
            .ok_or(ConfigError::ChainMismatch)?;
        let mut expected_previous = base_head.hash;
        let mut total = 0_usize;
        for raw in &envelopes {
            total = total
                .checked_add(raw.len())
                .ok_or(ConfigError::UpdateBatchTooLarge)?;
            if total > MAX_UPDATE_BATCH_BYTES {
                return Err(ConfigError::UpdateBatchTooLarge);
            }
            let envelope = EncryptedConfigEnvelope::from_bytes(raw)?;
            if envelope.network_id != network_id
                || envelope.revision != expected_revision
                || envelope.previous_hash != expected_previous
            {
                return Err(ConfigError::ChainMismatch);
            }
            expected_revision = expected_revision
                .checked_add(1)
                .ok_or(ConfigError::ChainMismatch)?;
            expected_previous = envelope.envelope_hash();
        }
        Ok(Self {
            network_id,
            base_head,
            envelopes,
        })
    }

    pub fn to_bytes(&self) -> Result<Bytes, ConfigError> {
        let validated = Self::new(self.network_id, self.base_head, self.envelopes.clone())?;
        let mut out = Vec::new();
        out.extend_from_slice(UPDATE_BATCH_MAGIC);
        out.extend_from_slice(validated.network_id.as_bytes());
        out.extend_from_slice(&validated.base_head.epoch.to_be_bytes());
        out.extend_from_slice(&validated.base_head.revision.to_be_bytes());
        out.extend_from_slice(&validated.base_head.hash);
        out.extend_from_slice(&(validated.envelopes.len() as u32).to_be_bytes());
        for envelope in &validated.envelopes {
            let len =
                u32::try_from(envelope.len()).map_err(|_| ConfigError::UpdateBatchTooLarge)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(envelope);
        }
        Ok(Bytes::from(out))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_UPDATE_BATCH_BYTES {
            return Err(ConfigError::UpdateBatchTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        decoder.magic(UPDATE_BATCH_MAGIC)?;
        let network_id = NetworkId::from_bytes(decoder.array()?);
        let base_head = ConfigHead {
            epoch: decoder.u64()?,
            revision: decoder.u64()?,
            hash: decoder.array()?,
        };
        let count = decoder.u32()? as usize;
        if count > MAX_UPDATE_ENVELOPES {
            return Err(ConfigError::UpdateBatchTooLarge);
        }
        let mut envelopes = Vec::with_capacity(count);
        for _ in 0..count {
            let len = decoder.u32()? as usize;
            if len > MAX_UPDATE_BATCH_BYTES {
                return Err(ConfigError::UpdateBatchTooLarge);
            }
            envelopes.push(Bytes::copy_from_slice(decoder.take(len)?));
        }
        decoder.finish()?;
        Self::new(network_id, base_head, envelopes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainExpectation {
    Genesis,
    Next(ConfigHead),
    Checkpoint(ConfigHead),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedConfig {
    pub plaintext: Bytes,
    pub head: ConfigHead,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedNetworkConfig {
    pub config: ValidatedNetworkConfig,
    pub head: ConfigHead,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid member encryption key")]
    InvalidMemberKey,
    #[error("invalid recipient count")]
    InvalidRecipientCount,
    #[error("configuration payload is too large")]
    PayloadTooLarge,
    #[error("configuration encryption failed")]
    EncryptionFailed,
    #[error("configuration decryption or authentication failed")]
    DecryptionFailed,
    #[error("HPKE key wrapping failed")]
    KeyWrapFailed,
    #[error("no key wrap can be opened by this member")]
    NoRecipientWrap,
    #[error("malformed configuration envelope")]
    MalformedWire,
    #[error("unsupported configuration envelope version {0}")]
    UnsupportedVersion(u16),
    #[error("configuration belongs to another network")]
    WrongNetwork,
    #[error("configuration signer does not match network root")]
    WrongSigner,
    #[error("online administrator lacks configuration-write permission")]
    PermissionDenied,
    #[error("configuration signature failed: {0}")]
    Signature(CertificateError),
    #[error("configuration chain revision or previous hash does not match current head")]
    ChainMismatch,
    #[error("decrypted configuration hash differs from signed payload hash")]
    PayloadHashMismatch,
    #[error("configuration envelope metadata differs from its decrypted snapshot")]
    EnvelopePayloadMismatch,
    #[error("configuration snapshot failed validation: {0}")]
    Snapshot(#[from] SnapshotError),
    #[error("configuration recipient wraps do not exactly match active member encryption keys")]
    RecipientSetMismatch,
    #[error("configuration update batch exceeds protocol limits")]
    UpdateBatchTooLarge,
}

fn validate_recipient_set(
    config: &NetworkConfigV1,
    recipients: &[[u8; 32]],
) -> Result<(), ConfigError> {
    let expected = config
        .members
        .iter()
        .map(|raw| {
            weaver_crypto::MemberCertificate::from_bytes(raw)
                .map(|certificate| certificate.payload().encryption_public_key)
        })
        .collect::<Result<HashSet<_>, _>>()
        .map_err(ConfigError::Signature)?;
    let actual: HashSet<_> = recipients.iter().copied().collect();
    if expected.len() != config.members.len()
        || actual.len() != recipients.len()
        || expected != actual
    {
        return Err(ConfigError::RecipientSetMismatch);
    }
    Ok(())
}

fn wrap_content_key(
    recipient_public: &[u8; 32],
    content_key: &[u8; CONTENT_KEY_LEN],
    aad: &[u8],
) -> Result<KeyWrap, ConfigError> {
    let recipient = <Kem as KemTrait>::PublicKey::from_bytes(recipient_public)
        .map_err(|_| ConfigError::InvalidMemberKey)?;
    let (encapsulated, mut context) =
        setup_sender::<HpkeSuiteAead, Kdf, Kem>(&OpModeS::Base, &recipient, HPKE_INFO)
            .map_err(|_| ConfigError::KeyWrapFailed)?;
    let ciphertext = context
        .seal(content_key, aad)
        .map_err(|_| ConfigError::KeyWrapFailed)?;
    Ok(KeyWrap {
        encapsulated_key: Bytes::copy_from_slice(encapsulated.to_bytes().as_slice()),
        ciphertext: Bytes::from(ciphertext),
    })
}

fn unwrap_content_key(
    recipient: &MemberEncryptionKeypair,
    wrap: &KeyWrap,
    aad: &[u8],
) -> Result<[u8; CONTENT_KEY_LEN], ConfigError> {
    let secret = <Kem as KemTrait>::PrivateKey::from_bytes(recipient.secret.as_ref())
        .map_err(|_| ConfigError::InvalidMemberKey)?;
    let encapsulated = <Kem as KemTrait>::EncappedKey::from_bytes(&wrap.encapsulated_key)
        .map_err(|_| ConfigError::KeyWrapFailed)?;
    let mut context = setup_receiver::<HpkeSuiteAead, Kdf, Kem>(
        &OpModeR::Base,
        &secret,
        &encapsulated,
        HPKE_INFO,
    )
    .map_err(|_| ConfigError::KeyWrapFailed)?;
    context
        .open(&wrap.ciphertext, aad)
        .map_err(|_| ConfigError::KeyWrapFailed)?
        .try_into()
        .map_err(|_| ConfigError::KeyWrapFailed)
}

fn envelope_aad(
    network_id: NetworkId,
    epoch: u64,
    revision: u64,
    previous_hash: [u8; 32],
    payload_hash: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 32 + 8 + 8 + 32 + 32);
    aad.extend_from_slice(b"WVRCFGA\x01");
    aad.extend_from_slice(network_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad.extend_from_slice(&previous_hash);
    aad.extend_from_slice(&payload_hash);
    aad
}

fn validate_chain(
    envelope: &EncryptedConfigEnvelope,
    expectation: ChainExpectation,
) -> Result<(), ConfigError> {
    match expectation {
        ChainExpectation::Genesis
            if envelope.revision == 0 && envelope.previous_hash == [0; 32] =>
        {
            Ok(())
        }
        ChainExpectation::Next(head)
            if head.revision.checked_add(1) == Some(envelope.revision)
                && envelope.previous_hash == head.hash
                && envelope.epoch >= head.epoch =>
        {
            Ok(())
        }
        ChainExpectation::Checkpoint(head)
            if envelope.epoch == head.epoch
                && envelope.revision == head.revision
                && envelope.envelope_hash() == head.hash =>
        {
            Ok(())
        }
        _ => Err(ConfigError::ChainMismatch),
    }
}

fn shuffle<T>(items: &mut [T]) -> Result<(), ConfigError> {
    for index in (1..items.len()).rev() {
        let mut random = [0; 8];
        getrandom::fill(&mut random).map_err(|_| ConfigError::RandomnessUnavailable)?;
        let selected = (u64::from_le_bytes(random) % (index as u64 + 1)) as usize;
        items.swap(index, selected);
    }
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

    fn take(&mut self, len: usize) -> Result<&'a [u8], ConfigError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ConfigError::MalformedWire)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ConfigError::MalformedWire)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ConfigError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ConfigError::MalformedWire)
    }

    fn magic(&mut self, expected: &[u8]) -> Result<(), ConfigError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(ConfigError::MalformedWire)
        }
    }

    fn u16(&mut self) -> Result<u16, ConfigError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ConfigError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ConfigError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), ConfigError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ConfigError::MalformedWire)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use weaver_crypto::{
        AdminCertificate, MemberCertificate, MemberRoles, OnlineAdminKey, SigningKeypair,
    };

    #[test]
    fn envelope_round_trips_for_each_active_member_and_chains() {
        let root = NetworkRootKey::generate().unwrap();
        let network = root.public().network_id();
        let first_member = MemberEncryptionKeypair::generate().unwrap();
        let second_member = MemberEncryptionKeypair::generate().unwrap();
        let recipients = [first_member.public_bytes(), second_member.public_bytes()];
        let genesis = EncryptedConfigEnvelope::seal(
            &root,
            1,
            0,
            [0; 32],
            b"revision zero topology",
            &recipients,
        )
        .unwrap();
        let genesis = EncryptedConfigEnvelope::from_bytes(&genesis.to_bytes()).unwrap();
        let first_open = genesis
            .open(
                &root.public(),
                network,
                &first_member,
                ChainExpectation::Genesis,
            )
            .unwrap();
        let second_open = genesis
            .open(
                &root.public(),
                network,
                &second_member,
                ChainExpectation::Genesis,
            )
            .unwrap();
        assert_eq!(first_open.plaintext, b"revision zero topology"[..]);
        assert_eq!(first_open, second_open);

        let revision_one = EncryptedConfigEnvelope::seal(
            &root,
            1,
            1,
            first_open.head.hash,
            b"revision one topology",
            &recipients,
        )
        .unwrap();
        let opened = revision_one
            .open(
                &root.public(),
                network,
                &first_member,
                ChainExpectation::Next(first_open.head),
            )
            .unwrap();
        assert_eq!(opened.plaintext, b"revision one topology"[..]);
        assert_eq!(opened.head.revision, 1);

        let revision_two = EncryptedConfigEnvelope::seal(
            &root,
            1,
            2,
            opened.head.hash,
            b"revision two topology",
            &recipients,
        )
        .unwrap();
        let batch = ConfigUpdateBatch::new(
            network,
            first_open.head,
            vec![revision_one.to_bytes(), revision_two.to_bytes()],
        )
        .unwrap();
        assert_eq!(
            ConfigUpdateBatch::from_bytes(&batch.to_bytes().unwrap()).unwrap(),
            batch
        );
        let mut wrong_base = first_open.head;
        wrong_base.hash[0] ^= 1;
        assert!(matches!(
            ConfigUpdateBatch::new(network, wrong_base, vec![revision_one.to_bytes()]),
            Err(ConfigError::ChainMismatch)
        ));
    }

    #[test]
    fn removed_member_cannot_open_future_epoch() {
        let root = NetworkRootKey::generate().unwrap();
        let network = root.public().network_id();
        let removed = MemberEncryptionKeypair::generate().unwrap();
        let active = MemberEncryptionKeypair::generate().unwrap();
        let envelope = EncryptedConfigEnvelope::seal(
            &root,
            2,
            0,
            [0; 32],
            b"post-revocation config",
            &[active.public_bytes()],
        )
        .unwrap();
        assert_eq!(
            envelope.open(&root.public(), network, &removed, ChainExpectation::Genesis),
            Err(ConfigError::NoRecipientWrap)
        );
        assert!(
            envelope
                .open(&root.public(), network, &active, ChainExpectation::Genesis)
                .is_ok()
        );
    }

    #[test]
    fn tampering_wrong_network_and_rollback_fail_closed() {
        let root = NetworkRootKey::generate().unwrap();
        let other_root = NetworkRootKey::generate().unwrap();
        let member = MemberEncryptionKeypair::generate().unwrap();
        let envelope = EncryptedConfigEnvelope::seal(
            &root,
            1,
            0,
            [0; 32],
            b"protected config",
            &[member.public_bytes()],
        )
        .unwrap();
        assert_eq!(
            envelope.open(
                &root.public(),
                other_root.public().network_id(),
                &member,
                ChainExpectation::Genesis
            ),
            Err(ConfigError::WrongNetwork)
        );

        let head = envelope
            .open(
                &root.public(),
                root.public().network_id(),
                &member,
                ChainExpectation::Genesis,
            )
            .unwrap()
            .head;
        assert_eq!(
            envelope.open(
                &root.public(),
                root.public().network_id(),
                &member,
                ChainExpectation::Next(head)
            ),
            Err(ConfigError::ChainMismatch)
        );

        let mut wire = envelope.to_bytes().to_vec();
        let ciphertext_offset = 8 + 2 + 32 + 8 + 8 + 32 + 32 + 24 + 4;
        wire[ciphertext_offset] ^= 1;
        let tampered = EncryptedConfigEnvelope::from_bytes(&wire).unwrap();
        assert!(matches!(
            tampered.open(
                &root.public(),
                root.public().network_id(),
                &member,
                ChainExpectation::Genesis
            ),
            Err(ConfigError::Signature(CertificateError::InvalidSignature))
        ));
    }

    #[test]
    fn member_encryption_key_restores_same_public_key() {
        let key = MemberEncryptionKeypair::generate().unwrap();
        let restored = MemberEncryptionKeypair::from_secret_bytes(key.secret_bytes()).unwrap();
        assert_eq!(restored.public_bytes(), key.public_bytes());
    }

    #[test]
    fn online_admin_signs_only_monotonic_post_genesis_config() {
        let root = NetworkRootKey::generate().unwrap();
        let network = root.public().network_id();
        let admin = OnlineAdminKey::generate().unwrap();
        let admin_certificate = AdminCertificate::issue(
            &root,
            admin.public_bytes(),
            ADMIN_PERMISSION_CONFIG_WRITE,
            50,
            100,
            10_000,
        )
        .unwrap();
        let member_signing = SigningKeypair::generate().unwrap();
        let member_encryption = MemberEncryptionKeypair::generate().unwrap();
        let member = MemberCertificate::issue(
            &root,
            member_signing.public_bytes(),
            member_encryption.public_bytes(),
            MemberRoles::MEMBER,
            51,
            100,
            10_000,
        )
        .unwrap();
        let genesis_config = NetworkConfigV1 {
            network_id: network,
            epoch: 0,
            revision: 0,
            previous_hash: [0; 32],
            issued_at_ms: 100,
            expires_at_ms: 9_000,
            admin_keys: vec![AdminKey {
                certificate: admin_certificate.to_bytes(),
            }],
            members: vec![member.to_bytes()],
            endpoint_bindings: Vec::new(),
            revoked_serials: Vec::new(),
            apps: Vec::new(),
            app_bindings: Vec::new(),
            relays: Vec::new(),
            presence_services: Vec::new(),
            epoch_secrets: EpochSecrets::from_bytes([[0x81; 32]; 4]),
            policies: NetworkPolicy::default(),
        };
        let genesis = EncryptedConfigEnvelope::seal_config(
            &root,
            &genesis_config,
            &[member_encryption.public_bytes()],
        )
        .unwrap();
        let opened_genesis = genesis
            .open_config(
                &root.public(),
                network,
                &member_encryption,
                ChainExpectation::Genesis,
                500,
            )
            .unwrap();

        let mut next_config = genesis_config;
        next_config.revision = 1;
        next_config.previous_hash = opened_genesis.head.hash;
        next_config.issued_at_ms = 101;
        let next = EncryptedConfigEnvelope::seal_next_config(
            &root.public(),
            &admin,
            &opened_genesis.config,
            opened_genesis.head,
            &next_config,
            &[member_encryption.public_bytes()],
            500,
        )
        .unwrap();
        let opened_next = next
            .open_next_config(
                &root.public(),
                &opened_genesis.config,
                &member_encryption,
                opened_genesis.head,
                500,
            )
            .unwrap();
        assert_eq!(opened_next.config.as_config(), &next_config);
        assert_eq!(opened_next.head.revision, 1);
        assert_eq!(
            next.open(
                &root.public(),
                network,
                &member_encryption,
                ChainExpectation::Next(opened_genesis.head)
            ),
            Err(ConfigError::WrongSigner)
        );
    }

    #[test]
    fn typed_config_requires_wrap_for_every_active_member_exactly_once() {
        let root = NetworkRootKey::generate().unwrap();
        let member_signing = SigningKeypair::generate().unwrap();
        let member_encryption = MemberEncryptionKeypair::generate().unwrap();
        let member = MemberCertificate::issue(
            &root,
            member_signing.public_bytes(),
            member_encryption.public_bytes(),
            MemberRoles::MEMBER,
            1,
            100,
            1_000,
        )
        .unwrap();
        let config = NetworkConfigV1 {
            network_id: root.public().network_id(),
            epoch: 0,
            revision: 0,
            previous_hash: [0; 32],
            issued_at_ms: 100,
            expires_at_ms: 900,
            admin_keys: Vec::new(),
            members: vec![member.to_bytes()],
            endpoint_bindings: Vec::new(),
            revoked_serials: Vec::new(),
            apps: Vec::new(),
            app_bindings: Vec::new(),
            relays: Vec::new(),
            presence_services: Vec::new(),
            epoch_secrets: EpochSecrets::from_bytes([[0x91; 32]; 4]),
            policies: NetworkPolicy::default(),
        };
        let unrelated = MemberEncryptionKeypair::generate().unwrap();
        assert_eq!(
            EncryptedConfigEnvelope::seal_config(&root, &config, &[unrelated.public_bytes()]),
            Err(ConfigError::RecipientSetMismatch)
        );
    }
}
