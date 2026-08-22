use std::{
    fmt,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::{SecretBytes, SecretId, SecretProtection, SecretStore, SecretStoreError};

const FILE_MAGIC: &[u8; 8] = b"WVRSEC\0\x01";
const NONCE_LEN: usize = 12;

/// Durable secret storage encrypted with an externally supplied 256-bit master key.
///
/// The master key is never written into `directory`. Production callers must obtain it
/// from a system key store, restricted file descriptor, KMS/HSM provider or interactive
/// unlock flow. This backend intentionally does not accept a passphrase or silently write
/// a plaintext key next to the ciphertext.
#[derive(Clone)]
pub struct EncryptedFileSecretStore {
    directory: Arc<PathBuf>,
    master_key: Arc<Zeroizing<[u8; 32]>>,
}

impl EncryptedFileSecretStore {
    pub fn open(
        directory: impl AsRef<Path>,
        master_key: [u8; 32],
    ) -> Result<Self, SecretStoreError> {
        std::fs::create_dir_all(directory.as_ref()).map_err(backend)?;
        Ok(Self {
            directory: Arc::new(directory.as_ref().to_path_buf()),
            master_key: Arc::new(Zeroizing::new(master_key)),
        })
    }

    fn path_for(&self, id: &SecretId) -> PathBuf {
        self.directory
            .join(format!("{}.wvs", hex::encode(id.as_bytes())))
    }
}

impl fmt::Debug for EncryptedFileSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedFileSecretStore")
            .field("directory", &self.directory)
            .field("master_key", &"[redacted]")
            .finish()
    }
}

#[async_trait]
impl SecretStore for EncryptedFileSecretStore {
    fn protection(&self) -> SecretProtection {
        SecretProtection::ExternalKeyEncrypted
    }

    async fn seal(&self, id: SecretId, plaintext: SecretBytes) -> Result<(), SecretStoreError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.seal_sync(id, plaintext))
            .await
            .map_err(join_error)?
    }

    async fn open(&self, id: &SecretId) -> Result<SecretBytes, SecretStoreError> {
        let store = self.clone();
        let id = id.clone();
        tokio::task::spawn_blocking(move || store.open_sync(&id))
            .await
            .map_err(join_error)?
    }

    async fn delete(&self, id: &SecretId) -> Result<(), SecretStoreError> {
        let store = self.clone();
        let id = id.clone();
        tokio::task::spawn_blocking(move || store.delete_sync(&id))
            .await
            .map_err(join_error)?
    }
}

impl EncryptedFileSecretStore {
    fn seal_sync(&self, id: SecretId, plaintext: SecretBytes) -> Result<(), SecretStoreError> {
        let final_path = self.path_for(&id);
        if final_path.exists() {
            return self.compare_existing(&id, plaintext.expose());
        }

        let mut nonce = [0; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(backend)?;
        let cipher = Aes256Gcm::new_from_slice(self.master_key.as_ref().as_slice())
            .map_err(|_| SecretStoreError::Backend("invalid master key length".into()))?;
        let aad = associated_data(&id);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.expose(),
                    aad: &aad,
                },
            )
            .map_err(|_| SecretStoreError::AuthenticationFailed)?;

        let mut random_suffix = [0; 16];
        getrandom::fill(&mut random_suffix).map_err(backend)?;
        let temp_path = self
            .directory
            .join(format!(".secret-{}.tmp", hex::encode(random_suffix)));
        let write_result = (|| {
            let mut file = create_private_file(&temp_path)?;
            file.write_all(FILE_MAGIC).map_err(backend)?;
            file.write_all(&nonce).map_err(backend)?;
            file.write_all(&ciphertext).map_err(backend)?;
            file.sync_all().map_err(backend)?;
            match std::fs::hard_link(&temp_path, &final_path) {
                Ok(()) => {
                    sync_directory(&self.directory)?;
                    Ok(())
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.compare_existing(&id, plaintext.expose())
                }
                Err(error) => Err(backend(error)),
            }
        })();
        let _ = std::fs::remove_file(temp_path);
        write_result
    }

    fn compare_existing(&self, id: &SecretId, plaintext: &[u8]) -> Result<(), SecretStoreError> {
        let existing = self.open_sync(id)?;
        if existing.expose() == plaintext {
            Ok(())
        } else {
            Err(SecretStoreError::AlreadyExistsDifferent)
        }
    }

    fn open_sync(&self, id: &SecretId) -> Result<SecretBytes, SecretStoreError> {
        let bytes = match std::fs::read(self.path_for(id)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(SecretStoreError::NotFound);
            }
            Err(error) => return Err(backend(error)),
        };
        if bytes.len() < FILE_MAGIC.len() + NONCE_LEN + 16
            || &bytes[..FILE_MAGIC.len()] != FILE_MAGIC
        {
            return Err(SecretStoreError::AuthenticationFailed);
        }
        let nonce_offset = FILE_MAGIC.len();
        let ciphertext_offset = nonce_offset + NONCE_LEN;
        let cipher = Aes256Gcm::new_from_slice(self.master_key.as_ref().as_slice())
            .map_err(|_| SecretStoreError::Backend("invalid master key length".into()))?;
        let aad = associated_data(id);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&bytes[nonce_offset..ciphertext_offset]),
                Payload {
                    msg: &bytes[ciphertext_offset..],
                    aad: &aad,
                },
            )
            .map_err(|_| SecretStoreError::AuthenticationFailed)?;
        Ok(SecretBytes::new(plaintext))
    }

    fn delete_sync(&self, id: &SecretId) -> Result<(), SecretStoreError> {
        match std::fs::remove_file(self.path_for(id)) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(backend(error)),
        }
    }
}

fn associated_data(id: &SecretId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FILE_MAGIC.len() + 32);
    aad.extend_from_slice(FILE_MAGIC);
    aad.extend_from_slice(id.as_bytes());
    aad
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<File, SecretStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(backend)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<File, SecretStoreError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(backend)
}

fn sync_directory(path: &Path) -> Result<(), SecretStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(backend)
}

fn backend(error: impl std::fmt::Display) -> SecretStoreError {
    SecretStoreError::Backend(error.to_string())
}

fn join_error(error: tokio::task::JoinError) -> SecretStoreError {
    SecretStoreError::Backend(format!("secret store worker failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn encrypted_secret_survives_reopen_without_plaintext_on_disk() {
        let directory = tempfile::tempdir().unwrap();
        let id = SecretId::from_bytes([0x31; 32]);
        let master = [0x42; 32];
        let store = EncryptedFileSecretStore::open(directory.path(), master).unwrap();
        store
            .seal(
                id.clone(),
                SecretBytes::new(b"private-key-material".to_vec()),
            )
            .await
            .unwrap();
        let disk = std::fs::read(store.path_for(&id)).unwrap();
        assert!(
            !disk
                .windows(b"private-key-material".len())
                .any(|window| window == b"private-key-material")
        );
        drop(store);

        let reopened = EncryptedFileSecretStore::open(directory.path(), master).unwrap();
        assert_eq!(
            reopened.open(&id).await.unwrap().expose(),
            b"private-key-material"
        );
        reopened
            .seal(
                id.clone(),
                SecretBytes::new(b"private-key-material".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(
            reopened
                .seal(id, SecretBytes::new(b"replacement".to_vec()))
                .await,
            Err(SecretStoreError::AlreadyExistsDifferent)
        );
    }

    #[tokio::test]
    async fn wrong_master_key_and_tampering_fail_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let id = SecretId::from_bytes([0x32; 32]);
        let store = EncryptedFileSecretStore::open(directory.path(), [1; 32]).unwrap();
        store
            .seal(id.clone(), SecretBytes::new(b"secret".to_vec()))
            .await
            .unwrap();
        let wrong = EncryptedFileSecretStore::open(directory.path(), [2; 32]).unwrap();
        assert_eq!(
            wrong.open(&id).await.unwrap_err(),
            SecretStoreError::AuthenticationFailed
        );

        let path = store.path_for(&id);
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(path, bytes).unwrap();
        assert_eq!(
            store.open(&id).await.unwrap_err(),
            SecretStoreError::AuthenticationFailed
        );
    }
}
