pub mod proto {
    tonic::include_proto!("weaver.demo");
}

use std::{fs, io, path::Path};

use iroh::SecretKey;

pub const DEMO_APP_ADDR: weaver_core::AppAddr = weaver_core::AppAddr::from_bytes([0xa1; 32]);
pub const DEMO_NETWORK_ID: weaver_core::NetworkId = weaver_core::NetworkId::from_bytes([0x91; 32]);
pub const DEMO_CLIENT_APP_ADDR: weaver_core::AppAddr = weaver_core::AppAddr::from_bytes([0xc1; 32]);
pub const DEMO_CLIENT_DEVICE_ID: weaver_core::DeviceId =
    weaver_core::DeviceId::from_bytes([0xd1; 32]);
pub const DEMO_CLIENT_ADDR: weaver_core::ScopedVirtualAddr =
    weaver_core::ScopedVirtualAddr::Client {
        app: DEMO_CLIENT_APP_ADDR,
        device: DEMO_CLIENT_DEVICE_ID,
    };

/// Development-only plaintext identity persistence.
///
/// Production nodes will use Weaver's `SecretStore`; keeping this helper in the demo crate makes
/// it impossible to accidentally use it from the network library.
pub fn load_or_create_dev_identity(path: &Path) -> io::Result<SecretKey> {
    match fs::read_to_string(path) {
        Ok(encoded) => {
            let bytes = hex::decode(encoded.trim())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "identity must contain 32 bytes")
            })?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let key = SecretKey::generate();
            let encoded = hex::encode(key.to_bytes());
            write_private_file(path, encoded.as_bytes())?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    fs::write(path, contents)
}
