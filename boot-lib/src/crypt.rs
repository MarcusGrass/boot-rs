use crate::BootCfg;
use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{AeadInPlace, Aes256Gcm, Nonce};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use argon2::{Algorithm, Params, Version};

pub const REQUIRED_HASH_LENGTH: usize = 32;
pub const REQUIRED_IV_LENGTH: usize = 12;
pub const MAGIC: [u8; 16] = *b"DECRYPTED_KERNEL";

pub struct Argon2Cfg {
    pub lanes: u32,
    pub mem_cost: u32,
    pub time_cost: u32,
}

pub const DEFAULT_CONFIG: Argon2Cfg = Argon2Cfg {
    lanes: 4,
    mem_cost: 65536,
    time_cost: 10,
};

pub struct Argon2Config(pub Argon2Cfg);

impl Default for Argon2Config {
    fn default() -> Self {
        Self(DEFAULT_CONFIG)
    }
}

impl Argon2Config {
    #[must_use]
    pub const fn custom(lanes: u32, mem_cost: u32, time_cost: u32) -> Self {
        let mut custom_base = DEFAULT_CONFIG;
        custom_base.lanes = lanes;
        custom_base.mem_cost = mem_cost;
        custom_base.time_cost = time_cost;
        Self(custom_base)
    }
}

impl<'a> From<&BootCfg<'a>> for Argon2Config {
    #[inline]
    fn from(value: &BootCfg<'a>) -> Self {
        Self(Argon2Cfg {
            lanes: value.argon2_lanes,
            mem_cost: value.argon2_mem_cost,
            time_cost: value.argon2_time_cost,
        })
    }
}

pub struct DerivedKey {
    pub key: [u8; REQUIRED_HASH_LENGTH],
    pub salt: [u8; REQUIRED_HASH_LENGTH],
}

/// Derive a key with the provided salt.
/// # Errors
/// Hashing failure.
pub fn derive_with_salt(
    pass: &[u8],
    salt: [u8; REQUIRED_HASH_LENGTH],
    config: &Argon2Config,
) -> Result<DerivedKey, String> {
    let mut key = [0u8; 32];
    argon2::Argon2::new(
        Algorithm::Argon2i,
        Version::V0x13,
        Params::new(
            config.0.mem_cost,
            config.0.time_cost,
            config.0.lanes,
            Some(REQUIRED_HASH_LENGTH),
        )
        .map_err(|e| format!("ERROR: Failed to instantiate argon2 parameters: {e}"))?,
    )
    .hash_password_into(pass, &salt, &mut key)
    .map_err(|e| format!("ERROR: Failed to hash password: {e}"))?;
    Ok(DerivedKey { key, salt })
}

/// Encrypts some input with AES-GCM.
/// # Errors
/// Invalid key or invalid cipher.
pub fn encrypt(
    src: &[u8],
    key: &[u8; REQUIRED_HASH_LENGTH],
    iv: [u8; REQUIRED_IV_LENGTH],
) -> Result<Vec<u8>, String> {
    let key: &GenericArray<u8, U32> = GenericArray::from_slice(key);
    let nonce = Nonce::from_slice(&iv);

    let payload = Payload::from(src);
    let encrypted = Aes256Gcm::new(key)
        .encrypt(nonce, payload)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    Ok(encrypted)
}

/// Same as `hash_and_decrypt_boot` arguments supplied differently.
/// # Errors
/// See `hash_and_decrypt_boot`
pub fn hash_and_decrypt<'a>(
    src: &'a mut Vec<u8>,
    pass: &[u8],
    salt: [u8; REQUIRED_HASH_LENGTH],
    iv: [u8; REQUIRED_IV_LENGTH],
    cfg: &Argon2Config,
) -> Result<&'a [u8], BootDecryptError> {
    let key = derive_with_salt(pass, salt, cfg).map_err(|e| {
        BootDecryptError::Other(format!(
            "ERROR: Failed to hash password with provided salt: {e}"
        ))
    })?;
    decrypt(src, &key.key, iv)
}

#[derive(Debug, Eq, PartialEq)]
pub enum BootDecryptError {
    /// Failed to decrypt into expected content.
    /// It could also be because of tampering or corruption.
    InvalidContent,
    /// Some error during the process of data conversion, would likely not be caused by the wrong
    /// key.
    Other(String),
}

/// Hashes the password according to the setting specified in `cfg`,
/// then attempts to decrypt the provided bytes.
/// # Errors
/// Key derivation failure.
/// Bad magic at the beginning of the decrypted content, likely caused by entering the wrong `pass`.
pub fn hash_and_decrypt_boot_cfg<'a>(
    src: &'a mut Vec<u8>,
    pass: &[u8],
    cfg: &BootCfg,
) -> Result<&'a [u8], BootDecryptError> {
    let argon2_cfg = Argon2Config(Argon2Cfg {
        lanes: cfg.argon2_lanes,
        mem_cost: cfg.argon2_mem_cost,
        time_cost: cfg.argon2_time_cost,
    });
    let key = derive_with_salt(pass, cfg.argon2_salt, &argon2_cfg).map_err(|e| {
        BootDecryptError::Other(format!(
            "ERROR: Failed to hash password with provided salt: {e}"
        ))
    })?;
    decrypt(src, &key.key, cfg.aes_initialization_vector)
}

fn decrypt<'a>(
    src: &'a mut Vec<u8>,
    key: &[u8; REQUIRED_HASH_LENGTH],
    iv: [u8; REQUIRED_IV_LENGTH],
) -> Result<&'a [u8], BootDecryptError> {
    let key: &GenericArray<u8, U32> = GenericArray::from_slice(key);
    let nonce = Nonce::from_slice(&iv);
    Aes256Gcm::new(key)
        .decrypt_in_place(nonce, &[], src)
        .map_err(|_e| BootDecryptError::InvalidContent)?;
    Ok(src)
}

#[cfg(test)]
mod tests {
    use crate::crypt::{
        decrypt, encrypt, REQUIRED_HASH_LENGTH, REQUIRED_IV_LENGTH,
    };

    #[test]
    fn encrypt_decrypt() {
        let key = [0u8; REQUIRED_HASH_LENGTH];
        let iv = [0u8; REQUIRED_IV_LENGTH];
        let data = b"My spooky data";
        let mut encrypted = encrypt(data, &key, iv).unwrap();
        assert_ne!(data.as_slice(), &encrypted);
        let decrypted = decrypt(&mut encrypted, &key, iv).unwrap();
        assert_eq!(data.as_slice(), decrypted);
    }

    #[test]
    fn encrypt_decrypt_bad_key() {
        let key = [0u8; REQUIRED_HASH_LENGTH];
        let iv = [0u8; REQUIRED_IV_LENGTH];
        let data = b"My spooky data";
        let mut encrypted = encrypt(data, &key, iv).unwrap();
        assert_ne!(data.as_slice(), &encrypted);
        let decrypted = decrypt(&mut encrypted, &key, iv).unwrap();
        assert_eq!(data.as_slice(), decrypted);
        let bad_key = [1u8; REQUIRED_HASH_LENGTH];
        let iv = [0u8; REQUIRED_IV_LENGTH];
        let mut encrypted = encrypt(data, &key, iv).unwrap();
        assert_ne!(data.as_slice(), &encrypted);

        let decrypted = decrypt(&mut encrypted, &bad_key, iv);
        assert!(decrypted.is_err());
    }
}
