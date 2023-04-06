use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use argon2::{Algorithm, Params, Version};

pub const REQUIRED_HASH_LENGTH: usize = 32;
pub const REQUIRED_NONCE_LENGTH: usize = 12;
pub const ARGON2_CFG_LENGTH: usize = 12;
pub const METADATA_LENGTH: usize = REQUIRED_NONCE_LENGTH + REQUIRED_HASH_LENGTH + ARGON2_CFG_LENGTH;
pub const AES_GCM_TAG_LENGTH: usize = 16;
pub const MAGIC: [u8; 16] = *b"DECRYPTED_KERNEL";

#[cfg_attr(test, derive(Eq, PartialEq, Debug))]
pub struct Argon2Cfg {
    pub lanes: u32,
    pub mem_cost: u32,
    pub time_cost: u32,
}

impl Argon2Cfg {
    fn serialize(&self) -> [u8; ARGON2_CFG_LENGTH] {
        let mut serialized = [0u8; ARGON2_CFG_LENGTH];
        serialized[0..4].copy_from_slice(&self.lanes.to_le_bytes());
        serialized[4..8].copy_from_slice(&self.mem_cost.to_le_bytes());
        serialized[8..12].copy_from_slice(&self.time_cost.to_le_bytes());
        serialized
    }

    fn deserialize(bytes: &[u8; ARGON2_CFG_LENGTH]) -> Self {
        Self {
            lanes: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            mem_cost: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            time_cost: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        }
    }
}

pub const DEFAULT_CONFIG: Argon2Cfg = Argon2Cfg {
    lanes: 4,
    mem_cost: 65536,
    time_cost: 10,
};

pub struct AesKey(pub [u8; REQUIRED_HASH_LENGTH]);

#[cfg_attr(test, derive(Eq, PartialEq, Debug))]
pub struct Argon2Salt(pub [u8; REQUIRED_HASH_LENGTH]);

#[cfg_attr(test, derive(Eq, PartialEq, Debug))]
pub struct AesGcmNonce(pub [u8; REQUIRED_NONCE_LENGTH]);

/// Derive a key with the provided salt.
/// # Errors
/// Hashing failure.
pub fn derive_key(
    pass: &[u8],
    salt: &Argon2Salt,
    argon2_cfg: &Argon2Cfg,
) -> Result<AesKey, String> {
    let mut key = [0u8; REQUIRED_HASH_LENGTH];
    argon2::Argon2::new(
        Algorithm::Argon2i,
        Version::V0x13,
        Params::new(
            argon2_cfg.mem_cost,
            argon2_cfg.time_cost,
            argon2_cfg.lanes,
            Some(REQUIRED_HASH_LENGTH),
        )
        .map_err(|e| format!("ERROR: Failed to instantiate argon2 parameters: {e}"))?,
    )
    .hash_password_into(pass, &salt.0, &mut key)
    .map_err(|e| format!("ERROR: Failed to hash password: {e}"))?;
    Ok(AesKey(key))
}

#[cfg_attr(test, derive(Eq, PartialEq, Debug))]
pub struct EncryptionMetadata {
    nonce: AesGcmNonce,
    salt: Argon2Salt,
    argon2_cfg: Argon2Cfg,
}

impl EncryptionMetadata {
    #[must_use]
    pub fn new(
        nonce: [u8; REQUIRED_NONCE_LENGTH],
        salt: [u8; REQUIRED_HASH_LENGTH],
        argon2_cfg: Argon2Cfg,
    ) -> Self {
        Self {
            nonce: AesGcmNonce(nonce),
            salt: Argon2Salt(salt),
            argon2_cfg,
        }
    }

    #[must_use]
    pub fn serialize(&self) -> [u8; METADATA_LENGTH] {
        let mut metadata = [0u8; METADATA_LENGTH];
        metadata[0..REQUIRED_NONCE_LENGTH].copy_from_slice(&self.nonce.0);
        metadata[REQUIRED_NONCE_LENGTH..REQUIRED_NONCE_LENGTH + REQUIRED_HASH_LENGTH]
            .copy_from_slice(&self.salt.0);
        metadata[REQUIRED_NONCE_LENGTH + REQUIRED_HASH_LENGTH
            ..REQUIRED_NONCE_LENGTH + REQUIRED_HASH_LENGTH + ARGON2_CFG_LENGTH]
            .copy_from_slice(&self.argon2_cfg.serialize());
        metadata
    }

    /// # Panics
    /// If the array bounds are manually written to be off
    #[must_use]
    pub fn deserialize(bytes: &[u8; METADATA_LENGTH]) -> Self {
        let nonce: [u8; REQUIRED_NONCE_LENGTH] =
            bytes[0..REQUIRED_NONCE_LENGTH].try_into().unwrap();
        let salt: [u8; REQUIRED_HASH_LENGTH] = bytes
            [REQUIRED_NONCE_LENGTH..REQUIRED_NONCE_LENGTH + REQUIRED_HASH_LENGTH]
            .try_into()
            .unwrap();
        let argon2_cfg = Argon2Cfg::deserialize(
            &bytes[REQUIRED_NONCE_LENGTH + REQUIRED_HASH_LENGTH
                ..REQUIRED_NONCE_LENGTH + REQUIRED_HASH_LENGTH + ARGON2_CFG_LENGTH]
                .try_into()
                .unwrap(),
        );
        Self {
            nonce: AesGcmNonce(nonce),
            salt: Argon2Salt(salt),
            argon2_cfg,
        }
    }

    #[inline]
    #[must_use]
    pub fn nonce(&self) -> &AesGcmNonce {
        &self.nonce
    }

    #[inline]
    #[must_use]
    pub fn salt(&self) -> &Argon2Salt {
        &self.salt
    }

    #[inline]
    #[must_use]
    pub fn argon2_cfg(&self) -> &Argon2Cfg {
        &self.argon2_cfg
    }
}

/// Encrypts some input with AES-GCM.
/// # Errors
/// Invalid key or invalid cipher.
pub fn encrypt(src: &[u8], key: &AesKey, metadata: &EncryptionMetadata) -> Result<Vec<u8>, String> {
    let key: &GenericArray<u8, U32> = GenericArray::from_slice(&key.0);
    let nonce = Nonce::from_slice(&metadata.nonce.0);

    let mut enc = Vec::with_capacity(src.len() + AES_GCM_TAG_LENGTH + METADATA_LENGTH);
    enc.extend_from_slice(&metadata.serialize());

    let output = Aes256Gcm::new(key)
        .encrypt(nonce, Payload::from(src))
        .map_err(|e| format!("Encryption failed: {e}"))?;
    enc.extend(output);
    Ok(enc)
}

/// Same as `hash_and_decrypt_boot` arguments supplied differently.
/// # Errors
/// See `hash_and_decrypt_boot`
/// # Panics
/// If the manual array bounds are off
pub fn hash_and_decrypt(src: &[u8], pass: &[u8]) -> Result<Vec<u8>, BootDecryptError> {
    let metadata_bytes: &[u8; METADATA_LENGTH] = src
        .get(..METADATA_LENGTH)
        .ok_or_else(|| {
            BootDecryptError::Other("Bad payload, length doesn't even fit metadata".to_string())
        })?
        .try_into()
        .unwrap();
    let metadata = EncryptionMetadata::deserialize(metadata_bytes);
    let key = derive_key(pass, &metadata.salt, &metadata.argon2_cfg).map_err(|e| {
        BootDecryptError::Other(format!(
            "ERROR: Failed to hash password with provided salt: {e}"
        ))
    })?;
    decrypt(src, &key, &metadata.nonce)
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

fn decrypt(src: &[u8], key: &AesKey, iv: &AesGcmNonce) -> Result<Vec<u8>, BootDecryptError> {
    let key: &GenericArray<u8, U32> = GenericArray::from_slice(&key.0);
    let nonce = Nonce::from_slice(&iv.0);
    let decrypted = Aes256Gcm::new(key)
        .decrypt(nonce, &src[METADATA_LENGTH..])
        .map_err(|_e| BootDecryptError::InvalidContent)?;
    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use crate::crypt::{
        decrypt, derive_key, encrypt, hash_and_decrypt, Argon2Cfg, EncryptionMetadata,
        DEFAULT_CONFIG, REQUIRED_HASH_LENGTH, REQUIRED_NONCE_LENGTH,
    };

    #[test]
    fn metadata_serialize_deserialize() {
        let enc = EncryptionMetadata::new(
            [5u8; REQUIRED_NONCE_LENGTH],
            [7u8; REQUIRED_HASH_LENGTH],
            DEFAULT_CONFIG,
        );
        let ser = enc.serialize();
        let de = EncryptionMetadata::deserialize(&ser);
        assert_eq!(enc, de);
    }

    /// Just something that doesn't force us to run tests with `--release`
    const LOW_COMPUTE_CFG: Argon2Cfg = Argon2Cfg {
        lanes: 1,
        mem_cost: 8,
        time_cost: 1,
    };

    #[test]
    fn encrypt_decrypt() {
        let pass = [0, 1, 2, 3];
        let nonce = [0u8; REQUIRED_NONCE_LENGTH];
        let salt = [0u8; REQUIRED_HASH_LENGTH];
        let metadata = EncryptionMetadata::new(nonce, salt, LOW_COMPUTE_CFG);
        let key = derive_key(&pass, &metadata.salt, &metadata.argon2_cfg).unwrap();
        let data = b"My spooky data";
        let mut encrypted = encrypt(data, &key, &metadata).unwrap();
        assert_ne!(data.as_slice(), &encrypted);
        let decrypted = hash_and_decrypt(&mut encrypted, &pass).unwrap();
        assert_eq!(data.as_slice(), decrypted);
    }

    #[test]
    fn encrypt_decrypt_bad_key() {
        let pass = [9u8, 5, 3, 4];
        let iv = [0u8; REQUIRED_NONCE_LENGTH];
        let salt = [0u8; REQUIRED_HASH_LENGTH];
        let metadata = EncryptionMetadata::new(iv, salt, LOW_COMPUTE_CFG);
        let key = derive_key(&pass, &metadata.salt, &metadata.argon2_cfg).unwrap();
        let data = b"My spooky data";
        let mut encrypted = encrypt(data, &key, &metadata).unwrap();
        assert_ne!(data.as_slice(), &encrypted);
        let decrypted = hash_and_decrypt(&mut encrypted, &pass).unwrap();
        assert_eq!(data.as_slice(), decrypted);
        let bad_pass = [1u8, 2, 3, 4];
        let mut encrypted = encrypt(data, &key, &metadata).unwrap();
        assert_ne!(data.as_slice(), &encrypted);
        let derived_bad = derive_key(&bad_pass, &metadata.salt, &metadata.argon2_cfg).unwrap();
        let decrypted = decrypt(&mut encrypted, &derived_bad, &metadata.nonce);
        assert!(decrypted.is_err());
    }
}
