use crate::BootCfg;
use aes::cipher::typenum::U32;
use aes::cipher::KeyIvInit;
use aes::cipher::{generic_array::GenericArray, AsyncStreamCipher};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use argon2::{Algorithm, Params, Version};

type Aes256Cfb8Enc = cfb8::Encryptor<aes::Aes256>;
type Aes256Cfb8Dec = cfb8::Decryptor<aes::Aes256>;

pub const REQUIRED_HASH_LENGTH: usize = 32;
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
    salt: [u8; 32],
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

/// Encrypts the boot image adding the 16 byte magic header.
/// This header add is wildly inefficient since we need to duplicate the entire vector.
/// We could realloc and push to front but that is also problematic, this shouldn't
/// be run in the bootloader anyway but I'm sorry about the RAM.
#[must_use]
pub fn encrypt_boot_image(src: &[u8], key: &[u8], iv: [u8; 16]) -> Vec<u8> {
    let mut new = Vec::with_capacity(src.len() + MAGIC.len());
    new.extend_from_slice(&MAGIC);
    new.extend_from_slice(src);
    encrypt(new, key, iv)
}

fn encrypt(mut src: Vec<u8>, key: &[u8], iv: [u8; 16]) -> Vec<u8> {
    let key: &GenericArray<u8, U32> = GenericArray::from_slice(key);
    //let cipher = aes::Aes128::new(key);
    Aes256Cfb8Enc::new(key, &iv.into()).encrypt(&mut src);
    src
}

/// Same as `hash_and_decrypt_boot` arguments supplied differently.
/// # Errors
/// See `hash_and_decrypt_boot`
pub fn hash_and_decrypt<'a>(
    src: &'a mut [u8],
    pass: &[u8],
    salt: [u8; 32],
    iv: [u8; 16],
    cfg: &Argon2Config,
) -> Result<&'a [u8], BootDecryptError> {
    let key = derive_with_salt(pass, salt, cfg).map_err(|e| {
        BootDecryptError::Other(format!(
            "ERROR: Failed to hash password with provided salt: {e}"
        ))
    })?;
    decrypt_boot_image(src, &key.key, iv)
}

#[derive(Debug, Eq, PartialEq)]
pub enum BootDecryptError {
    /// Failed to find the expected magic, which is likely because we tried to decrypt
    /// with the wrong key.
    BadMagic,
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
    src: &'a mut [u8],
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
    decrypt_boot_image(src, &key.key, cfg.aes_initialization_vector)
}

fn decrypt_boot_image<'a>(
    src: &'a mut [u8],
    key: &[u8],
    iv: [u8; 16],
) -> Result<&'a [u8], BootDecryptError> {
    let decrypted = decrypt(src, key, iv);
    if decrypted[..MAGIC.len()] != MAGIC {
        return Err(BootDecryptError::BadMagic);
    }
    Ok(&decrypted[MAGIC.len()..])
}

fn decrypt<'a>(src: &'a mut [u8], key: &[u8], iv: [u8; 16]) -> &'a [u8] {
    let key: &GenericArray<u8, U32> = GenericArray::from_slice(key);
    Aes256Cfb8Dec::new(key, &iv.into()).decrypt(src);
    src
}

#[cfg(test)]
mod tests {
    use crate::crypt::{
        decrypt, decrypt_boot_image, encrypt, encrypt_boot_image, BootDecryptError,
    };

    #[test]
    fn encrypt_decrypt() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let data = b"My spooky data";
        let mut encrypted = encrypt(data.to_vec(), &key, iv);
        assert_ne!(data.as_slice(), &encrypted);
        let decrypted = decrypt(&mut encrypted, &key, iv);
        assert_eq!(data.as_slice(), decrypted);
    }

    #[test]
    fn encrypt_decrypt_bad_key() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let data = b"My spooky data";
        let mut encrypted = encrypt(data.to_vec(), &key, iv);
        assert_ne!(data.as_slice(), &encrypted);
        let decrypted = decrypt(&mut encrypted, &key, iv);
        assert_eq!(data.as_slice(), decrypted);
        let bad_key = [1u8; 32];
        let iv = [0u8; 16];
        let mut encrypted = encrypt(data.to_vec(), &key, iv);
        assert_ne!(data.as_slice(), &encrypted);
        let decrypted = decrypt(&mut encrypted, &bad_key, iv);
        assert_ne!(data.as_slice(), decrypted);
    }

    #[test]
    fn encrypt_decrypt_boot() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let data = b"My spooky boot data";
        let mut encrypted = encrypt_boot_image(data.as_slice(), &key, iv);
        assert_ne!(data.as_slice(), &encrypted);
        let decrypted = decrypt_boot_image(&mut encrypted, &key, iv).unwrap();
        assert_eq!(data.as_slice(), decrypted);
    }

    #[test]
    fn encrypt_decrypt_boot_fail_bad_key() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let data = b"My spooky boot data";
        let mut encrypted = encrypt_boot_image(data.as_slice(), &key, iv);
        assert_ne!(data.as_slice(), &encrypted);
        let decrypted = decrypt_boot_image(&mut encrypted, &key, iv).unwrap();
        assert_eq!(data.as_slice(), decrypted);
        let bad_key = [1u8; 32];
        let iv = [0u8; 16];
        let mut encrypted = encrypt_boot_image(data.as_slice(), &key, iv);
        assert_ne!(data.as_slice(), &encrypted);
        if let Err(e) = decrypt_boot_image(&mut encrypted, &bad_key, iv) {
            assert_eq!(BootDecryptError::BadMagic, e);
        } else {
            panic!("Successfully decrypted image with a bad key!");
        }
    }
}
