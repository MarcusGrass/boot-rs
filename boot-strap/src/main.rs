//! First of all, I want to say that I'm sorry about the name, I just couldn't help myself.
#![warn(clippy::pedantic)]

mod initramfs;

use crate::initramfs::{gen_key_file, generate_initramfs, regen_key_file};
use boot_lib::crypt::{
    derive_with_salt, encrypt, hash_and_decrypt, Argon2Config, BootDecryptError,
    REQUIRED_HASH_LENGTH, REQUIRED_IV_LENGTH,
};
use boot_lib::BootCfg;
use clap::{Parser, Subcommand};
use initramfs_lib::print_ok;
use ring::rand::SecureRandom;
use std::fmt::Write;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

/// Generate initramfs, boot options, and encrypt a kernel image.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    action: Actions,
}

#[derive(clap::Subcommand, Debug)]
enum Actions {
    Boot(GenBootOpts),

    #[command(subcommand)]
    Initramfs(InitramfsAction),
}

/// Initramfs generation
#[derive(clap::Subcommand, Debug)]
enum InitramfsAction {
    /// Generate a keyfile to be embedded in the initramfs and then used with cryptsetup.
    GenerateKey {
        /// Configuration file where salt will be written into, needs to be a properly formatted
        /// `initramfs.cfg`.
        #[clap(short, long)]
        initramfs_cfg: PathBuf,

        #[clap(flatten)]
        argon2_opts: Argon2Opts,
        /// Destination for the keyfile, ideally this should have as low permissions as possible
        /// ex: 400
        #[clap(short, long)]
        destination_file: PathBuf,
    },

    /// Regenerate a keyfile to be embedded in the initramfs and then used with cryptsetup.
    RegenerateKey {
        /// Configuration file where salt will be written into, needs to be a properly formatted
        /// `initramfs.cfg` with a provided `password_salt`.
        #[clap(short, long)]
        initramfs_cfg: PathBuf,

        #[clap(flatten)]
        argon2_opts: Argon2Opts,

        /// Destination for the keyfile, ideally this should have as low permissions as possible
        /// ex: 400
        #[clap(short, long)]
        destination_file: PathBuf,
    },

    /// Generate a clean initramfs directory
    GenerateInitramfs {
        /// Configuration file containing uuids of cryptdevices
        #[clap(short, long)]
        initramfs_cfg: PathBuf,

        /// Directory where the initramfs should be created, will wipe a previous initramfs if it exists there.
        /// Ex: /root/initramfs
        #[clap(short, long)]
        destination_directory: PathBuf,

        #[clap(flatten)]
        argon2_opts: Argon2Opts,
    },
}

/// Generate an initramfs directory
#[derive(Parser, Debug)]
struct InitramfsOpts {
    /// Configuration file containing uuids of cryptdevices
    initramfs_cfg: PathBuf,

    /// Directory where the initramfs should be created, will wipe a previous initramfs if it exists there.
    /// Ex: /root/initramfs
    out_dir: PathBuf,

    #[clap(flatten)]
    argon2_opts: Argon2Opts,
}

#[derive(Subcommand, Debug)]
enum BootAction {
    Generate(GenBootOpts),
}

/// Generate boot options and encrypt a kernel image.
#[derive(Parser, Debug, Clone)]
struct GenBootOpts {
    // Useless argument, clap breaks without it because it's buggy.
    boot: Option<String>,

    /// The kernel image path.
    /// Where the kernel image to encrypt is.
    /// If compiling locally, is usually `src-dir/arch/<arch>/boot/bzImage`.
    #[clap(long, short('i'))]
    kernel_image_path: PathBuf,

    /// Encrypted destination.
    /// Where to put the encrypted kernel image.
    #[clap(long, short('e'))]
    kernel_enc_path: PathBuf,

    /// Configuration destination.
    /// Where to put the generated configuration file.
    #[clap(long, short)]
    cfg_destination: PathBuf,

    /// Efi boot device.
    /// The efi label of the boot device.
    /// Ex: `HD(1,GPT,f0054eea-adf8-4956-958f-12e353cac4c8,0x800,0x100000)`
    #[clap(long, short('d'))]
    efi_device: String,

    /// Efi boot device kernel path.
    /// The internal path on the EFI device, where you plan to put the kernel.
    /// Likely to be the same as `kernel_enc_path`.
    /// We're not using microsoft path-specs because we're not in microsoft world just yet.
    /// Ex: `/EFI/gentoo/gentoo-6.1.19.enc`
    #[clap(long, short('p'))]
    efi_path: PathBuf,

    #[clap(flatten)]
    argon2_opts: Argon2Opts,
}

#[derive(Parser, Clone, Debug)]
struct Argon2Opts {
    /// Argon 2 mem cost.
    /// The password will be converted to a 32-byte AES key using argon2, this specifies a custom
    /// mem cost for that algorithm.
    /// If omitted, a default value will be used.
    #[clap(long, short('m'))]
    argon2_mem: Option<u32>,

    /// Argon 2 time cost.
    /// The password will be converted to a 32-byte AES key using argon2, this specifies a custom
    /// time cost for that algorithm.
    /// If omitted, a default value will be used.
    #[clap(long, short('t'))]
    argon2_time: Option<u32>,

    /// Argon 2 parallel cost.
    /// The password will be converted to a 32-byte AES key using argon2, this specifies a custom
    /// parallel cost for that algorithm.
    /// If omitted, a default value will be used.
    #[clap(long, short('l'))]
    argon2_lanes: Option<u32>,
}

impl From<Argon2Opts> for Argon2Config {
    fn from(value: Argon2Opts) -> Self {
        let mut cfg = Argon2Config::default();
        if let Some(lanes) = value.argon2_lanes {
            cfg.0.lanes = lanes;
        }
        if let Some(mem) = value.argon2_mem {
            cfg.0.mem_cost = mem;
        }
        if let Some(time) = value.argon2_time {
            cfg.0.time_cost = time;
        }
        cfg
    }
}

fn main() {
    let args = Args::parse();
    match args.action {
        Actions::Boot(boot_opts) => match generate(&boot_opts) {
            Ok(_) => {}
            Err(e) => {
                panic!("Failed to generate: {e}");
            }
        },
        Actions::Initramfs(action) => match action {
            InitramfsAction::GenerateKey {
                initramfs_cfg,
                argon2_opts,
                destination_file,
            } => {
                gen_key_file(&initramfs_cfg, &argon2_opts, &destination_file).unwrap();
            }
            InitramfsAction::RegenerateKey {
                initramfs_cfg,
                argon2_opts,
                destination_file,
            } => {
                regen_key_file(&initramfs_cfg, &argon2_opts, &destination_file).unwrap();
            }
            InitramfsAction::GenerateInitramfs {
                initramfs_cfg,
                destination_directory,
                argon2_opts,
            } => {
                generate_initramfs(&initramfs_cfg, &argon2_opts, &destination_directory).unwrap();
            }
        },
    }
}

fn generate(opts: &GenBootOpts) -> Result<(), String> {
    let gen_opts = GenBootOpts::parse();
    let kernel_data = std::fs::read(&gen_opts.kernel_image_path).map_err(|e| {
        format!(
            "Failed to read kernel image at supplied path {:?}: {e}",
            gen_opts.kernel_image_path
        )
    })?;
    print_ok!("Read kernel image at {:?}", gen_opts.kernel_image_path);
    let efi_path = get_efi_path_string(&opts.efi_path)
        .map_err(|e| format!("Failed to convert supplied efi path: {e}"))?;
    let (iv, salt) =
        generate_crypt_randoms().map_err(|e| format!("Failed to generate random vectors: {e}"))?;
    let pass = prompt_passwords().map_err(|e| format!("Failed to get password: {e}"))?;
    let argon2_cfg = opts.argon2_opts.clone().into();
    println!("[boot-rs]: Deriving encryption key.");
    let (key, derive_key_time) = timed(|| derive_with_salt(pass.as_bytes(), salt, &argon2_cfg))?;
    let key = key.map_err(|e| format!("Failed to derive a key from the password: {e}"))?;
    println!("[boot-rs]: Derived encryption key in {derive_key_time} seconds.");
    println!("[boot-rs]: Encrypting kernel image.");
    let (encrypted, encrypt_time) = timed(|| encrypt(&kernel_data, &key.key, iv))?;
    println!("[boot-rs]: Encrypted kernel image in {encrypt_time} seconds.");
    // Insanity check.
    let encrypted = encrypted?;
    if encrypted == kernel_data {
        return Err(
            "Encryption failed, output data same as input data (Sanity check triggered)."
                .to_string(),
        );
    }
    let mut enc_c = encrypted.clone();
    println!("[boot-rs]: Starting a test decryption.");
    let (decrypted, decryption_time) = timed(|| {
        match hash_and_decrypt(&mut enc_c, pass.as_bytes(), salt, iv, &argon2_cfg) {
            Ok(dec) => Ok(dec),
            Err(e) => {
                match e {
                    BootDecryptError::InvalidContent => {
                        Err("Failed to decrypt encrypted boot image (better here than at boot time), failed to find magic in decrypted bytes".to_string())
                    }
                    BootDecryptError::Other(o) => {
                        Err(format!("Failed to decrypt encrypted boot image: {o}"))
                    }
                }
            }
        }
    })?;
    let decrypted = decrypted?;
    if decrypted != kernel_data.as_slice() {
        return Err("Failed to decrypt kernel image, input is not the same as output".to_string());
    }
    println!("[boot-rs]: Successfully ran test-decryption in {decryption_time} seconds");
    let cfg = BootCfg {
        device: &opts.efi_device,
        encrypted_path_on_device: &efi_path,
        aes_initialization_vector: iv,
        argon2_salt: salt,
        argon2_mem_cost: argon2_cfg.0.mem_cost,
        argon2_time_cost: argon2_cfg.0.time_cost,
        argon2_lanes: argon2_cfg.0.lanes,
    };
    let cfg_out = cfg.serialize();
    println!(
        "[boot-rs]: Writing encrypted kernel to {:?}",
        opts.kernel_enc_path
    );
    std::fs::write(&opts.kernel_enc_path, encrypted).map_err(|e| {
        format!(
            "Failed to write encrypted kernel to out path {:?}: {e}",
            opts.kernel_enc_path
        )
    })?;
    println!(
        "[boot-rs]: Writing configuration to {:?}",
        opts.cfg_destination
    );
    std::fs::write(&opts.cfg_destination, cfg_out).map_err(|e| {
        format!(
            "Failed to write cfg to out path {:?}: {e}",
            opts.cfg_destination
        )
    })?;
    println!("[boot-rs]: Success!");
    Ok(())
}

#[inline]
fn generate_crypt_randoms() -> Result<([u8; REQUIRED_IV_LENGTH], [u8; REQUIRED_HASH_LENGTH]), String>
{
    let mut iv: [u8; REQUIRED_IV_LENGTH] = [0u8; REQUIRED_IV_LENGTH];
    let rand = ring::rand::SystemRandom::new();
    rand.fill(iv.as_mut_slice())
        .map_err(|e| format!("Failed to generate a random initialization vector: {e}"))?;
    let mut salt: [u8; REQUIRED_HASH_LENGTH] = [0u8; REQUIRED_HASH_LENGTH];
    rand.fill(salt.as_mut_slice())
        .map_err(|e| format!("Failed to generate a random salt: {e}"))?;
    Ok((iv, salt))
}

#[inline]
fn prompt_passwords() -> Result<String, String> {
    let pass = rpassword::prompt_password("Enter the encryption password: ")
        .map_err(|e| format!("Failed to get the decryption password from stdin: {e}"))?;
    let pass2 = rpassword::prompt_password("Enter password again: ")
        .map_err(|e| format!("Failed to get decryption password repetition from stdin: {e}"))?;
    if pass2 != pass {
        return Err("Password mismatch!".to_string());
    }
    Ok(pass)
}

#[inline]
fn timed<R, F: FnOnce() -> R>(func: F) -> Result<(R, f32), String> {
    let now = SystemTime::now();
    let res = (func)();
    let elapsed = now.elapsed().map_err(|e| {
        format!(
            "Failed to get elapsed time, system misconfiguration, or we're in a time vortex: {e}"
        )
    })?;
    Ok((res, elapsed.as_secs_f32()))
}

#[inline]
fn get_efi_path_string(input_path: &Path) -> Result<String, String> {
    let mut path = "\\".to_string();
    let orig_len = path.len();
    for component in input_path.components() {
        match component {
            Component::RootDir => {
                continue;
            }
            Component::Normal(component) => {
                let utf8 = component.to_str()
                    .ok_or_else(|| format!("Failed to convert a path component {component:?} of the `efi_path` {input_path:?} to utf8."))?;
                path.write_fmt(format_args!("{utf8}\\"))
                    .map_err(|e| format!("Failed to append to string, should never happen: {e}"))?;
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(format!(
                    "Got bad path component {component:?} in efi_path {input_path:?}"
                ));
            }
        }
    }
    if path.len() > orig_len {
        path = path.trim_end_matches('\\').to_string();
    }
    Ok(path)
}
