use crate::initramfs::{gen_cfg, generate_initramfs};
use alloc::format;
use alloc::string::{String, ToString};
use boot_lib::crypt::{
    derive_key, encrypt, hash_and_decrypt, Argon2Cfg, BootDecryptError, EncryptionMetadata,
    DEFAULT_CONFIG, REQUIRED_HASH_LENGTH, REQUIRED_NONCE_LENGTH,
};
use boot_lib::BootCfg;
use core::fmt::Write;
use initramfs_lib::{print_error, print_ok};
use rusl::string::unix_str::UnixStr;
use tiny_cli::{ArgParse, Subcommand};
use tiny_std::linux::get_pass::get_pass;
use tiny_std::println;
use tiny_std::time::SystemTime;
use tiny_std::unix::random::system_random;

/// Generate initramfs configuration
#[derive(Debug, ArgParse)]
#[cli(help_path = "boot-rs, initramfs, gen-cfg")]
struct InitramfsGenCfgOpts {
    /// UUID for the home partition
    #[cli(short = "h", long = "home-uuid")]
    home_uuid: String,
    /// UUID for the root partition
    #[cli(short = "r", long = "root-uuid")]
    root_uuid: String,
    /// UUID for the swap partition
    #[cli(short = "s", long = "swap-uuid")]
    swap_uuid: String,
    /// Overwrite the current file if present.
    ///  Probably not good, since we generate a cryptsetup key from the generated salt,
    ///  if key that has already been registered, this salt shouldn't change
    #[cli(short = "o", long = "overwrite")]
    overwrite: bool,
    /// Destination file
    #[cli(short = "d", long = "destination-file")]
    destination_file: Option<&'static UnixStr>,
}
#[derive(Debug, ArgParse)]
#[cli(help_path = "boot-rs, initramfs, gen-init")]
struct InitramfsGenInitOpts {
    /// Configuration file containing uuids of cryptdevices
    #[cli(short = "i", long = "initramfs-cfg")]
    initramfs_cfg: &'static UnixStr,
    /// Directory where the initramfs should be created, will wipe a previous initramfs if it exists there.
    /// Ex: /root/initramfs
    #[cli(short = "d", long = "destination-file")]
    destination_directory: &'static UnixStr,

    /// Argon 2 mem cost.
    /// The password will be converted to a 32-byte AES key using argon2, this specifies a custom
    /// mem cost for that algorithm.
    /// If omitted, a default value will be used.
    #[cli(short = "m", long = "argon2-mem")]
    argon2_mem: Option<u32>,

    /// Argon 2 time cost.
    /// The password will be converted to a 32-byte AES key using argon2, this specifies a custom
    /// time cost for that algorithm.
    /// If omitted, a default value will be used.
    #[cli(short = "t", long = "argon2-time")]
    argon2_time: Option<u32>,
    /// Argon 2 parallel cost.
    /// The password will be converted to a 32-byte AES key using argon2, this specifies a custom
    /// parallel cost for that algorithm.
    /// If omitted, a default value will be used.
    #[cli(short = "l", long = "argon2-lanes")]
    argon2_lanes: Option<u32>,
}

#[derive(Debug, ArgParse)]
#[cli(help_path = "boot-rs, initramfs")]
struct InitramfsOptions {
    #[cli(subcommand)]
    subcommand: InitramfsAction,
}

#[derive(Debug, Subcommand)]
enum InitramfsAction {
    GenCfg(InitramfsGenCfgOpts),
    GenInit(InitramfsGenInitOpts),
}

/// Encrypt kernel image
#[derive(Debug, ArgParse)]
#[cli(help_path = "boot-rs, boot")]
struct BootOpts {
    /// The kernel image path.
    /// Where the kernel image to encrypt is.
    /// If compiling locally, is usually `src-dir/arch/<arch>/boot/bzImage`.
    #[cli(short = "i", long = "kernel-image-path")]
    kernel_image_path: &'static UnixStr,

    /// Encrypted destination.
    /// Where to put the encrypted kernel image.
    #[cli(short = "e", long = "kernel-enc-path")]
    kernel_enc_path: &'static UnixStr,

    /// Configuration destination.
    /// Where to put the generated configuration file.
    #[cli(short = "c", long = "cfg-destination")]
    cfg_destination: &'static UnixStr,

    /// Efi boot device.
    /// The efi label of the boot device.
    /// Ex: `HD(1,GPT,f0054eea-adf8-4956-958f-12e353cac4c8,0x800,0x100000)`
    #[cli(short = "d", long = "efi-device")]
    efi_device: String,

    /// Efi boot device kernel path.
    /// The internal path on the EFI device, where you plan to put the kernel.
    /// Likely to be the same as `kernel_enc_path`.
    /// We're not using microsoft path-specs because we're not in microsoft world just yet.
    /// Ex: `/EFI/gentoo/gentoo-6.1.19.enc`
    #[cli(short = "p", long = "efi-path")]
    efi_path: &'static UnixStr,

    /// Argon 2 mem cost.
    /// The password will be converted to a 32-byte AES key using argon2, this specifies a custom
    /// mem cost for that algorithm.
    /// If omitted, a default value will be used.
    #[cli(short = "m", long = "argon2-mem")]
    argon2_mem: Option<u32>,
    /// Argon 2 time cost.
    /// The password will be converted to a 32-byte AES key using argon2, this specifies a custom
    /// time cost for that algorithm.
    /// If omitted, a default value will be used.
    #[cli(short = "t", long = "argon2-time")]
    argon2_time: Option<u32>,
    /// Argon 2 parallel cost.
    /// The password will be converted to a 32-byte AES key using argon2, this specifies a custom
    /// parallel cost for that algorithm.
    /// If omitted, a default value will be used.
    #[cli(short = "l", long = "argon2-lanes")]
    argon2_lanes: Option<u32>,
}

/// Generate boot config
#[derive(Debug, ArgParse)]
#[cli(help_path = "boot-rs")]
struct Opts {
    #[cli(subcommand)]
    subcommand: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    Initramfs(InitramfsOptions),
    Boot(BootOpts),
}

fn create_argon2opts_maybe_default(
    argon2_mem: Option<u32>,
    argon2_time: Option<u32>,
    argon2_lanes: Option<u32>,
) -> Argon2Cfg {
    let mut cfg = DEFAULT_CONFIG;
    if let Some(lanes) = argon2_lanes {
        cfg.lanes = lanes;
    }
    if let Some(mem) = argon2_mem {
        cfg.mem_cost = mem;
    }
    if let Some(time) = argon2_time {
        cfg.time_cost = time;
    }
    cfg
}

pub(crate) fn run() {
    let args = tiny_std::unix::cli::parse_cli_args::<Opts>();
    match args.subcommand {
        Action::Initramfs(initramfs) => match initramfs.subcommand {
            InitramfsAction::GenCfg(InitramfsGenCfgOpts {
                home_uuid,
                root_uuid,
                swap_uuid,
                overwrite,
                destination_file,
            }) => {
                gen_cfg(home_uuid, root_uuid, swap_uuid, destination_file, overwrite).unwrap();
            }
            InitramfsAction::GenInit(InitramfsGenInitOpts {
                initramfs_cfg,
                destination_directory,
                argon2_mem,
                argon2_time,
                argon2_lanes,
            }) => {
                let argon2_cfg =
                    create_argon2opts_maybe_default(argon2_mem, argon2_time, argon2_lanes);
                if let Err(e) =
                    generate_initramfs(&initramfs_cfg, &argon2_cfg, &destination_directory)
                {
                    print_error!("Failed to generate initramfs: {e}");
                    rusl::process::exit(1);
                }
                print_ok!("Successfully generated initramfs, don't forget to add initramfs-rs as `./init` to it.");
            }
        },
        Action::Boot(boot_opts) => match generate(&boot_opts) {
            Ok(_) => {}
            Err(e) => {
                panic!("Failed to generate: {e}");
            }
        },
    }
}

fn generate(gen_opts: &BootOpts) -> Result<(), String> {
    let kernel_data = tiny_std::fs::read(&gen_opts.kernel_image_path).map_err(|e| {
        format!(
            "Failed to read kernel image at supplied path {:?}: {e}",
            gen_opts.kernel_image_path
        )
    })?;
    print_ok!("Read kernel image at {:?}", gen_opts.kernel_image_path);
    let efi_path = get_efi_path_string(
        gen_opts
            .efi_path
            .as_str()
            .map_err(|_e| format!("Failed to convert supplied EFI path to a utf8 str"))?,
    )
    .map_err(|e| format!("Failed to convert supplied efi path: {e}"))?;
    let (nonce, salt) =
        generate_nonce_and_salt().map_err(|e| format!("Failed to generate random vectors: {e}"))?;
    let pass = prompt_passwords().map_err(|e| format!("Failed to get password: {e}"))?;
    let argon2_cfg = create_argon2opts_maybe_default(
        gen_opts.argon2_mem,
        gen_opts.argon2_time,
        gen_opts.argon2_lanes,
    );
    let metadata = EncryptionMetadata::new(nonce, salt, argon2_cfg);
    println!("[boot-rs]: Deriving encryption key.");
    let (key, derive_key_time) =
        timed(|| derive_key(pass.as_bytes(), metadata.salt(), metadata.argon2_cfg()))?;
    let key = key.map_err(|e| format!("Failed to derive a key from the password: {e}"))?;
    println!("[boot-rs]: Derived encryption key in {derive_key_time} seconds.");
    println!("[boot-rs]: Encrypting kernel image.");
    let (encrypted, encrypt_time) = timed(|| encrypt(&kernel_data, &key, &metadata))?;
    println!("[boot-rs]: Encrypted kernel image in {encrypt_time} seconds.");
    // Insanity check.
    let encrypted = encrypted?;
    if encrypted == kernel_data {
        return Err(
            "Encryption failed, output data same as input data (Sanity check triggered)."
                .to_string(),
        );
    }
    println!("[boot-rs]: Starting a test decryption.");
    let (decrypted, decryption_time) = timed(|| {
        match hash_and_decrypt(&encrypted, pass.as_bytes()) {
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
        device: &gen_opts.efi_device,
        encrypted_path_on_device: &efi_path,
    };
    let cfg_out = cfg.serialize();
    println!(
        "[boot-rs]: Writing encrypted kernel to {:?}",
        gen_opts.kernel_enc_path
    );
    tiny_std::fs::write(&gen_opts.kernel_enc_path, encrypted.as_slice()).map_err(|e| {
        format!(
            "Failed to write encrypted kernel to out path {:?}: {e}",
            gen_opts.kernel_enc_path
        )
    })?;
    println!(
        "[boot-rs]: Writing configuration to {:?}",
        gen_opts.cfg_destination
    );
    tiny_std::fs::write(&gen_opts.cfg_destination, cfg_out.as_bytes()).map_err(|e| {
        format!(
            "Failed to write cfg to out path {:?}: {e}",
            gen_opts.cfg_destination
        )
    })?;
    println!("[boot-rs]: Success!");
    Ok(())
}

#[inline]
fn generate_nonce_and_salt(
) -> Result<([u8; REQUIRED_NONCE_LENGTH], [u8; REQUIRED_HASH_LENGTH]), String> {
    let mut iv: [u8; REQUIRED_NONCE_LENGTH] = [0u8; REQUIRED_NONCE_LENGTH];
    system_random(&mut iv)
        .map_err(|e| format!("Failed to generate a random initialization vector: {e}"))?;
    let mut salt: [u8; REQUIRED_HASH_LENGTH] = [0u8; REQUIRED_HASH_LENGTH];
    system_random(&mut salt).map_err(|e| format!("Failed to generate a random salt: {e}"))?;
    Ok((iv, salt))
}

#[inline]
fn prompt_passwords() -> Result<String, String> {
    let mut pass_bytes = [0u8; 128];
    println!("Enter kernel decryption password: ");
    let pass = get_pass(&mut pass_bytes)
        .map_err(|e| format!("Failed to get the decryption password from stdin: {e}"))?;
    let mut pass2_bytes = [0u8; 128];
    println!("Repeat kernel decryption password: ");
    let pass2 = get_pass(&mut pass2_bytes)
        .map_err(|e| format!("Failed to get decryption password repetition from stdin: {e}"))?;
    if pass2 != pass {
        return Err("Password mismatch!".to_string());
    }
    Ok(pass.trim_end_matches('\n').to_string())
}

#[inline]
fn timed<R, F: FnOnce() -> R>(func: F) -> Result<(R, f32), String> {
    let now = SystemTime::now();
    let res = (func)();
    let elapsed = now.elapsed().ok_or_else(|| {
        "Failed to get elapsed time, system misconfiguration, or we're in a time vortex".to_string()
    })?;
    Ok((res, elapsed.as_secs_f32()))
}

#[inline]
fn get_efi_path_string(input_path: &str) -> Result<String, String> {
    let mut path = String::new();
    let orig_len = path.len();
    for component in input_path.split('/') {
        path.write_fmt(format_args!("{component}\\"))
            .map_err(|e| format!("Failed to append to string, should never happen: {e}"))?;
    }
    if path.len() > orig_len {
        path = path.trim_end_matches('\\').to_string();
    }
    println!("Using efi path {path}");
    Ok(path)
}
