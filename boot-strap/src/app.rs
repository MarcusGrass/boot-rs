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
use tiny_cli::{arg_parse, Parser};
use tiny_std::linux::get_pass::get_pass;
use tiny_std::process::exit;
use tiny_std::time::SystemTime;
use tiny_std::unix::random::system_random;

arg_parse!(
    #[name("Initramfs gen-cfg")]
    #[description("Generates initramfs configuration")]
    struct InitramfsGenCfgOpts {
        #[short("h"), long("home-uuid"), description("UUID for the home partition")]
        home_uuid: String,
        #[short("r"), long("root-uuid"), description("UUID for the root partition")]
        root_uuid: String,
        #[short("s"), long("swap-uuid"), description("UUID for the swap partition")]
        swap_uuid: String,
        #[short("o"), long("overwrite"), description("Overwrite the current file if present.
        Probably not good, since we generate a cryptsetup key from the generated salt,
        if key that has already been registered, this salt shouldn't change")]
        overwrite: bool,
        #[optional]
        #[short("d"), long("destination-file"), description("Destination file")]
        destination_file: Option<String>,
    }
);

arg_parse!(
    #[name("Initramfs gen-init")]
    #[description("Generates initramfs")]
    struct InitramfsGenInitOpts {
        #[short("i"), long("initramfs-cfg"), description("Configuration file containing uuids of cryptdevices")]
        initramfs_cfg: String,
        #[short("d"), long("destination-file"), description("Directory where the initramfs should be created, will wipe a previous initramfs if it exists there.
        Ex: /root/initramfs")]
        destination_directory: String,

        #[optional]
        #[short("m"), long("argon2-mem"), description("Argon 2 mem cost.
        The password will be converted to a 32-byte AES key using argon2, this specifies a custom
        mem cost for that algorithm.
        If omitted, a default value will be used.")]
        argon2_mem: Option<u32>,
        #[optional]
        #[short("t"), long("argon2-time"), description("Argon 2 time cost.
        The password will be converted to a 32-byte AES key using argon2, this specifies a custom
        time cost for that algorithm.
        If omitted, a default value will be used.")]
        argon2_time: Option<u32>,
        #[optional]
        #[short("l"), long("argon2-lanes"), description("Argon 2 parallel cost.
        The password will be converted to a 32-byte AES key using argon2, this specifies a custom
        parallel cost for that algorithm.
        If omitted, a default value will be used.")]
        argon2_lanes: Option<u32>,
    }
);

arg_parse!(
    #[name("Initramfs operations")]
    #[description("Generates initramfs")]
    struct InitramfsOptions {
        #[subcommand("gen-cfg")]
        gen_cfg: Option<InitramfsGenCfgOpts>,
        #[subcommand("gen-init")]
        gen_init: Option<InitramfsGenInitOpts>,
    }
);

arg_parse!(
    #[name("Boot options")]
    #[description("Generate boot options and encrypt a kernel image")]
    struct BootOpts {
        #[short("i"), long("kernel-image-path"), description("The kernel image path.
        Where the kernel image to encrypt is.
        If compiling locally, is usually `src-dir/arch/<arch>/boot/bzImage`.")]
        kernel_image_path: String,


        #[short("e"), long("kernel-enc-path"), description("Encrypted destination.
        Where to put the encrypted kernel image.")]
        kernel_enc_path: String,

        #[short("c"), long("cfg-destination"), description("Configuration destination.
        Where to put the generated configuration file.")]
        cfg_destination: String,

        #[short("d"), long("efi-device"), description("Efi boot device.
        The efi label of the boot device.
        Ex: `HD(1,GPT,f0054eea-adf8-4956-958f-12e353cac4c8,0x800,0x100000)`")]
        efi_device: String,


        #[short("p"), long("efi-path"), description("Efi boot device kernel path.
        The internal path on the EFI device, where you plan to put the kernel.
        Likely to be the same as `kernel_enc_path`.
        We're not using microsoft path-specs because we're not in microsoft world just yet.
        Ex: `/EFI/gentoo/gentoo-6.1.19.enc`")]
        efi_path: String,

        #[optional]
        #[short("m"), long("argon2-mem"), description("Argon 2 mem cost.
        The password will be converted to a 32-byte AES key using argon2, this specifies a custom
        mem cost for that algorithm.
        If omitted, a default value will be used.")]
        argon2_mem: Option<u32>,
        #[optional]
        #[short("t"), long("argon2-time"), description("Argon 2 time cost.
        The password will be converted to a 32-byte AES key using argon2, this specifies a custom
        time cost for that algorithm.
        If omitted, a default value will be used.")]
        argon2_time: Option<u32>,
        #[optional]
        #[short("l"), long("argon2-lanes"), description("Argon 2 parallel cost.
        The password will be converted to a 32-byte AES key using argon2, this specifies a custom
        parallel cost for that algorithm.
        If omitted, a default value will be used.")]
        argon2_lanes: Option<u32>,
    }
);

arg_parse!(
    #[name("Boot-rs")]
    #[description("Generate boot config")]
    struct Opts {
        #[subcommand("initramfs")]
        initramfs: Option<InitramfsOptions>,
        #[subcommand("boot")]
        boot_opts: Option<BootOpts>,
    }
);

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
    let mut args = tiny_std::env::args().skip(1);
    let args = match Opts::parse(&mut args) {
        Ok(a) => a,
        Err(e) => {
            unix_print::unix_eprintln!("{e}");
            exit(1);
        }
    };
    match (args.initramfs, args.boot_opts) {
        (Some(initramfs), None) => match (initramfs.gen_cfg, initramfs.gen_init) {
            (
                Some(InitramfsGenCfgOpts {
                    home_uuid,
                    root_uuid,
                    swap_uuid,
                    overwrite,
                    destination_file,
                }),
                None,
            ) => {
                gen_cfg(home_uuid, root_uuid, swap_uuid, destination_file, overwrite).unwrap();
            }
            (
                None,
                Some(InitramfsGenInitOpts {
                    initramfs_cfg,
                    destination_directory,
                    argon2_mem,
                    argon2_time,
                    argon2_lanes,
                }),
            ) => {
                let argon2_cfg =
                    create_argon2opts_maybe_default(argon2_mem, argon2_time, argon2_lanes);
                if let Err(e) = generate_initramfs(&initramfs_cfg, &argon2_cfg, &destination_directory) {
                    print_error!("Failed to generate initramfs: {e}");
                    rusl::process::exit(1);
                }
                print_ok!("Successfully generated initramfs, don't forget to add initramfs-rs as `./init` to it.");
            }
            _ => panic!("Expected either gen_cfg or gen_init"),
        },
        (None, Some(boot_opts)) => match generate(&boot_opts) {
            Ok(_) => {}
            Err(e) => {
                panic!("Failed to generate: {e}");
            }
        },
        _ => panic!("Expected either boot or init"),
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
    let efi_path = get_efi_path_string(&gen_opts.efi_path)
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
    unix_print::unix_println!("[boot-rs]: Deriving encryption key.");
    let (key, derive_key_time) =
        timed(|| derive_key(pass.as_bytes(), metadata.salt(), metadata.argon2_cfg()))?;
    let key = key.map_err(|e| format!("Failed to derive a key from the password: {e}"))?;
    unix_print::unix_println!("[boot-rs]: Derived encryption key in {derive_key_time} seconds.");
    unix_print::unix_println!("[boot-rs]: Encrypting kernel image.");
    let (encrypted, encrypt_time) = timed(|| encrypt(&kernel_data, &key, &metadata))?;
    unix_print::unix_println!("[boot-rs]: Encrypted kernel image in {encrypt_time} seconds.");
    // Insanity check.
    let encrypted = encrypted?;
    if encrypted == kernel_data {
        return Err(
            "Encryption failed, output data same as input data (Sanity check triggered)."
                .to_string(),
        );
    }
    unix_print::unix_println!("[boot-rs]: Starting a test decryption.");
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
    unix_print::unix_println!(
        "[boot-rs]: Successfully ran test-decryption in {decryption_time} seconds"
    );
    let cfg = BootCfg {
        device: &gen_opts.efi_device,
        encrypted_path_on_device: &efi_path,
    };
    let cfg_out = cfg.serialize();
    unix_print::unix_println!(
        "[boot-rs]: Writing encrypted kernel to {:?}",
        gen_opts.kernel_enc_path
    );
    tiny_std::fs::write(&gen_opts.kernel_enc_path, encrypted.as_slice()).map_err(|e| {
        format!(
            "Failed to write encrypted kernel to out path {:?}: {e}",
            gen_opts.kernel_enc_path
        )
    })?;
    unix_print::unix_println!(
        "[boot-rs]: Writing configuration to {:?}",
        gen_opts.cfg_destination
    );
    tiny_std::fs::write(&gen_opts.cfg_destination, cfg_out.as_bytes()).map_err(|e| {
        format!(
            "Failed to write cfg to out path {:?}: {e}",
            gen_opts.cfg_destination
        )
    })?;
    unix_print::unix_println!("[boot-rs]: Success!");
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
    unix_print::unix_println!("Enter kernel decryption password: ");
    let pass = get_pass(&mut pass_bytes)
        .map_err(|e| format!("Failed to get the decryption password from stdin: {e}"))?;
    let mut pass2_bytes = [0u8; 128];
    unix_print::unix_println!("Repeat kernel decryption password: ");
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
    unix_print::unix_println!("Using efi path {path}");
    Ok(path)
}
