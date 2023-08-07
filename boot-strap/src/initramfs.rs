use alloc::format;
use alloc::string::{String, ToString};
use boot_lib::crypt::{Argon2Cfg, Argon2Salt, REQUIRED_HASH_LENGTH};
use initramfs_lib::{print_ok, read_cfg, write_cfg, Cfg};
use rusl::platform::Mode;
use tiny_std::fs::OpenOptions;
use tiny_std::io::{Read, Write};
use tiny_std::linux::get_pass::get_pass;
use tiny_std::process::Stdio;
use tiny_std::unix::random::system_random;

pub(crate) fn gen_cfg(
    home_uuid: String,
    root_uuid: String,
    swap_uuid: String,
    dest: Option<String>,
    overwrite: bool,
) -> Result<(), String> {
    for disk_uuid in [&home_uuid, &root_uuid, &swap_uuid] {
        if let Err(e) = tiny_std::fs::metadata(format!("/dev/disk/by-uuid/{disk_uuid}")) {
            return Err(format!("Failed to read metadata for disk specified by uuid {disk_uuid}, double check that the disk is correct: {e}"));
        }
    }
    let mut salt = [0u8; REQUIRED_HASH_LENGTH];
    system_random(&mut salt).map_err(|e| format!("Failed to generate random salt {e}"))?;
    let cfg = Cfg {
        root_uuid,
        swap_uuid,
        home_uuid,
        pass_salt: Some(hex::encode(salt)),
        crypt_file: None,
    };
    let dest = if let Some(dest) = dest {
        print_ok!("Using supplied location as destination {dest:?}");
        dest
    } else {
        print_ok!("No cfg output destination supplied");
        let config_dir = tiny_std::env::var("XDG_CONFIG_HOME").map_err(|_e| {
            "No cfg output destination supplied, couldn't find `XDG_CONFIG_HOME`".to_string()
        })?;
        let dest_dir = format!("{config_dir}/boot-rs");

        if tiny_std::fs::exists(&dest_dir)
            .map_err(|e| format!("Failed to check if {dest_dir} exists: {e}"))?
        {
            let dest = format!("{dest_dir}/initramfs.cfg");
            if tiny_std::fs::exists(&dest)
                .map_err(|e| format!("Failed to check if {dest} exists: {e}"))?
                && !overwrite
            {
                return Err(format!(
                    "Destination {dest:?} already exists and `overwrite` was not specified"
                ));
            }
            dest
        } else {
            tiny_std::fs::create_dir_all(&dest_dir)
                .map_err(|e| format!("Failed to create destination directory {dest_dir:?}: {e}"))?;
            format!("{dest_dir}/initramfs.cfg")
        }
    };
    print_ok!("Writing new CFG to {dest:?}");
    write_cfg(&cfg, dest.as_str())
}

pub(crate) fn gen_key_file(
    cfg_file: &str,
    argon2_cfg: &Argon2Cfg,
    dest: &str,
) -> Result<(), String> {
    let mut initramfs_cfg = cfg_from_path(cfg_file)?;
    if initramfs_cfg.pass_salt.is_some() {
        return Err("The provided cfg already has a provided salt, implying that a key has already been generated.\n\
        If you want to generate a key for the same salt, use `regenerate-key`".to_string());
    }
    let mut salt = [0u8; REQUIRED_HASH_LENGTH];
    system_random(&mut salt).map_err(|e| format!("Failed to generate random salt {e}"))?;
    let mut pass_bytes = [0u8; 128];
    unix_print::unix_print!("Enter password for transient crypt-file: ");
    let pwd = get_pass(&mut pass_bytes)
        .map_err(|e| format!("Failed to get password to test disk decryption {e}"))?;
    let pwd = pwd.trim_end_matches('\n');
    let key = boot_lib::crypt::derive_key(pwd.as_bytes(), &Argon2Salt(salt), argon2_cfg)
        .map_err(|e| format!("Failed to derive a key with salt {e}"))?;
    initramfs_cfg.pass_salt = Some(hex::encode(salt));
    let cfg = cfg_file;
    write_cfg(&initramfs_cfg, cfg)
        .map_err(|e| format!("Failed to write config with new salt {e}"))?;
    OpenOptions::new()
        .create_new(true)
        .mode(Mode::S_IRUSR)
        .open(dest)
        .map_err(|e| format!("Failed to create new file at {dest:?}: {e}"))?
        .write_all(&key.0)
        .map_err(|e| format!("Failed to write regenerated key to destination {dest:?}: {e}"))
}

pub(crate) fn regen_key_file(
    cfg_file: &str,
    argon2opts: &Argon2Cfg,
    dest: &str,
) -> Result<(), String> {
    let initramfs_cfg = cfg_from_path(cfg_file)?;
    let Some(salt) = initramfs_cfg.pass_salt else {
        return Err("The provided cfg already no provided salt, implying that no key has been generated.\n\
        If you want to generate a new key, use `generate-key`".to_string())
    };
    let salt_bytes: [u8; REQUIRED_HASH_LENGTH] = hex::decode(salt)
        .map_err(|e| format!("Failed to decode salt hex {e}"))?
        .try_into()
        .map_err(|e| format!("The provided salt is not 32 bytes {e:?}"))?;
    let mut pass_bytes = [0u8; 128];
    unix_print::unix_print!("Enter password for transient crypt-file: ");
    let pwd = get_pass(&mut pass_bytes)
        .map_err(|e| format!("Failed to get password to test disk decryption {e}"))?;
    let pwd = pwd.trim_end_matches('\n');
    let argon2_cfg = argon2opts.clone();
    let key = boot_lib::crypt::derive_key(pwd.as_bytes(), &Argon2Salt(salt_bytes), argon2_cfg)
        .map_err(|e| format!("Failed to derive a key with salt {e}"))?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(Mode::S_IRUSR)
        .open(dest)
        .map_err(|e| format!("Failed to create new file at {dest:?}: {e}"))?
        .write_all(&key.0)
        .map_err(|e| format!("Failed to write regenerated key to destination {dest:?}: {e}"))
}

fn cfg_from_path(path: &str) -> Result<Cfg, String> {
    let cfg =
        read_cfg(path).map_err(|e| format!("Failed to read initramfs cfg from disk {e:?}"))?;
    Ok(cfg)
}

pub(crate) fn generate_initramfs(
    cfg_file: &str,
    argon2opts: &Argon2Cfg,
    dest: &str,
) -> Result<(), String> {
    let cfg = cfg_from_path(cfg_file)
        .map_err(|e| format!("Failed to read configuration at {cfg_file:?}: {e}"))?;
    if tiny_std::fs::exists(dest).map_err(|e| format!("Failed to check if {dest} exists: {e}"))? {
        return Err(format!(
            "Directory already exists at initramfs destination {dest:?}"
        ));
    }
    create_751_dir(dest)?;
    for dir in ["bin", "dev", "lib64", "mnt", "proc", "run", "sbin", "sys"] {
        let path = format!("{dest}/{dir}");
        create_751_dir(&path)?;
    }

    create_751_dir(&format!("{dest}/mnt/root"))?;
    let copy_from_fs = [
        ("/bin/busybox", format!("{dest}/bin/busybox")),
        ("/sbin/cryptsetup", format!("{dest}/sbin/cryptsetup")),
        ("/sbin/e2fsck.static", format!("{dest}/sbin/e2fsck")),
    ];
    for (src, dest) in copy_from_fs {
        static_check_copy(src, &dest)?;
    }
    shell_out_copy_archive_dev(dest)?;
    if cfg.pass_salt.is_some() {
        regen_key_file(cfg_file, argon2opts, &format!("{dest}/crypt.key"))
    } else {
        gen_key_file(cfg_file, argon2opts, &format!("{dest}/crypt.key"))
    }
    .map_err(|e| format!("Failed to create key {e}"))?;
    let cfg_path_utf8 = format!("{dest}/initramfs.cfg");
    write_cfg(&cfg, &cfg_path_utf8).map_err(|e| format!("Failed to write initramfs.cfg to {e}"))?;
    Ok(())
}

fn create_751_dir(dir: &str) -> Result<(), String> {
    tiny_std::fs::create_dir_mode(dir, Mode::from(0o751))
        .map_err(|e| format!("Failed to create 751 mode directory {dir:?} for initramfs {e}"))
}

fn static_check_copy(src: &str, dest: &str) -> Result<(), String> {
    if !tiny_std::fs::exists(src).map_err(|e| format!("Failed to check if {src} exists: {e}"))? {
        return Err(format!(
            "Tried to copy {src:?} to {dest:?} but {src:?} does not exist"
        ));
    }
    let mut file_out = tiny_std::process::Command::new("/usr/bin/file")
        .unwrap()
        .stdout(Stdio::MakePipe)
        .arg(src)
        .unwrap()
        .spawn()
        .map_err(|e| {
            format!("Failed to spawn `file` command on {src:?} to check if statically linked {e}")
        })?;
    let status = file_out.wait().unwrap();
    let mut output = String::new();
    file_out
        .stdout
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    if status != 0 {
        return Err(format!("Failed to run `file` command on {src:?} to check if statically linked, got exit status {status}"));
    }
    if !output.contains("statically linked") && !output.contains("static-pie linked") {
        return Err(format!("`file` command on {src:?} produces output that did not contain the words 'statically linked' or 'static-pie linked' suggesting it's not statically linked, which would produce issues."));
    }
    let content =
        tiny_std::fs::read(src).map_err(|e| format!("Failed to copy {src:?} to {dest:?}: {e}"))?;
    let metadata = tiny_std::fs::metadata(src)
        .map_err(|e| format!("Failed to copy {src:?} to {dest:?}: {e}"))?;
    let mut dest_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(metadata.mode())
        .open(dest)
        .map_err(|e| format!("Failed to copy {src:?} to {dest:?}: {e}"))?;
    dest_file
        .write_all(&content)
        .map_err(|e| format!("Failed to copy {src:?} to {dest:?}: {e}"))?;
    Ok(())
}

fn shell_out_copy_archive_dev(dest_base: &str) -> Result<(), String> {
    for dir in ["null", "console", "tty"] {
        let mut output = tiny_std::process::Command::new("/bin/cp")
            .unwrap()
            .arg("--archive")
            .unwrap()
            .arg(format!("/dev/{dir}"))
            .unwrap()
            .arg(format!("{dest_base}/dev"))
            .unwrap()
            .spawn()
            .map_err(|e| format!("Failed to spawn copy command `cp --archive /dev/{dir} {dest_base:?}/dev` : {e}"))?;
        let status = output.wait().unwrap();
        if status != 0 {
            //let maybe_utf8_out = String::from_utf8(output.stderr);
            return Err(format!("Failed to run `cp --archive /dev/{dir} {dest_base:?}/dev`, got exit status {status}"));
        }
    }

    Ok(())
}
