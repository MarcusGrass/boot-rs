use crate::Argon2Opts;
use initramfs_lib::{read_cfg, write_cfg, Cfg};
use ring::rand::SecureRandom;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

pub(crate) fn gen_key_file(
    cfg_file: &Path,
    argon2opts: &Argon2Opts,
    dest: &Path,
) -> Result<(), String> {
    let mut initramfs_cfg = cfg_from_path(cfg_file)?;
    if initramfs_cfg.pass_salt.is_some() {
        return Err("The provided cfg already has a provided salt, implying that a key has already been generated.\n\
        If you want to generate a key for the same salt, use `regenerate-key`".to_string());
    }
    let mut salt = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut salt)
        .map_err(|e| format!("Failed to generate random salt {e}"))?;
    let argon2_cfg = argon2opts.clone().into();
    let pwd = rpassword::prompt_password("Enter password for transient crypt-file: ")
        .map_err(|e| format!("Failed to get password to test disk decryption {e}"))?;
    let key = boot_lib::crypt::derive_with_salt(pwd.as_bytes(), salt, &argon2_cfg)
        .map_err(|e| format!("Failed to derive a key with salt {e}"))?;
    initramfs_cfg.pass_salt = Some(hex::encode(key.salt));
    let cfg_os = cfg_file.as_os_str();
    let cfg = cfg_os.to_str().ok_or_else(|| {
        "Failed to convert initramfs cfg path to utf8, only utf8 paths allowed".to_string()
    })?;
    write_cfg(&initramfs_cfg, cfg)
        .map_err(|e| format!("Failed to write config with new salt {e}"))?;
    OpenOptions::new()
        .create_new(true)
        .mode(0o400)
        .open(dest)
        .map_err(|e| format!("Failed to create new file at {dest:?}: {e}"))?
        .write_all(&key.key)
        .map_err(|e| format!("Failed to write regenerated key to destination {dest:?}: {e}"))
}

pub(crate) fn regen_key_file(
    cfg_file: &Path,
    argon2opts: &Argon2Opts,
    dest: &Path,
) -> Result<(), String> {
    let initramfs_cfg = cfg_from_path(cfg_file)?;
    let Some(salt) = initramfs_cfg.pass_salt else {
        return Err("The provided cfg already no provided salt, implying that no key has been generated.\n\
        If you want to generate a new key, use `generate-key`".to_string())
    };
    let salt_bytes: [u8; 32] = hex::decode(salt)
        .map_err(|e| format!("Failed to decode salt hex {e}"))?
        .try_into()
        .map_err(|e| format!("The provided salt is not 32 bytes {e:?}"))?;
    let pwd = rpassword::prompt_password("Enter password for transient crypt-file: ")
        .map_err(|e| format!("Failed to get password to test disk decryption {e}"))?;
    let argon2_cfg = argon2opts.clone().into();
    let key = boot_lib::crypt::derive_with_salt(pwd.as_bytes(), salt_bytes, &argon2_cfg)
        .map_err(|e| format!("Failed to derive a key with salt {e}"))?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(dest)
        .map_err(|e| format!("Failed to create new file at {dest:?}: {e}"))?
        .write_all(&key.key)
        .map_err(|e| format!("Failed to write regenerated key to destination {dest:?}: {e}"))
}

fn cfg_from_path(path: &Path) -> Result<Cfg, String> {
    let cfg_os = path.as_os_str();
    let cfg = cfg_os.to_str().ok_or_else(|| {
        "Failed to convert initramfs cfg path to utf8, only utf8 paths allowed".to_string()
    })?;
    let cfg = read_cfg(cfg).map_err(|e| format!("Failed to read initramfs cfg from disk {e:?}"))?;
    Ok(cfg)
}

pub(crate) fn generate_initramfs(
    cfg_file: &Path,
    argon2opts: &Argon2Opts,
    dest: &Path,
) -> Result<(), String> {
    let cfg = cfg_from_path(cfg_file)
        .map_err(|e| format!("Failed to read configuration at {cfg_file:?}: {e}"))?;
    if exists(dest)? {
        return Err(format!(
            "Directory already exists at initramfs destination {dest:?}"
        ));
    }
    create_751_dir(dest)?;
    for dir in ["bin", "dev", "lib64", "mnt", "proc", "run", "sbin", "sys"] {
        let path = dest.join(dir);
        create_751_dir(&path)?;
    }
    create_751_dir(&dest.join("mnt").join("root"))?;
    let copy_from_fs = [
        ("/bin/busybox", dest.join("bin").join("busybox")),
        ("/sbin/cryptsetup", dest.join("sbin").join("cryptsetup")),
        (
            "/lib64/ld-linux-x86-64.so.2",
            dest.join("lib64").join("ld-linux-x86-64.so.2"),
        ),
    ];
    for (src, dest) in copy_from_fs {
        static_check_copy(Path::new(src), &dest)?;
    }
    shell_out_copy_archive_dev(dest)?;
    if cfg.pass_salt.is_some() {
        regen_key_file(cfg_file, argon2opts, &dest.join("crypt.key"))
    } else {
        gen_key_file(cfg_file, argon2opts, &dest.join("crypt.key"))
    }
    .map_err(|e| format!("Failed to create key {e}"))?;
    let cfg_path = dest.join("initramfs.cfg");
    let cfg_path_os = cfg_path.as_os_str();
    let cfg_path_utf8 = cfg_path_os
        .to_str()
        .ok_or("Failed to convert cfg path {cfg_path:?} to utf8")?;
    write_cfg(&cfg, cfg_path_utf8).map_err(|e| format!("Failed to write initramfs.cfg to {e}"))?;
    Ok(())
}

fn create_751_dir(dir: &Path) -> Result<(), String> {
    DirBuilder::new()
        .mode(0o751)
        .create(dir)
        .map_err(|e| format!("Failed to create 751 mode directory {dir:?} for initramfs {e}"))
}

fn static_check_copy(src: &Path, dest: &Path) -> Result<(), String> {
    if !exists(src)? {
        return Err(format!(
            "Tried to copy {src:?} to {dest:?} but {src:?} does not exist"
        ));
    }
    let file_out = std::process::Command::new("file")
        .arg(src)
        .output()
        .map_err(|e| {
            format!("Failed to run `file` command on {src:?} to check if statically linked {e}")
        })?;
    if !file_out.status.success() {
        return Err(format!("Failed to run `file` command on {src:?} to check if statically linked, got exit status {}", file_out.status));
    }
    let output = String::from_utf8(file_out.stdout).map_err(|e| {
        format!("`file` command on {src:?} produced output that was not valid utf8 {e}")
    })?;
    if !output.contains("statically linked") && !output.contains("static-pie linked") {
        return Err(format!("`file` command on {src:?} produces output that did not contain the words 'statically linked' or 'static-pie linked' suggesting it's not statically linked, which would produce issues."));
    }
    std::fs::copy(src, dest).map_err(|e| format!("Failed to copy {src:?} to {dest:?}: {e}"))?;
    Ok(())
}

fn exists(path: &Path) -> Result<bool, String> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(format!("Failed to check metadata at {path:?}: {e}"))
            }
        }
    }
}

fn shell_out_copy_archive_dev(dest_base: &Path) -> Result<(), String> {
    for dir in ["null", "console", "tty"] {
        let output = std::process::Command::new("cp")
            .arg("--archive")
            .arg(format!("/dev/{dir}"))
            .arg(dest_base.join("dev"))
            .output()
            .map_err(|e| format!("Failed to spawn copy command `cp --archive /dev/{dir} {dest_base:?}/dev` : {e}"))?;
        if !output.status.success() {
            let maybe_utf8_out = String::from_utf8(output.stderr);
            return Err(format!("Failed to run `cp --archive /dev/{dir} {dest_base:?}/dev`, got exit status {}, output {:?}", output.status, maybe_utf8_out));
        }
    }

    Ok(())
}
