#![no_std]

use crate::error::{Error, Result};
use alloc::string::{String, ToString};
use alloc::{format, vec};
use rusl::error::Errno;
use rusl::platform::FilesystemType;
use rusl::unistd::{mount, swapon, unmount};
use tiny_std::io::{Read, Write};
use tiny_std::linux::get_pass::get_pass;
use tiny_std::process::{Command, Stdio};
use unix_print::unix_eprintln;

mod error;
pub mod print;

extern crate alloc;

pub fn full_init(cfg: &Cfg) -> Result<()> {
    print_ok!("Mounting pseudo filesystems.");
    mount_pseudo_filesystems()
        .map_err(|e| Error::App(format!("Failed to mount pseudo filesystems {e:?}")))?;
    print_ok!("Running mdev.");
    run_mdev().map_err(|e| Error::App(format!("Failed to run mdev oneshot: {e:?}")))?;
    print_ok!("Mounting user filesystems.");
    mount_user_filesystems(cfg)
        .map_err(|e| Error::App(format!("Failed to mount user filesystems {e:?}")))?;
    print_ok!("Cleaning up.");
    try_unmount().map_err(|e| Error::App(format!("Failed to unmount pseudo filesystems {e:?}")))?;
    print_ok!("Done, switching root");
    let e = switch_root();
    Err(e)
}

pub fn mount_pseudo_filesystems() -> Result<()> {
    mount::<_, _, &'static str>("none\0", "/proc\0", FilesystemType::Proc, 0, None)
        .map_err(|e| Error::MountPseudo(format!("Failed to mount proc types at /proc: {e}")))?;
    mount::<_, _, &'static str>("none\0", "/sys\0", FilesystemType::Sysfs, 0, None)
        .map_err(|e| Error::MountPseudo(format!("Failed to mount sysfs types at /sys: {e}")))?;
    mount::<_, _, &'static str>("none\0", "/dev\0", FilesystemType::Devtmpfs, 0, None)
        .map_err(|e| Error::MountPseudo(format!("Failed to mount devtmpfs at /dev: {e}")))?;
    Ok(())
}

enum AuthMethod {
    File(String),
    Pass(String),
}

const PASS_BUF_CAP: usize = 64;
pub fn mount_user_filesystems(cfg: &Cfg) -> Result<()> {
    let parts = get_partitions(cfg)
        .map_err(|e| Error::Mount(format!("Failed to find partitions {e:?}")))?;
    let mut pass_buf = [0u8; PASS_BUF_CAP];
    let auth_method = if let Some(file) = cfg.crypt_file.clone() {
        AuthMethod::File(file)
    } else {
        print_pending!("Enter passphrase for decryption: ");
        let pass = get_pass(&mut pass_buf)
            .map_err(|e| Error::Crypt(format!("Failed to get password for decryption: {e}")))?;
        AuthMethod::Pass(pass.trim().to_string())
    };
    let confirmed_auth = try_decrypt_fallback_pass(&parts.root, "croot", auth_method)?;
    open_cryptodisk(&parts.swap, "cswap", &confirmed_auth)
        .map_err(|e| Error::Mount(format!("Failed to decrypt swap partition {e:?}")))?;
    open_cryptodisk(&parts.home, "chome", &confirmed_auth)
        .map_err(|e| Error::Mount(format!("Failed to decrypt home partition {e:?}")))?;
    mount::<_, _, &'static str>(
        "/dev/mapper/croot",
        "/mnt/root\0",
        FilesystemType::Ext4,
        0,
        None,
    )
    .map_err(|e| {
        Error::Mount(format!(
            "Failed to mount root partition {} to /mnt/root: {e:?}",
            parts.root
        ))
    })?;
    mount::<_, _, &'static str>(
        "/dev/mapper/chome",
        "/mnt/root/home\0",
        FilesystemType::Ext4,
        0,
        None,
    )
    .map_err(|e| {
        Error::Mount(format!(
            "Failed to mount home partition {} to /mnt/root/home: {e:?}",
            parts.home
        ))
    })?;
    swapon("/dev/mapper/cswap", 0)
        .map_err(|e| Error::Mount(format!("Failed to swapon {}: {e:?}", parts.swap)))?;
    Ok(())
}

fn try_decrypt_fallback_pass(
    root_uuid: &str,
    root_target: &str,
    method: AuthMethod,
) -> Result<AuthMethod> {
    match open_cryptodisk(root_uuid, root_target, &method) {
        Ok(_) => Ok(method),
        Err(e) => {
            let mut e = e;
            for i in 0..3 {
                // All variables that borrow this buf is dropped when we exit this scope
                print_error!("Failed to decrypt root partition: {e:?}, will try again with passphrase, attempt {i}");
                print_pending!("Enter passphrase for decryption: ");
                let mut pass_buffer = [0u8; PASS_BUF_CAP];
                let pass = get_pass(&mut pass_buffer).map_err(|e| {
                    Error::Crypt(format!("Failed to get password for decryption: {e}"))
                })?;
                let try_auth = AuthMethod::Pass(pass.trim().to_string());
                match open_cryptodisk(root_uuid, root_target, &try_auth) {
                    Ok(_) => {
                        print_ok!("It's your lucky day, continuing.");
                        return Ok(try_auth);
                    }
                    Err(err) => {
                        e = err;
                    }
                }
            }
            Err(e)
        }
    }
}

pub fn run_mdev() -> Result<()> {
    let mut cmd = Command::new("/bin/busybox\0")
        .map_err(|e| Error::Spawn(format!("Failed to create command /bin/busybox: {e}")))?;
    cmd.arg("mdev\0")
        .map_err(|e| {
            Error::Spawn(format!(
                "Failed to append command mdev to /bin/busybox: {e}"
            ))
        })?
        .arg("-s\0")
        .map_err(|e| {
            Error::Spawn(format!(
                "Failed to append command -s to '/bin/busybox mdev: {e}"
            ))
        })?;
    let exit = cmd
        .spawn()
        .map_err(|e| Error::Spawn(format!("Failed to spawn /bin/busybox mdev -s: {e}")))?
        .wait()
        .map_err(|e| {
            Error::Spawn(format!(
                "Failed to wait for process exit for /bin/busybox mdev -s: {e}"
            ))
        })?;
    if exit != 0 {
        return Err(Error::Spawn(format!(
            "Got bad exit code from /bin/busybox mdev -s: {exit}"
        )));
    }
    Ok(())
}

#[cfg_attr(test, derive(Debug))]
pub struct Partitions {
    pub root: String,
    pub swap: String,
    pub home: String,
}

pub fn get_partitions(cfg: &Cfg) -> Result<Partitions> {
    let mut cmd = Command::new("/bin/busybox\0")
        .map_err(|e| Error::Spawn(format!("Failed to instantiate busybox command {e}")))?;
    cmd.arg("blkid\0")
        .map_err(|e| Error::Spawn(format!("Failed to append blkid to busybox command {e}")))?;
    let tgt = spawn_await_stdout(cmd, 4096)?;
    let mut root = None;
    let mut swap = None;
    let mut home = None;
    for line in tgt.lines() {
        // Dirty just checking contains, which essentially mean we also accept part-uuids since they
        // are on the same line.

        // /dev/nvme1n1p4: ...UUID=... etc
        if line.contains(&cfg.root_uuid) {
            let (part, _discard_rest) = line.split_once(':')
                .ok_or_else(|| Error::FindPartitions(format!("Failed to find root partition device name on blkid line that contains the specified uuid={}, line={line}", cfg.root_uuid)))?;
            root = Some(part.to_string())
        } else if line.contains(&cfg.swap_uuid) {
            let (part, _discard_rest) = line.split_once(':')
                .ok_or_else(|| Error::FindPartitions(format!("Failed to find swap partition device name on blkid line that contains the specified uuid={}, line={line}", cfg.swap_uuid)))?;
            swap = Some(part.to_string())
        } else if line.contains(&cfg.home_uuid) {
            let (part, _discard_rest) = line.split_once(':')
                .ok_or_else(|| Error::FindPartitions(format!("Failed to find home partition device name on blkid line that contains the specified uuid={}, line={line}", cfg.home_uuid)))?;
            home = Some(part.to_string())
        }
    }
    Ok(Partitions {
        root: root.ok_or_else(|| {
            Error::FindPartitions(format!(
                "Failed to find root partition={} from blkid",
                cfg.root_uuid
            ))
        })?,
        swap: swap.ok_or_else(|| {
            Error::FindPartitions(format!(
                "Failed to find swap partition={} from blkid",
                cfg.swap_uuid
            ))
        })?,
        home: home.ok_or_else(|| {
            Error::FindPartitions(format!(
                "Failed to find home partition={} from blkid",
                cfg.home_uuid
            ))
        })?,
    })
}

pub(crate) fn open_cryptodisk(
    device_name: &str,
    target_name: &str,
    auth: &AuthMethod,
) -> Result<()> {
    let key_file = match auth {
        AuthMethod::File(f) => f.clone(),
        AuthMethod::Pass(pass) => {
            let key_file = "keyfile";
            match tiny_std::fs::metadata(key_file) {
                Ok(_) => key_file.to_string(),
                Err(e) => {
                    if e.matches_errno(Errno::ENOENT) {
                        let mut file = tiny_std::fs::OpenOptions::new()
                            .write(true)
                            .create(true)
                            .open(key_file)
                            .map_err(|e| {
                                Error::Crypt(format!("Failed to open/create keyfile {e}"))
                            })?;
                        file.write_all(pass.as_bytes())
                            .map_err(|e| Error::Crypt(format!("Failed to write keyfile {e}")))?;
                        key_file.to_string()
                    } else {
                        return Err(Error::Crypt(format!(
                            "Failed to check for existing keyfile {e}"
                        )));
                    }
                }
            }
        }
    };

    let mut child = tiny_std::process::Command::new("/sbin/cryptsetup")
        .map_err(|e| {
            Error::Crypt(format!(
                "Failed to instantiate command /sbin/cryptsetup {e}"
            ))
        })?
        .arg("--key-file")
        .map_err(|e| {
            Error::Crypt(format!(
                "Failed to instantiate command /sbin/cryptsetup adding arg --key-file {e}"
            ))
        })?
        .arg(&key_file)
        .map_err(|e| {
            Error::Crypt(format!(
                "Failed to instantiate command /sbin/cryptsetup adding arg {key_file}: {e}"
            ))
        })?
        .arg("open")
        .map_err(|e| {
            Error::Crypt(format!(
                "Failed to instantiate command /sbin/cryptsetup adding arg open {e}"
            ))
        })?
        .arg(device_name)
        .map_err(|e| {
            Error::Crypt(format!(
                "Failed to instantiate command /sbin/cryptsetup, adding device {device_name}: {e}"
            ))
        })?
        .arg(target_name)
        .map_err(|e| {
            Error::Crypt(format!(
                "Failed to instantiate command /sbin/cryptsetup, adding target {target_name}: {e}"
            ))
        })?
        .spawn()
        .map_err(|e| Error::Crypt(format!("Failed to spawn /sbin/cryptsetup {e}")))?;
    let res = child.wait().map_err(|e| {
        Error::Crypt(format!(
            "Failed to await for child process /sbin/cryptsetup: {e}"
        ))
    })?;
    if res != 0 {
        return Err(Error::Crypt(format!(
            "Got error from /sbin/cryptsetup, code {res}"
        )));
    }
    Ok(())
}

pub(crate) fn spawn_await_stdout(mut cmd: Command, buf_size: usize) -> Result<String> {
    let mut child = cmd
        .stdout(Stdio::MakePipe)
        .spawn()
        .map_err(|e| Error::Spawn(format!("Failed to spawn command {e}")))?;
    let res = child
        .wait()
        .map_err(|e| Error::Spawn(format!("Failed to wait for child to exit {e}")))?;
    if res != 0 {
        return Err(Error::Spawn(format!("Got bad exit code {res} from child")));
    }
    let mut buf = vec![0u8; buf_size];
    let mut stdout = child
        .stdout
        .ok_or_else(|| Error::Spawn("Failed to get child stdout handle".to_string()))?;
    let read_bytes = stdout
        .read(&mut buf)
        .map_err(|e| Error::Spawn(format!("Failed to read from child stdout handle {e}")))?;
    // Maybe don't double alloc here but who cares really
    String::from_utf8(buf[..read_bytes].to_vec())
        .map_err(|e| Error::Spawn(format!("Failed to convert child stdout to utf8 {e}")))
}

// This can fail without it necessarily being a problem
pub fn try_unmount() -> Result<()> {
    if let Err(e) = unmount("/proc\0") {
        unix_eprintln!("Failed to unmount proc fs: {e}");
    }
    if let Err(e) = unmount("/sys\0") {
        unix_eprintln!("Failed to unmount sysfs {e}");
    }
    // Don't try to unmount /dev, we're using it
    Ok(())
}

pub fn switch_root() -> Error {
    let mut cmd = match Command::new("/bin/busybox\0") {
        Ok(cmd) => cmd,
        Err(e) => return Error::Spawn(format!("Failed to create command /bin/busybox: {e}")),
    };
    if let Err(e) = cmd.arg("switch_root\0") {
        return Error::Spawn(format!(
            "Failed to append command switch_root to /bin/busybox: {e}"
        ));
    }
    if let Err(e) = cmd.arg("/mnt/root\0") {
        return Error::Spawn(format!(
            "Failed to append command /mnt/root to '/bin/busybox switch_root': {e}"
        ));
    }
    if let Err(e) = cmd.arg("/sbin/init\0") {
        return Error::Spawn(format!(
            "Failed to append command /sbin/init to '/bin/busybox switch_root /mnt/root': {e}"
        ));
    }
    let e = cmd.exec();
    Error::Spawn(format!(
        "Failed to execute '/bin/busybox switch_root /mnt/root /sbin/init': {e}"
    ))
}

pub fn bail_to_shell() -> Error {
    unix_eprintln!("Bailing to shell, good luck.");
    let mut cmd = match Command::new("/bin/busybox\0") {
        Ok(cmd) => cmd,
        Err(e) => {
            return Error::Bail(format!(
                "Failed to create command /bin/busybox when bailing: {e}"
            ))
        }
    };
    if let Err(e) = cmd.arg("sh\0") {
        return Error::Bail(format!(
            "Failed to append command /sh to '/bin/busybox' when bailing: {e}"
        ));
    }
    let e = cmd.exec();
    Error::Bail(format!(
        "Failed to run exec on '/bin/busybox sh' when bailing: {e}"
    ))
}

#[derive(Debug)]
pub struct Cfg {
    pub root_uuid: String,
    pub swap_uuid: String,
    pub home_uuid: String,
    pub pass_salt: Option<String>,
    pub crypt_file: Option<String>,
}

pub fn read_cfg(cfg_path: &str) -> Result<Cfg> {
    let content = tiny_std::fs::read_to_string(cfg_path)
        .map_err(|e| Error::Cfg(format!("Failed to read cfg at {cfg_path}: {e}")))?;
    let mut root_uuid = None;
    let mut swap_uuid = None;
    let mut home_uuid = None;
    let mut pass_salt = None;
    let mut crypt_file = None;
    for (ind, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Allow comments
        if trimmed.starts_with("//") {
            continue;
        }
        let (key, value) = trimmed.split_once('=')
            .ok_or_else(|| Error::Cfg(format!("Found non empty line that doesn't contain '=' or starts with '//' [{ind}]: '{line}'")))?;
        match key {
            "root" => root_uuid = Some(value.to_string()),
            "home" => home_uuid = Some(value.to_string()),
            "swap" => swap_uuid = Some(value.to_string()),
            "password_salt" => pass_salt = Some(value.to_string()),
            "crypt_file" => crypt_file = Some(value.to_string()),
            other => {
                return Err(Error::Cfg(format!(
                    "Unrecognized key in config file {other} at [{ind}]: '{line}'"
                )))
            }
        }
    }
    Ok(Cfg {
        root_uuid: root_uuid
            .ok_or_else(|| Error::Cfg(format!("No root uuid found in cfg at path {cfg_path}")))?,
        swap_uuid: swap_uuid
            .ok_or_else(|| Error::Cfg(format!("No swap uuid found in cfg at path {cfg_path}")))?,
        home_uuid: home_uuid
            .ok_or_else(|| Error::Cfg(format!("No home uuid found in cfg at path {cfg_path}")))?,
        pass_salt,
        crypt_file,
    })
}

pub fn write_cfg(cfg: &Cfg, path: &str) -> core::result::Result<(), String> {
    let pass = if let Some(salt) = &cfg.pass_salt {
        format!("password_salt={salt}\n")
    } else {
        "".to_string()
    };
    let crypt = if let Some(crypt) = &cfg.crypt_file {
        format!("crypt_file={crypt}\n")
    } else {
        "".to_string()
    };
    let content = format!(
        "home={}\nroot={}\nswap={}\n{pass}{crypt}",
        cfg.home_uuid, cfg.root_uuid, cfg.swap_uuid
    );
    let mut file = tiny_std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("Failed to open file for reading at {path}: {e}"))?;
    file.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write content into file at {path}: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Needs your testing machine's disk uuids
    #[test]
    #[ignore]
    fn test_blkid() {
        let cfg = read_cfg("/home/gramar/code/rust/yubi-initramfs/initramfs.cfg").unwrap();
        let parts = get_partitions(&cfg).unwrap();
        unix_eprintln!("{parts:?}");
    }
}
