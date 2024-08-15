#![no_main]
#![no_std]
#![warn(clippy::pedantic)]
#![allow(clippy::let_underscore_untyped, clippy::used_underscore_binding)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use boot_lib::crypt::BootDecryptError;
use boot_lib::BootCfg;
use core::fmt::Write;
use uefi::prelude::*;
use uefi::proto::console::text::Key;
use uefi::proto::device_path::text::{AllowShortcuts, DevicePathToText, DisplayOnly};
use uefi::proto::device_path::DevicePath;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::ProtocolPointer;
use uefi::table::boot::{LoadImageSource, SearchType};
use uefi::table::runtime::Time;
use uefi::CStr16;

const CFG_RAW: &str = include_str!("../../boot.cfg");

#[entry]
fn main(_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi::helpers::init(&mut system_table).unwrap();
    let _ = system_table
        .stdout()
        .write_str("[boot-rs]: Welcome to the encrypted boot checker!\n");
    let e = match boot(&mut system_table) {
        Ok(()) => {
            // Should be unreachable if I understood the docs correctly, we should yield to
            // the kernel image and never come back.
            return Status::SUCCESS;
        }
        // Borrow checker, the above borrow doesn't allow us to use stdout.
        Err(e) => e,
    };
    let _ = system_table
        .stdout()
        .write_fmt(format_args!("[boot-rs]: Failed to boot: {e}.\n"));
    await_enter(&mut system_table);
    Status::LOAD_ERROR
}

fn boot(system: &mut SystemTable<Boot>) -> Result<(), String> {
    let boot_cfg = BootCfg::parse_raw(CFG_RAW)
        .map_err(|e| format!("ERROR: Failed to read configuration {e}"))?;
    // Casting into P which has access to GUID is neigh impossible, so we'll just turbofish
    // into a function. Gets around vtable shennanigans as well.
    let encrypted_kernel = read_kernel_data::<SimpleFileSystem>(system, &boot_cfg)?;
    let _ = system.stdout().write_str("[boot-rs]: Read kernel file.\n");
    let decrypted_kernel = decrypt_kernel(system, &encrypted_kernel)?;
    let _ = system
        .stdout()
        .write_str("[boot-rs]: Decrypted kernel file, loading kernel image.\n");
    yield_to_kernel(system, decrypted_kernel)
}

fn read_kernel_data<P: ProtocolPointer + ?Sized>(
    system: &mut SystemTable<Boot>,
    cfg: &BootCfg,
) -> Result<Vec<u8>, String> {
    let hb = system
        .boot_services()
        .locate_handle_buffer(SearchType::ByProtocol(&P::GUID))
        .map_err(|e| {
            format!("ERROR: Failed to locate handle buffers for SimpleFileSystem: {e:?}")
        })?;
    let to_text_handle = system
        .boot_services()
        .get_handle_for_protocol::<DevicePathToText>()
        .unwrap();
    let to_text_path_protoc = system
        .boot_services()
        .open_protocol_exclusive::<DevicePathToText>(to_text_handle)
        .unwrap();
    for handle in hb.iter() {
        if let Ok(dev_protoc) = system
            .boot_services()
            .open_protocol_exclusive::<DevicePath>(*handle)
        {
            let mut found_tgt = false;
            for node in dev_protoc.node_iter() {
                let text = to_text_path_protoc
                    .convert_device_node_to_text(
                        system.boot_services(),
                        node,
                        DisplayOnly(false),
                        AllowShortcuts(true),
                    )
                    .unwrap();
                if text.to_string().to_lowercase() == cfg.device.to_lowercase() {
                    found_tgt = true;
                }
            }
            if !found_tgt {
                continue;
            }
            for node in dev_protoc.node_iter() {
                let node_ptr = node.as_ffi_ptr();
                // I don't know why there aren't conversion methods for this, maybe I'm doing something weird
                // Safety: No pointer conversion, no messing with the pointer
                let mut dev_ptr = unsafe { DevicePath::from_ffi_ptr(node_ptr) };
                if let Ok(can_load_fs) = system
                    .boot_services()
                    .locate_device_path::<SimpleFileSystem>(&mut dev_ptr)
                {
                    let mut loaded = system.boot_services().open_protocol_exclusive::<SimpleFileSystem>(can_load_fs)
                        .map_err(|e| format!("ERROR: Failed to load SimpleFileSystem protocol on an handle checked to be able to load it: {e:?}"))?;
                    if let Ok(mut vol) = loaded.open_volume() {
                        let mut buf = vec![0u16; 256];
                        let file_name = CStr16::from_str_with_buf(cfg.encrypted_path_on_device, &mut buf)
                            .map_err(|e| format!("ERROR: Failed to convert `encrypted_path_on_device` {} to a CStr16: {e:?}", cfg.encrypted_path_on_device))?;
                        let file_handle = vol.open(file_name, FileMode::Read, FileAttribute::all())
                            .map_err(|e| format!("ERROR: Failed to open `encrypted_path_on_device` {} for reading: {e:?}", cfg.encrypted_path_on_device))?;
                        let mut content = file_handle.into_regular_file()
                            .ok_or_else(|| format!("ERROR: Failed to convert `encrypted_path_on_device` {} into a regular file.", cfg.encrypted_path_on_device))?;
                        let info = content.get_boxed_info::<FileInfo>()
                            .map_err(|e| format!("ERROR: Failed to get file info of regular file at `encrypted_path_on_device` {}: {e:?}", cfg.encrypted_path_on_device))?;
                        let file_size: usize = info.file_size().try_into().map_err(|e| {
                            format!("ERROR: Regular file to big to fit in a usize {e}")
                        })?;
                        let mut buffer = vec![0u8; file_size];
                        let read_bytes = content.read(&mut buffer)
                            .map_err(|e| format!("ERROR: Failed to read {file_size} bytes from regular file at `encrypted_path_on_device` into memory: {e:?}"))?;
                        if read_bytes != file_size {
                            return Err(format!("ERROR: Read unexpected of bytes from regular file at `encrypted_path_on_device`: expected {file_size}, got {read_bytes}."));
                        }
                        return Ok(buffer);
                    }
                }
            }
        }
    }
    Err("ERROR: Failed to find kernel image an any device".to_string())
}

fn decrypt_kernel(system: &mut SystemTable<Boot>, buf: &[u8]) -> Result<Vec<u8>, String> {
    for i in 1..4 {
        let key = get_pass(system)?;
        let _ = system
            .stdout()
            .write_str("[boot-rs]: Got password, deriving key and attempting decrypt.\n");
        let t0 = system.runtime_services().get_time();
        match boot_lib::crypt::hash_and_decrypt(buf, key.as_bytes()) {
            Ok(tgt) => {
                let t1 = system.runtime_services().get_time();
                let failed_time = if let (Ok(t0), Ok(t1)) = (t0, t1) {
                    #[allow(clippy::cast_precision_loss)]
                    if let Some(delta) = get_time_delta_millis(t0, t1) {
                        let seconds = delta as f32 / 1000f32;
                        let _ = system.stdout().write_fmt(format_args!(
                            "[boot-rs]: Derived key and decrypted kernel in {seconds} seconds.\n"
                        ));
                        false
                    } else {
                        true
                    }
                } else {
                    true
                };
                if failed_time {
                    let _ = system.stdout().write_fmt(format_args!(
                        "[boot-rs]: Derived key and decrypted kernel.\n"
                    ));
                }
                return Ok(tgt);
            }
            Err(e) => match e {
                BootDecryptError::InvalidContent => {
                    let _ = system.stdout().write_fmt(format_args!(
                        "[boot-rs]: Failed to decrypt kernel, bad pass, attempt [{i}/3].\n"
                    ));
                }
                BootDecryptError::Other(o) => {
                    return Err(format!("ERROR: Failed to decrypt kernel image: {o}"));
                }
            },
        }
    }
    Err("ERROR: Failed to decrypt kernel image, too many failed attempts".to_string())
}

fn yield_to_kernel(
    system: &mut SystemTable<Boot>,
    mut raw_kernel_image: Vec<u8>,
) -> Result<(), String> {
    let self_h = system.boot_services().image_handle();
    // Data is copied, it's okay to drop the buffer after this code executes
    let loaded_kernel = system
        .boot_services()
        .load_image(
            self_h,
            LoadImageSource::FromBuffer {
                buffer: &mut raw_kernel_image,
                file_path: None,
            },
        )
        .map_err(|e| format!("ERROR: Failed to load kernel image: {e:?}"))?;
    system
        .boot_services()
        .start_image(loaded_kernel)
        .map_err(|e| format!("ERROR: Failed to yield execution to the kernel image: {e:?}"))
}

fn get_pass(system_table: &mut SystemTable<Boot>) -> Result<String, String> {
    let _ = system_table
        .stdout()
        .write_str("[boot-rs]: Enter kernel decryption key: \n");
    let mut decr = String::new();
    loop {
        // Safety:
        // Safe if event is not reused after close (we only oneshot it).

        let Some(key_ready_evt) = system_table.stdin().wait_for_key_event() else {
            continue;
        };
        system_table.boot_services().wait_for_event(&mut [key_ready_evt])
            .map_err(|e| format!("ERROR: Failed to wait for key event when listening to kernel decryption key: {e:?}"))?;
        let key = system_table
            .stdin()
            .read_key()
            .map_err(|e| {
                format!("ERROR: Failed to read key after waiting and receiving a key event: {e:?}")
            })?
            .ok_or_else(|| {
                "ERROR: Failed to read key (none supplied) after waiting and receiving a key event"
                    .to_string()
            })?;
        match key {
            Key::Printable(key) => {
                let ch = char::from(key);
                // We're in Microsoft world Char16s and carriage returns.
                if ch == '\r' {
                    break;
                }
                decr.push(ch);
            }
            Key::Special(_) => {}
        }
    }
    Ok(decr)
}

fn await_enter(system_table: &mut SystemTable<Boot>) {
    let _ = system_table
        .stdout()
        .write_str("[boot-rs]: Press enter to exit.\n");
    let stdin = system_table.stdin();
    loop {
        if let Some(key) = stdin.read_key().unwrap() {
            match key {
                Key::Printable(ch) => {
                    if char::from(ch) == '\r' {
                        break;
                    }
                }
                Key::Special(_) => {}
            }
        }
    }
}

fn get_time_delta_millis(t0: Time, t1: Time) -> Option<u64> {
    if t0.day() == t1.day() {
        let t1_millis = get_millis_of_day(t1);
        let t0_millis = get_millis_of_day(t0);
        if t0_millis > t1_millis {
            Some(t0_millis - t1_millis)
        } else {
            Some(t1_millis - t0_millis)
        }
    } else {
        // Don't really want to take in to account different days, let's keep it simple
        None
    }
}

fn get_millis_of_day(t: Time) -> u64 {
    (u64::from(t.second()) + u64::from(t.minute()) * 60 + u64::from(t.hour()) * 3600) * 1000
        + u64::from(t.nanosecond()) / 1_000_000
}
