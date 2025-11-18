#![cfg_attr(not(test), no_std)]
#![warn(clippy::pedantic)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};

pub mod crypt;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct BootCfg<'a> {
    pub device: &'a str,
    pub encrypted_path_on_device: &'a str,
}

impl<'a> BootCfg<'a> {
    /// Tries to parse the boot cfg from a raw string
    /// # Errors
    /// Bad format
    pub fn parse_raw(cfg: &'a str) -> Result<Self, String> {
        let mut device: Option<&'a str> = None;
        let mut encrypted_path_on_device: Option<&'a str> = None;
        for line in cfg.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "device" => {
                        device = Some(value);
                    }
                    "encrypted_path_on_device" => {
                        encrypted_path_on_device = Some(value);
                    }
                    e => {
                        return Err(format!("Got unrecognized configuration key {e}"));
                    }
                }
            } else if line.trim().starts_with('#') || line.trim().is_empty() {
            } else {
                return Err(format!("Found bad line in configuration {line}"));
            }
        }

        Ok(Self {
            device: device
                .ok_or_else(|| "ERROR: Missing configuration for `device`".to_string())?,
            encrypted_path_on_device: encrypted_path_on_device.ok_or_else(|| {
                "ERROR: Missing configuration for `encrypted_path_on_device`".to_string()
            })?,
        })
    }

    #[must_use]
    pub fn serialize(&self) -> String {
        format!(
            "\
        device={}\n\
        encrypted_path_on_device={}\n\
        ",
            self.device, self.encrypted_path_on_device,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_parse_example_cfg() {
        let bytes = include_str!("../../boot.cfg.tst");
        let res = BootCfg::parse_raw(bytes).unwrap();
        let ser = res.serialize();
        let de = BootCfg::parse_raw(&ser).unwrap();
        assert_eq!(res, de);
    }
}
