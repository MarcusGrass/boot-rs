#![cfg_attr(not(test), no_std)]
#![warn(clippy::pedantic)]
extern crate alloc;

use crate::crypt::DEFAULT_CONFIG;
use alloc::format;
use alloc::string::{String, ToString};

pub mod crypt;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct BootCfg<'a> {
    pub device: &'a str,
    pub encrypted_path_on_device: &'a str,
    pub aes_initialization_vector: [u8; 16],
    pub argon2_salt: [u8; 32],
    pub argon2_mem_cost: u32,
    pub argon2_time_cost: u32,
    pub argon2_lanes: u32,
}

impl<'a> BootCfg<'a> {
    /// Tries to parse the boot cfg from a raw string
    /// # Errors
    /// Bad format
    pub fn parse_raw(cfg: &'a str) -> Result<Self, String> {
        let mut device: Option<&'a str> = None;
        let mut encrypted_path_on_device: Option<&'a str> = None;
        let mut aes_initialization_vector: Option<[u8; 16]> = None;
        let mut argon2_salt: Option<[u8; 32]> = None;
        let mut argon2_mem_cost: Option<u32> = None;
        let mut argon2_time_cost: Option<u32> = None;
        let mut argon2_lanes: Option<u32> = None;
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
                    "aes_initialization_vector" => {
                        let mut buf = [0u8; 16];
                        hex::decode_to_slice(value.as_bytes(), &mut buf)
                            .map_err(|e| format!("ERROR: Failed to decode `aes_initialization_vector` as [u8; 16] from hex bytes: {e}"))?;
                        aes_initialization_vector = Some(buf);
                    }
                    "argon2_salt" => {
                        let mut buf = [0u8; 32];
                        hex::decode_to_slice(value.as_bytes(), &mut buf)
                            .map_err(|e| format!("ERROR: Failed to decode `argon2_salt` as [u8; 32] from hex bytes: {e}"))?;
                        argon2_salt = Some(buf);
                    }
                    "argon2_mem_cost" => {
                        let mem_cost = value.parse().map_err(|e| {
                            format!("ERROR: Failed to decode `argon2_mem_cost` as a u32: {e}")
                        })?;
                        argon2_mem_cost = Some(mem_cost);
                    }
                    "argon2_time_cost" => {
                        let time_cost = value.parse().map_err(|e| {
                            format!("ERROR: Failed to decode `argon2_time_cost` as a u32: {e}")
                        })?;
                        argon2_time_cost = Some(time_cost);
                    }
                    "argon2_lanes" => {
                        let lanes = value.parse().map_err(|e| {
                            format!("ERROR: Failed to decode `argon2_lanes` as a u32: {e}")
                        })?;
                        argon2_lanes = Some(lanes);
                    }
                    e => {
                        return Err(format!("Got unrecognized configuration key {e}"));
                    }
                }
            } else if line.trim().starts_with('#') || line.trim().is_empty() {
                continue;
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
            aes_initialization_vector: aes_initialization_vector.ok_or_else(|| {
                "ERROR: Missing configuration for `aes_initialization_vector`".to_string()
            })?,
            argon2_salt: argon2_salt
                .ok_or_else(|| "ERROR: Missing configuration for `argon2_salt`".to_string())?,
            argon2_mem_cost: argon2_mem_cost.unwrap_or(DEFAULT_CONFIG.mem_cost),
            argon2_time_cost: argon2_time_cost.unwrap_or(DEFAULT_CONFIG.time_cost),
            argon2_lanes: argon2_lanes.unwrap_or(DEFAULT_CONFIG.lanes),
        })
    }

    #[must_use]
    pub fn serialize(&self) -> String {
        let iv_hex = hex::encode(self.aes_initialization_vector);
        let salt = hex::encode(self.argon2_salt);
        format!(
            "\
        device={}\n\
        encrypted_path_on_device={}\n\
        aes_initialization_vector={}\n\
        argon2_salt={}\n\
        argon2_mem_cost={}\n\
        argon2_time_cost={}\n\
        argon2_lanes={}\n\
        ",
            self.device,
            self.encrypted_path_on_device,
            iv_hex,
            salt,
            self.argon2_mem_cost,
            self.argon2_time_cost,
            self.argon2_lanes
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_parse_example_cfg() {
        let bytes = include_str!("../../boot.cfg");
        let res = BootCfg::parse_raw(bytes).unwrap();
        let ex_salt = [
            107u8, 105, 119, 105, 107, 105, 119, 105, 107, 105, 119, 105, 107, 105, 119, 105, 107,
            105, 119, 105, 107, 105, 119, 105, 107, 105, 119, 105, 107, 105, 119, 105,
        ];
        let ex_iv = [
            107u8, 105, 119, 105, 107, 105, 119, 105, 107, 105, 119, 105, 107, 105, 119, 105,
        ];
        assert_eq!(ex_salt, res.argon2_salt);
        assert_eq!(ex_iv, res.aes_initialization_vector);
        assert_eq!(DEFAULT_CONFIG.lanes, res.argon2_lanes);
        assert_eq!(DEFAULT_CONFIG.mem_cost, res.argon2_mem_cost);
        assert_eq!(DEFAULT_CONFIG.time_cost, res.argon2_time_cost);
        let ser = res.serialize();
        let de = BootCfg::parse_raw(&ser).unwrap();
        assert_eq!(res, de);
        eprintln!("{ser}");
    }
}
