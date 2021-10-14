use config_file::FromConfigFile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum Output {
    #[serde(rename = "carbon")]
    #[serde(alias = "graphite")]
    CarbonOutput {
        prefix: String,
        // change to carbon with 'graphite' alias after issue rust#54726 has been fixeed
        graphite_server: String,
        graphite_port: u16,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataEntry {
    pub table: bool,
    pub instance: String,
    pub values: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum SnmpAuthProtocol {
    #[serde(rename = "SHA")]
    Sha,
    #[serde(rename = "MD5")]
    Md5,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum SnmpPrivProtocol {
    #[serde(rename = "AES")]
    Aes,
    #[serde(rename = "DES")]
    Des,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum SnmpVersion {
    #[serde(rename = "3")]
    Three,
}

/// Timeout in seconds.
#[derive(Debug, Deserialize, Serialize)]
pub struct Timeout(pub u64);
impl Default for Timeout {
    fn default() -> Self {
        Timeout(10)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceSnmpSettings {
    pub host: String,
    pub version: SnmpVersion,
    pub secname: String,
    pub authprotocol: SnmpAuthProtocol,
    pub authpassword: String,
    pub privprotocol: SnmpPrivProtocol,
    pub privpassword: String,
    #[serde(default)]
    pub timeout: Timeout,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceEntry {
    pub snmp: DeviceSnmpSettings,
    pub collect: Vec<String>,
    pub interval: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub output: Output,
    pub data: HashMap<String, DataEntry>,
    pub devices: HashMap<String, DeviceEntry>,
}

pub fn from_file(path: &str) -> Config {
    Config::from_config_file(path).unwrap()
}
