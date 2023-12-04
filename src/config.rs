use anyhow::bail;
use anyhow::Error;
use config_file::FromConfigFile;
use log::{debug, trace};
use scan_dir::ScanDir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct DataEntry {
    pub table: bool,
    pub instance: String,
    pub values: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum SnmpAuthProtocol {
    #[serde(rename = "SHA")]
    Sha,
    #[serde(rename = "MD5")]
    Md5,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum SnmpPrivProtocol {
    #[serde(rename = "AES")]
    Aes,
    #[serde(rename = "DES")]
    Des,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum SnmpVersion {
    #[serde(rename = "3")]
    Three,
}

/// Timeout in seconds.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Timeout(pub u64);
impl Default for Timeout {
    fn default() -> Self {
        Timeout(10)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct DeviceEntry {
    pub snmp: DeviceSnmpSettings,
    pub collect: Vec<String>,
    pub interval: u16,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct OptionalConfig {
    pub output: Option<Output>,
    pub data: Option<HashMap<String, DataEntry>>,
    pub devices: Option<HashMap<String, DeviceEntry>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub output: Output,
    pub data: HashMap<String, DataEntry>,
    pub devices: HashMap<String, DeviceEntry>,
}

pub fn from_file(path: &str) -> Result<Config, Error> {
    debug!("config(file={}): loading from file", path);
    Ok(Config::from_config_file(path)?)
}

fn from_file_optional(path: &str) -> Result<OptionalConfig, Error> {
    debug!("config(file={}): loading from file", path);
    Ok(OptionalConfig::from_config_file(path)?)
}

pub fn from_directory(path: &str) -> Result<Config, Error> {
    debug!(
        "config(directory={}): loading configuration files from directory",
        path
    );

    let mut config = OptionalConfig::default();

    // enumerate yaml files which we need to parse
    let files: Vec<_> = ScanDir::files()
        .walk(path, |iter| {
            iter.filter(|(_, name)| name.ends_with(".yaml"))
                .map(|(ref entry, _)| entry.path())
                .collect()
        })
        .map_err(|errors| anyhow::Error::msg(format!("{:#?}", errors)))?;

    for file in files {
        let tmp_config = from_file_optional(file.to_str().unwrap())?;

        // handle output
        if let Some(tmp_output) = tmp_config.output {
            match &config.output {
                Some(output) => {
                    if output != &tmp_output {
                        bail!("Previous definition of output {:?} differs from new output definition {:?} in {:?}", output, tmp_output,file);
                    }
                }
                None => config.output = Some(tmp_output),
            };
        }

        // handle data
        if let Some(tmp_data) = tmp_config.data {
            match &mut config.data {
                Some(data) => {
                    for (tmp_entry_name, tmp_entry) in tmp_data.iter() {
                        if let Some(entry) = data.get(tmp_entry_name) {
                            if entry != tmp_entry {
                                bail!(
                        "Previous definition of data entry {} differs from new definition in {:?}",
                        tmp_entry_name,
                        file
                    );
                            }
                        } else {
                            data.insert(tmp_entry_name.to_string(), tmp_entry.clone());
                        }
                    }
                }
                None => config.data = Some(tmp_data),
            }
        }

        // handle devices
        if let Some(tmp_devices) = tmp_config.devices {
            match &mut config.devices {
                Some(devices) => {
                    for (tmp_device_name, tmp_device) in tmp_devices.iter() {
                        if let Some(device) = devices.get(tmp_device_name) {
                            if device != tmp_device {
                                bail!("Previous definition of device entry {} differs from new definition in {:?}", tmp_device_name,file);
                            }
                        } else {
                            devices.insert(tmp_device_name.to_string(), tmp_device.clone());
                        }
                    }
                }
                None => config.devices = Some(tmp_devices),
            }
        }
    }

    trace!("OptionalConfig is: {:#?}", config);

    Ok(Config {
        output: match config.output {
            Some(output) => output,
            None => bail!("Missing 'output' section in configuration"),
        },
        data: match config.data {
            Some(data) => data,
            None => bail!("Missing 'data' section in configuration"),
        },
        devices: match config.devices {
            Some(devices) => devices,
            None => bail!("Missing 'devices' section in configuration"),
        },
    })
}
