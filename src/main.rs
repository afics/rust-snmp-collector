#![allow(clippy::iter_nth_zero)]

use std::collections::{HashMap, HashSet};
use std::env;
use std::iter::Iterator;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use anyhow::{bail, Error, Result};
use clap::Clap;
use crossbeam_channel::unbounded;
use log::{debug, info, trace, warn};
use scan_dir::ScanDir;

use snmp_mp::VarBind;

mod cli;
mod collector;
mod config;
mod output;
mod snmp;
mod stat_result;

use cli::{Command, Opts};
use collector::collect_device_safe;
use config::Config;
use output::{carbon_send_safe, CarbonMetricValue};
use snmp::vec_to_var_binds;

fn main() -> Result<(), Error> {
    env_logger::init();

    // handle commandline arguments
    let cli: Opts = Opts::parse();
    trace!("Parsed commandline options:\n{:#?}", cli);

    let cli_config_test = Command::ConfigTest == cli.command;
    let cli_mib_test = Command::MibTest == cli.command;
    let cli_preflight_check = Command::PreflightCheck == cli.command;

    // do stuff FIXME
    let config_file_path = cli.config;

    debug!("config(file={}): loading from file", config_file_path);
    let config: Arc<Config> = Arc::new(config::from_file(&config_file_path)?);

    debug!("config(file={}): validating", config_file_path);
    // validated configuration
    for (device_name, device) in config.devices.iter() {
        for collector in &device.collect {
            if !config.data.contains_key(collector) {
                bail!(
                    "Undefined collector '{}' used in device '{}'",
                    collector,
                    device_name
                );
            }
        }
    }
    debug!("config(file={}): validation successful", config_file_path);

    if cli_config_test {
        debug!("Configtest succeeded");
        println!("Config is OK");
        return Ok(());
    }

    debug!(
        "config(file={}): determining required mibs and oid var_bind maps",
        config_file_path
    );
    let mut required_mibs: HashSet<String> = env::var("MIBS")
        .unwrap_or_else(|_| "SNMPv2-MIB:SNMPv2-SMI".to_string())
        .split(':')
        .map(|s| s.to_string())
        .collect();

    let mut required_oids: HashSet<String> = HashSet::new();
    for data in config.data.values() {
        required_oids.insert(data.instance.to_string());
        required_mibs.insert(data.instance.split("::").nth(0).unwrap().to_string());
        for value in &data.values {
            required_oids.insert(value.to_string());
            required_mibs.insert(value.split("::").nth(0).unwrap().to_string());
        }
    }

    let required_mibs = required_mibs;
    debug!(
        "config(file={}): required mibs = {:?}",
        config_file_path, required_mibs
    );

    let mibdirs: Vec<String> = env::var("MIBDIRS")
        .unwrap_or_else(|_| "/var/lib/snmp/mibs:/usr/share/mibs:/usr/share/snmp/mibs".to_string())
        .split(':')
        .map(|s| s.to_string())
        .collect();
    debug!("mibs: MIBDIRS={:?}", mibdirs);

    debug!("mibs: loading required_mibs");
    trace!("mibs: required_mibs = {:?}", required_mibs);
    let mut mibs: Vec<mib_parser::MibInfo> = vec![];
    let mib_parse_options = mib_parser::ParseOptions {
        pretty_print: false,
    };
    for mibdir in mibdirs {
        if !Path::new(&mibdir).is_dir() {
            debug!("mibs: mibdir {} does not exist, skipping", mibdir);
            continue;
        }

        let _: Vec<_> = ScanDir::files()
            .walk(mibdir, |iter| {
                iter.filter(|&(_, ref name)| {
                    required_mibs.contains(name.split(".").nth(0).unwrap())
                })
                .map(|(ref entry, _)| {
                    // load mib
                    debug!("mibs: parsing {:?}", entry.path());
                    mibs.push(mib_parser::parse_file(&entry.path(), &mib_parse_options).unwrap());
                })
                .collect()
            })
            .unwrap();
    }
    let mibs = mibs;

    if mibs.len() != required_mibs.len() {
        let mut mibs_found = HashSet::new();
        for mib in mibs {
            mibs_found.insert(mib.modules.first().unwrap().name.clone());
        }
        trace!("mibs: mibs_found={:?}", mibs_found);
        bail!(
            "Could not find some required mibs: {:?}",
            required_mibs.difference(&mibs_found)
        );
    }

    let mut oid_var_bind_map: HashMap<String, VarBind> = HashMap::new();

    for oid in required_oids {
        let full_oid = snmp::build_snmp_mib_tree(&oid, &mibs)?;

        debug!("mibs: resolved {} to {:?}", oid, full_oid);
        oid_var_bind_map.insert(oid, vec_to_var_binds(full_oid));
    }

    if cli_mib_test {
        debug!("Mib-test succeeded");
        println!("MIBs are OK");
        return Ok(());
    }

    if cli_preflight_check {
        debug!("Preflight-check succeeded");
        println!("We are GO for launch.");
        return Ok(());
    }

    // TODO: generate this with the same code that is used in collector::collect_device
    if cli.command == Command::ShowOutputKeys {
        for (device_name, device) in &config.devices {
            for collector in &device.collect {
                let collector_def = config.data.get(collector).unwrap();
                for collector_value in &collector_def.values {
                    // let collector_value.replace("::", ".");

                    let key = output::format_key(
                        device_name,
                        &format!("<{}>", collector_def.instance),
                        &collector_value.split("::").nth(1).unwrap().to_string(),
                    );
                    println!("{}", key);
                }
            }
        }
        return Ok(());
    }

    // set up channel where we communicate SnmpStatResults
    let (snmp_chan_sender, snmp_chan_receiver) = unbounded();

    // start collection threads, one per device
    for (device_name, _) in config.devices.iter() {
        let device_name = device_name.clone();
        let config = config.clone();
        let oid_var_bind_map = oid_var_bind_map.clone();
        let snmp_chan_sender = snmp_chan_sender.clone();
        // one thread per device
        thread::Builder::new()
            .name(format!("c:{}", device_name))
            .spawn(move || {
                collect_device_safe(device_name, config, oid_var_bind_map, snmp_chan_sender)
            })
            .unwrap();
    }

    info!(
        "main: started collection for {} devices",
        config.devices.len()
    );

    // start carbon_output thread
    let (carbon_chan_sender, carbon_chan_receiver) = unbounded();
    let carbon_chan_recovery_sender = carbon_chan_sender.clone(); // used to reinject carbonMetricValues on TCP errors

    info!("main: starting output thread");
    thread::Builder::new()
        .name("carbon_output".to_string())
        .spawn(move || {
            carbon_send_safe(
                config.output.clone(),
                carbon_chan_recovery_sender,
                carbon_chan_receiver,
            )
        })
        .unwrap();

    // stats processing format SnmpStatResults and send them as carbonMetricValue
    info!("main: starting main processing loop");
    loop {
        let result = snmp_chan_receiver.recv().unwrap();

        // convert var_bind oid to its named string
        let result_value_name_oid = result.value.name().components().split_last().unwrap().1;
        let full_val_name = oid_var_bind_map
            .iter()
            .find_map(|kv| {
                if kv.1.name().components() == result_value_name_oid {
                    Some(kv.0.clone())
                } else {
                    None
                }
            })
            .unwrap();
        let val_name = full_val_name.split("::").nth(1).unwrap().to_string();

        // example: IF-MIB::ifName -> Ethernet1/1
        let key_value = snmp::var_numeric_value_to_string(result.key.value());
        if key_value == None {
            warn!(
                "result_loop(for {}): can not handle non numeric values ({}).",
                result.device, val_name
            );
            continue;
        }

        // actual metric value
        let value = snmp::var_bind_to_u64(result.value);
        if value == None {
            debug!(
                "result_loop(for {}): can not handle snmp result for {}",
                result.device, val_name
            );

            continue;
        };

        let key_value = key_value.unwrap();

        let ts = result.timestamp;
        let key = output::format_key(&result.device, &key_value, &val_name);

        let value = format!("{}", value.unwrap());

        debug!(
            "result_loop(for {}): sending to carbon '{} {} {}'",
            result.device,
            ts.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            key,
            value
        );

        carbon_chan_sender
            .send(CarbonMetricValue {
                timestamp: ts,
                metric: key.clone(),
                value: value.clone(),
            })
            .unwrap();
    }
}
