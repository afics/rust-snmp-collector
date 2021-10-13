use std::collections::{HashMap, HashSet};
use std::env;
use std::iter::Iterator;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use crossbeam_channel::unbounded;

use log::{debug, error, info, warn};

use scan_dir::ScanDir;

use snmp_mp::VarBind;

mod collector;
mod config;
mod output;
mod snmp;
mod stat_result;

use collector::collect_device_safe;
use config::Config;
use output::sanitize_graphite;
use snmp::vec_to_var_binds;

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    let config_file_path = &args[1];

    debug!("config(file={}): loading from file", config_file_path);
    let config: Arc<Config> = Arc::new(config::from_file(&args[1]));

    debug!("config(file={}): validating", config_file_path);
    // validated configuration
    for (device_name, device) in config.devices.iter() {
        for collector in &device.collect {
            if !config.data.contains_key(collector) {
                error!(
                    "Undefined collector '{}' used in device '{}'",
                    collector, device_name
                );
                panic!();
            }
        }
    }
    debug!("config(file={}): validation successful", config_file_path);

    debug!(
        "config(file={}): determining required mibs and oid var_bind maps",
        config_file_path
    );
    let mut required_mibs: HashSet<String> = HashSet::new();
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
        .unwrap_or("/var/lib/snmp/mibs:/usr/share/mibs".to_string())
        .split(":")
        .map(|s| s.to_string())
        .collect();
    debug!("mibs: MIBDIRS={:?}", mibdirs);

    debug!("mibs: loading required_mibs");
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
                iter.filter(|&(_, ref name)| required_mibs.contains(name))
                    .map(|(ref entry, _)| {
                        // load mib
                        debug!("mibs: parsing {:?}", entry.path());
                        mibs.push(
                            mib_parser::parse_file(&entry.path(), &mib_parse_options).unwrap(),
                        );
                    })
                    .collect()
            })
            .unwrap();
    }
    let mibs = mibs;

    let mut oid_var_bind_map: HashMap<String, VarBind> = HashMap::new();
    let mut mib_modules: Vec<&mib_parser::Module> = vec![];
    for mib in &mibs {
        for module in &mib.modules {
            mib_modules.push(module);
        }
    }
    let mib_modules = mib_modules;

    for oid in required_oids {
        let oid_module = oid.split("::").nth(0).unwrap();
        let oid_field = oid.split("::").nth(1).unwrap();

        let module = mib_modules
            .iter()
            .filter(|v| v.name == oid_module)
            .nth(0)
            .unwrap();
        let full_oid = snmp::build_snmp_mib_tree(oid_field.to_string(), module);

        debug!("mibs: resolved {} to {:?}", oid, full_oid);
        oid_var_bind_map.insert(oid, vec_to_var_binds(full_oid));
    }

    // set up channel where we communicate SnmpStatResults
    let (chan_sender, chan_receiver) = unbounded();
    // start collection threads, one per device
    for (device_name, _) in config.devices.iter() {
        let device_name = device_name.clone();
        let config = config.clone();
        let oid_var_bind_map = oid_var_bind_map.clone();
        let chan_sender = chan_sender.clone();
        // one thread per device
        thread::Builder::new()
            .spawn(move || collect_device_safe(device_name, config, oid_var_bind_map, chan_sender))
            .unwrap();
    }

    info!(
        "main: started collection for {} devices",
        config.devices.iter().count()
    );

    // set up output
    let output_prefix;
    match &config.output {
        config::Output::GraphiteOutput {
            prefix,
            graphite_server: _,
            graphite_port: _,
        } => output_prefix = prefix,
    }

    loop {
        let result = chan_receiver.recv().unwrap();

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
        let val_name = full_val_name.split("::").nth(1).unwrap();

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

        let ts = result.timestamp;
        let key = format!(
            "{}.{}.{}.{}",
            sanitize_graphite(output_prefix),
            sanitize_graphite(&result.device),
            sanitize_graphite(&key_value.unwrap()),
            val_name
        );
        let value = value.unwrap();

        debug!(
            "result_loop(for {}): sending to graphite '{} {} {}'",
            result.device,
            ts.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            key,
            value
        );

        // TODO: send to graphite
    }
}
