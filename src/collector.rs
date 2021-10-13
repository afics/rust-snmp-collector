use std::collections::{HashMap, HashSet};
use std::iter::Iterator;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender as CrossbeamSender;

use log::{debug, error, info, warn};

use failure::Error;
use rand::Rng;

use snmp_mp::{VarBind, VarValue};

use crate::config::Config;
use crate::snmp::{
    fetch_table as snmp_fetch_table, fetch_var_binds as snmp_fetch_var_binds, vec_to_var_binds,
};
use crate::stat_result::SnmpStatResult;

pub fn collect_device_safe(
    device_name: String,
    config: Arc<Config>,
    oid_var_bind_map: HashMap<String, VarBind>,
    channel: CrossbeamSender<SnmpStatResult>,
) {
    let device = config.devices.get(&device_name).unwrap();
    let interval = Duration::from_secs(device.interval.into());
    let backoff = interval / 3;

    let startup_delay = Duration::from_secs(rand::thread_rng().gen_range(0..interval.as_secs()));
    debug!(
        "collect_device_safe({}): startup delay -> sleeping for {:?}",
        device_name, startup_delay
    );
    thread::sleep(startup_delay);

    loop {
        let collect = collect_device(
            device_name.clone(),
            config.clone(),
            oid_var_bind_map.clone(),
            channel.clone(),
        );
        if let Err(error) = &collect {
            warn!(
                "collect_device_safe({}): {:?}; backing off for {:?}",
                device_name, error, backoff
            );
            thread::sleep(backoff);
            info!(
                "collect_device_safe({}): backoff {:?} done, retrying...",
                device_name, backoff
            );
            continue;
        }
    }
}

pub fn collect_device(
    device_name: String,
    config: Arc<Config>,
    oid_var_bind_map: HashMap<String, VarBind>,
    channel: CrossbeamSender<SnmpStatResult>,
) -> Result<(), Error> {
    debug!("collect_device({}): start", device_name);
    let device = config.devices.get(&device_name).unwrap();
    let interval = Duration::from_secs(device.interval.into());

    // condense mibs to connect
    let mut collect_map: HashMap<VarBind, HashSet<VarBind>> = HashMap::new();
    for collect in &device.collect {
        let config_data_entry = config.data.get(collect).unwrap();
        let instance_oid = oid_var_bind_map.get(&config_data_entry.instance).unwrap();

        let entry = collect_map
            .entry(instance_oid.clone())
            .or_insert_with(|| HashSet::new());

        for value in &config_data_entry.values {
            entry.insert(oid_var_bind_map.get(value).unwrap().clone());
        }
    }
    let collect_map = collect_map;

    debug!(
        "collect_device({}): collect_map = {:?}",
        device_name, collect_map
    );

    let timeout = device.snmp.timeout.0;

    loop {
        let start_time = Instant::now();

        for (collect_key, collect_values) in &collect_map {
            let mut hpe_comware_workaround_var_binds: Vec<VarBind> = vec![];
            debug!("collect_device({}) fetch_table start", device_name);

            // request snmp data
            let table_names = snmp_fetch_table(&device.snmp, vec![collect_key.clone()], timeout)?;

            for collect_value in collect_values {
                let table_values =
                    snmp_fetch_table(&device.snmp, vec![collect_value.clone()], timeout)?;

                debug!("collect_device({}) fetch_table done", device_name);

                // zip key value tuples from the name and value tables
                for (_, name_bind) in &table_names {
                    let name_string: String = match name_bind.value() {
                        VarValue::String(s) => String::from_utf8_lossy(s).to_string(),
                        _ => {
                            error!("collect_device({}): table_name oid does not return STRING, unsupported type", device_name);
                            break;
                        }
                    };

                    let name_index = name_bind.name().components().last().unwrap();
                    let table_value = table_values.iter().find(|(_, val_bind)| {
                        val_bind.name().components().last().unwrap() == name_index
                    });

                    if let Some(table_value) = table_value {
                        // we found a value_bind for the corresponding name_bind
                        let (table_instant, table_bind) = table_value.clone();

                        channel
                            .send(SnmpStatResult {
                                device: device_name.clone(),
                                timestamp: table_instant.clone(),
                                key: name_bind.clone(),
                                value: table_bind,
                            })
                            .unwrap();
                    } else {
                        // we did not, try requesting it through a simple get_request
                        debug!("collect_device({}): hpe_comware_workaround: {} = {} not found in value table, triggering workaround", device_name, name_bind.name(), name_string);
                        hpe_comware_workaround_var_binds.push(name_bind.clone());
                    }
                }

                // HPE comware workaround -> request missing oids with a GetRequest
                if hpe_comware_workaround_var_binds.len() > 0 {
                    debug!("collect_device({}): hpe_comware_workaround: {} oids not found, requesting via snmpget", device_name, hpe_comware_workaround_var_binds.len());

                    // build request var_binds
                    let mut hpe_comware_workaround_value_var_binds: Vec<VarBind> = vec![];
                    for name_bind in &hpe_comware_workaround_var_binds {
                        let mut request_oid =
                            table_values.first().unwrap().1.name().components().to_vec();
                        *request_oid.last_mut().unwrap() =
                            *name_bind.name().components().last().unwrap(); // oid of missing element
                        hpe_comware_workaround_value_var_binds.push(vec_to_var_binds(request_oid));
                    }

                    // request binds
                    let hpe_comware_snmp_data = snmp_fetch_var_binds(
                        &device.snmp,
                        hpe_comware_workaround_value_var_binds,
                        timeout,
                    )?;
                    for (name_bind, (table_instant, table_bind)) in hpe_comware_workaround_var_binds
                        .iter()
                        .zip(hpe_comware_snmp_data.iter())
                    {
                        let mut table_bind = table_bind.clone();
                        if table_bind.value() == &VarValue::NoSuchInstance {
                            debug!("collect_device({}): hpe_comware_workaround: {} = {} ->  NoSuchInstance for value, assuming 0_64", device_name, name_bind.name(), msnmp::format_var_bind::format_var_value(name_bind.value()));
                            table_bind.set_value(VarValue::BigCounter(0));
                        }
                        channel
                            .send(SnmpStatResult {
                                device: device_name.clone(),
                                timestamp: table_instant.clone(),
                                key: name_bind.clone(),
                                value: table_bind.clone(),
                            })
                            .unwrap();
                    }
                    hpe_comware_workaround_var_binds.clear();
                }
            }
        }
        let snmp_duration = start_time.elapsed();
        if snmp_duration < interval {
            debug!(
                "collect_device({}): snmp took {:?}",
                device_name, snmp_duration
            );

            thread::sleep(interval);
        } else {
            warn!(
                "collect_device({}): snmp took {:?}, which is longer than set interval {:?}",
                device_name, snmp_duration, interval
            );
        }
    }
}
