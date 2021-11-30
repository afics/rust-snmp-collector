use std::collections::{HashMap, HashSet};
use std::iter::Iterator;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender as CrossbeamSender;

use log::{debug, error, info, trace, warn};

use anyhow::Error;
use rand::Rng;

use msnmp::session::{Session, Step};
use msnmp::Client;
use snmp_mp::{VarBind, VarValue};
use snmp_usm::{
    Aes128PrivKey, AuthKey, DesPrivKey, Digest, LocalizedKey, Md5, PrivKey, Sha1, WithLocalizedKey,
};

use crate::config::Config;
use crate::config::{SnmpAuthProtocol, SnmpPrivProtocol};
use crate::snmp::{
    snmp_bulkwalk as snmp_fetch_table, snmp_get as snmp_fetch_var_binds, vec_to_var_binds,
};
use crate::stat_result::SnmpStatResult;

macro_rules! collect_device {
    ($digest:ty, $device_name:expr, $config:expr, $oid_var_bind_map:expr, $channel:expr) => {{
        let device = $config.devices.get($device_name).unwrap();
        if SnmpPrivProtocol::Aes == device.snmp.privprotocol {
            let salt = rand::random();
            collect_device_::<
                $digest,
                Aes128PrivKey<$digest>,
                <Aes128PrivKey<$digest> as PrivKey>::Salt,
            >($device_name, $config, $oid_var_bind_map, $channel, salt)
        } else {
            let salt = rand::random();
            collect_device_::<$digest, DesPrivKey<$digest>, <DesPrivKey<$digest> as PrivKey>::Salt>(
                $device_name,
                $config,
                $oid_var_bind_map,
                $channel,
                salt,
            )
        }
    }};
}

pub fn collect_device(
    device_name: String,
    config: Arc<Config>,
    oid_var_bind_map: HashMap<String, VarBind>,
    channel: CrossbeamSender<SnmpStatResult>,
) -> Result<(), Error> {
    let device = config.devices.get(&device_name).unwrap();
    match &device.snmp.authprotocol {
        SnmpAuthProtocol::Sha => {
            collect_device!(Sha1, &device_name, config, oid_var_bind_map, channel)
        }
        SnmpAuthProtocol::Md5 => {
            collect_device!(Md5, &device_name, config, oid_var_bind_map, channel)
        }
    }
}

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
            // condense error
            let error_debug_str = format!("{:#?}", error)
                .split('\n')
                .map(|s| s.trim_matches(' '))
                .collect::<Vec<&str>>()
                .join(" ");

            warn!(
                "collect_device_safe({}): error: {}; backing off for {:?}",
                device_name, error_debug_str, backoff
            );
            thread::sleep(backoff);
            info!(
                "collect_device_safe({}): backoff {:?} done, retrying...",
                device_name, backoff
            );
        }
    }
}

fn collect_device_<'a, D: 'a, P, S>(
    device_name: &str,
    config: Arc<Config>,
    oid_var_bind_map: HashMap<String, VarBind>,
    channel: CrossbeamSender<SnmpStatResult>,
    salt: P::Salt,
) -> Result<(), Error>
where
    D: Digest,
    P: PrivKey<Salt = S> + WithLocalizedKey<'a, D>,
    S: Step + Copy,
{
    debug!("collect_device({}): start", device_name);
    let device = config.devices.get(device_name).unwrap();
    let interval = Duration::from_secs(device.interval.into());

    // condense mibs to connect
    let mut collect_map: HashMap<VarBind, HashSet<VarBind>> = HashMap::new();
    for collect in &device.collect {
        let config_data_entry = config.data.get(collect).unwrap();
        let instance_oid = oid_var_bind_map.get(&config_data_entry.instance).unwrap();

        let entry = collect_map
            .entry(instance_oid.clone())
            .or_insert_with(HashSet::new);

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

    // snmp
    let host = if device.snmp.host.find(':').is_none() {
        format!("{}:{}", device.snmp.host, msnmp::SNMP_PORT_NUM)
    } else {
        device.snmp.host.clone()
    };

    let mut client = Client::new(host, Some(timeout))?;
    let mut session: Session<D, P, S> = Session::new(&mut client, device.snmp.secname.as_bytes())?;

    let localized_key =
        LocalizedKey::<D>::new(device.snmp.authpassword.as_bytes(), session.engine_id());
    let auth_key = AuthKey::new(localized_key);
    session.set_auth_key(auth_key);

    let localized_key =
        LocalizedKey::<D>::new(device.snmp.privpassword.as_bytes(), session.engine_id());
    let priv_key = P::with_localized_key(localized_key);
    session.set_priv_key_and_salt(priv_key, salt);

    // fetch metrics in this loop
    loop {
        let start_time = Instant::now();

        for (collect_key, collect_values) in &collect_map {
            let mut hpe_comware_workaround_var_binds: Vec<VarBind> = vec![];
            debug!(
                "collect_device({}) fetch_table({:?}) start",
                device_name,
                collect_key.name().components()
            );

            // request snmp data
            let table_names =
                snmp_fetch_table(vec![collect_key.clone()], &mut client, &mut session)?;

            debug!(
                "collect_device({}) fetch_table({:?}) done",
                device_name,
                collect_key.name().components()
            );

            for collect_value in collect_values {
                debug!(
                    "collect_device({}) fetch_table({:?}) start",
                    device_name,
                    collect_value.name().components()
                );
                let table_values =
                    snmp_fetch_table(vec![collect_value.clone()], &mut client, &mut session)?;

                debug!(
                    "collect_device({}) fetch_table({:?}) done",
                    device_name,
                    collect_value.name().components()
                );

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
                                device: device_name.to_string(),
                                timestamp: table_instant,
                                key: name_bind.clone(),
                                value: table_bind,
                            })
                            .unwrap();
                    } else {
                        // we did not, try requesting it through a simple get_request
                        trace!("collect_device({}): hpe_comware_workaround: {} = {} not found in value table, triggering workaround", device_name, name_bind.name(), name_string);
                        hpe_comware_workaround_var_binds.push(name_bind.clone());
                    }
                }

                // HPE comware workaround -> request missing oids with a GetRequest
                if !hpe_comware_workaround_var_binds.is_empty() {
                    trace!("collect_device({}): hpe_comware_workaround: {} oids not found, requesting via snmpget", device_name, hpe_comware_workaround_var_binds.len());

                    // build request var_binds
                    let mut hpe_comware_workaround_value_var_binds: Vec<VarBind> = vec![];
                    for name_bind in &hpe_comware_workaround_var_binds {
                        // get base oid from another (not missing) table value
                        // this may fail if the requested table is empty, this case is logged
                        if let Some(first_table_value) = table_values.first() {
                            let mut request_oid = first_table_value.1.name().components().to_vec();

                            // replace last element in oid with the one that's been indicated as
                            // missing in hpe_comware_workaround_var_binds
                            *request_oid.last_mut().unwrap() =
                                *name_bind.name().components().last().unwrap(); // oid of missing element

                            hpe_comware_workaround_value_var_binds
                                .push(vec_to_var_binds(request_oid));
                        } else {
                            debug!("collect_device({}): hpe_comware_workaround: table_value.first() is None, possibly an empty table was received from the device", device_name);
                        }
                    }

                    // only execute if a non empty table with missing values has been detected
                    // while building the request var_binds
                    if !hpe_comware_workaround_value_var_binds.is_empty() {
                        // request binds
                        let hpe_comware_snmp_data = snmp_fetch_var_binds(
                            hpe_comware_workaround_value_var_binds,
                            &mut client,
                            &mut session,
                        )?;
                        for (name_bind, (table_instant, table_bind)) in
                            hpe_comware_workaround_var_binds
                                .iter()
                                .zip(hpe_comware_snmp_data.iter())
                        {
                            let mut table_bind = table_bind.clone();
                            if table_bind.value() == &VarValue::NoSuchInstance {
                                trace!("collect_device({}): hpe_comware_workaround: {} = {} ->  NoSuchInstance for value, assuming 0_64", device_name, name_bind.name(), msnmp::format_var_bind::format_var_value(name_bind.value()));
                                table_bind.set_value(VarValue::BigCounter(0));
                            }
                            channel
                                .send(SnmpStatResult {
                                    device: device_name.to_string(),
                                    timestamp: *table_instant,
                                    key: name_bind.clone(),
                                    value: table_bind.clone(),
                                })
                                .unwrap();
                        }
                    }

                    // clear, will be filled with new missing var binds in the next iteration
                    hpe_comware_workaround_var_binds.clear();
                }
            }
        }
        let snmp_duration = start_time.elapsed();
        if snmp_duration < interval {
            let wait = interval - snmp_duration;
            debug!(
                "collect_device({}): snmp took {:?}, waiting for {:?} until next interval",
                device_name, snmp_duration, wait
            );

            thread::sleep(wait);
        } else {
            warn!(
                "collect_device({}): snmp took {:?}, which is longer than set interval {:?}",
                device_name, snmp_duration, interval
            );
        }
    }
}
