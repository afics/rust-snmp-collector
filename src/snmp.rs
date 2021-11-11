use anyhow::{format_err, Error};
use log::trace;
use std::time::SystemTime;

use msnmp::msg_factory;
use msnmp::request::get_var_binds;
use msnmp::session::{Session, Step};
use msnmp::Client;
use snmp_mp::{ObjectIdent, PduType, VarBind, VarValue};
use snmp_usm::{Digest, PrivKey};

pub fn snmp_bulkwalk<D, P, S>(
    oid: Vec<VarBind>,
    client: &mut Client,
    session: &mut Session<D, P, S>,
) -> Result<Vec<(SystemTime, VarBind)>, Error>
where
    D: Digest,
    P: PrivKey<Salt = S>,
    S: Step + Copy,
{
    let mut request_var_binds = oid;

    let mut result: Vec<(SystemTime, VarBind)> = vec![];

    let end_oid = &msnmp::request::next_sibling(request_var_binds[0].name());
    loop {
        let mut get_next_request =
            msg_factory::create_bulk_request_msg(request_var_binds.clone(), session);

        let get_next_response = client.send_request(&mut get_next_request, session)?;

        match get_var_binds(&get_next_response) {
            Some(binds) => {
                for var_bind in binds {
                    if var_bind.name() >= end_oid || var_bind.value() == &VarValue::EndOfMibView {
                        return Ok(result);
                    }

                    result.push((SystemTime::now(), var_bind.clone()));
                }
                request_var_binds = vec![VarBind::new(binds.last().unwrap().name().clone())];
            }
            None => return Ok(result),
        }
    }
}

pub fn snmp_get<D, P, S>(
    request_var_binds: Vec<VarBind>,
    client: &mut Client,
    session: &mut Session<D, P, S>,
) -> Result<Vec<(SystemTime, VarBind)>, Error>
where
    D: Digest,
    P: PrivKey<Salt = S>,
    S: Step + Copy,
{
    let mut get_request =
        msg_factory::create_request_msg(PduType::GetRequest, request_var_binds, session);

    let mut result: Vec<(SystemTime, VarBind)> = vec![];

    let response = client.send_request(&mut get_request, session)?;
    if let Some(var_binds) = get_var_binds(&response) {
        for var_bind in var_binds {
            result.push((SystemTime::now(), var_bind.clone()));
        }
    }

    Ok(result)
}

pub fn vec_to_var_binds(v: Vec<u64>) -> VarBind {
    VarBind::new(ObjectIdent::new(v))
}

fn find_module<'a>(
    module: &String,
    mibs: &'a Vec<mib_parser::MibInfo>,
) -> Option<&'a mib_parser::Module> {
    mibs.iter()
        .filter(|v| {
            v.modules
                .iter()
                .filter(|m| m.name == module.as_ref())
                .count()
                > 0
        })
        .nth(0)?
        .modules
        .iter()
        .filter(|m| m.name == module.as_ref())
        .nth(0)
}

pub fn build_snmp_mib_tree(
    oid: &String,
    mibs: &Vec<mib_parser::MibInfo>,
) -> Result<Vec<u64>, Error> {
    let mut tree_oid: Vec<u64> = vec![];

    let oid_module = oid.split("::").nth(0).unwrap().to_string();
    let oid_field = oid.split("::").nth(1).unwrap().to_string();

    let module = find_module(&oid_module, &mibs);

    if module.is_none() {
        return Err(format_err!(
            "Could not resolve module {} for {} which is required",
            oid,
            oid_module
        ));
    }
    let module = module.unwrap();

    let mut oid_field = oid_field.clone();

    loop {
        trace!(
            "build_snmp_mib_tree(oid={}, module=...): current_field = {}",
            oid,
            oid_field
        );

        if let Some(assignment) = module
            .assignments
            .iter()
            .filter(|v| v.name == oid_field)
            .nth(0)
        {
            let assignment_split: Vec<String> = assignment
                .value
                .as_ref()
                .unwrap()
                .split(' ')
                .map(|s| s.to_string())
                .collect();

            let assignment_parent_name = &assignment_split[1];
            let assignment_parent_oid = &assignment_split[2];

            tree_oid.push(assignment_parent_oid.parse().unwrap());

            oid_field = assignment_parent_name.to_string();
        } else if let Some(import) = module.imports.iter().filter(|v| v.name == oid_field).nth(0) {
            let mut upper_oid =
                build_snmp_mib_tree(&format!("{}::{}", import.from, import.name), mibs)?;
            upper_oid.extend(tree_oid.iter().rev());
            return Ok(upper_oid);
        } else {
            if oid_field == "iso" {
                // define in Rec. ITU-T X.660 | ISO/IEC 9834-1
                tree_oid.push(1);
                tree_oid.reverse();
                return Ok(tree_oid);
            }

            return Err(format_err!(
                "build_snmp_mib_tree: Could not resolve {} in {}",
                oid_field,
                module.name
            ));
        }
    }
}

pub fn var_numeric_value_to_string(var_value: &VarValue) -> Option<String> {
    match var_value {
        VarValue::Int(i) => Some(format!("{}", i)),
        VarValue::String(s) => Some(format!("{}", String::from_utf8_lossy(s))),
        VarValue::ObjectId(oid) => Some(format!("{}", oid)),
        VarValue::Counter(c) => Some(format!("{}", c)),
        VarValue::UnsignedInt(ui) => Some(format!("{}", ui)),
        VarValue::BigCounter(bc) => Some(format!("{}", bc)),
        _ => None,
    }
}

pub fn var_bind_to_i128(v: VarBind) -> Option<i128> {
    match v.value() {
        snmp_mp::VarValue::Counter(value) => Some(*value as i128),
        snmp_mp::VarValue::UnsignedInt(value) => Some(*value as i128),
        snmp_mp::VarValue::BigCounter(value) => Some((*value).into()),
        snmp_mp::VarValue::Int(value) => Some((*value).into()),
        _ => {
            return None;
        }
    }
}
