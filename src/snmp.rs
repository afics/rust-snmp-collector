use failure::Error;
use msnmp::msg_factory;
use msnmp::request::get_var_binds;
use msnmp::session::{Session, Step};
use msnmp::Client;
use snmp_mp::{ObjectIdent, PduType, VarBind, VarValue};
use snmp_usm::{Digest, PrivKey};
use std::time::SystemTime;

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
    let mut request_var_binds = oid.clone();

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

pub fn build_snmp_mib_tree(oid_field: String, module: &mib_parser::Module) -> Vec<u64> {
    let mut tree_oid: Vec<u64> = vec![];
    let mut oid_field = oid_field.clone();

    loop {
        let assignment: &mib_parser::Assignment = module
            .assignments
            .iter()
            .filter(|v| v.name == oid_field)
            .nth(0)
            .unwrap();
        let assignment_split: Vec<String> = assignment
            .value
            .as_ref()
            .unwrap()
            .split(" ")
            .map(|s| s.to_string())
            .collect();
        let assignment_parent_name = &assignment_split[1];
        let assignment_parent_oid = &assignment_split[2];

        tree_oid.push(assignment_parent_oid.parse().unwrap());

        oid_field = assignment_parent_name.to_string();

        if assignment_parent_name == "mib-2" {
            break; // we reached mib-2 base
        }
    }
    let mut full_oid: Vec<u64> = vec![1, 3, 6, 1, 2, 1]; // mib-2 base
    full_oid.extend(tree_oid.iter().rev());

    return full_oid;
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

pub fn var_bind_to_u64(v: VarBind) -> Option<u64> {
    match v.value() {
        snmp_mp::VarValue::Counter(value) => Some(*value as u64),
        snmp_mp::VarValue::UnsignedInt(value) => Some(*value as u64),
        snmp_mp::VarValue::BigCounter(value) => Some(*value),
        _ => None,
    }
}
