use std::time::SystemTime;

use snmp_mp::VarBind;

#[derive(Debug)]
pub struct SnmpStatResult {
    pub device: String,
    pub timestamp: SystemTime,
    pub key: VarBind,
    pub value: VarBind,
}
