use std::io::prelude::*;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Error;
use crossbeam_channel::{Receiver, Sender};
use log::{debug, info, trace, warn};
use size_format::SizeFormatterSI;

use crate::config::Output;

#[derive(Debug)]
pub struct CarbonMetricValue {
    pub timestamp: SystemTime,
    pub metric: String,
    pub value: String,
}

pub fn carbon_send_safe(
    output: Output,
    channel_sender: Sender<CarbonMetricValue>,
    channel_receiver: Receiver<CarbonMetricValue>,
) {
    let backoff = Duration::from_secs(1);

    loop {
        let sender = carbon_send(
            output.clone(),
            channel_sender.clone(),
            channel_receiver.clone(),
        );
        if let Err(error) = sender {
            let (carbon_server, carbon_port) = match &output {
                Output::CarbonOutput {
                    prefix: _,
                    graphite_server,
                    graphite_port,
                } => (graphite_server, graphite_port),
            };
            let carbon_host = format!("{}:{}", carbon_server, carbon_port);

            let queue_len = channel_receiver.len();
            let memory_consumed =
                std::mem::size_of::<CarbonMetricValue>() as u64 * queue_len as u64;
            warn!(
                "carbon_send_safe({}): error {:?}; buffering {} metric values, using {} memory; backing off for {:?}",
                carbon_host, error, queue_len, SizeFormatterSI::new(memory_consumed), backoff
            );
            thread::sleep(backoff);
            info!(
                "carbon_send_safe({}): backoff {:?} done, retrying...",
                carbon_host, backoff
            );
        }
    }
}

pub fn carbon_send(
    output: Output,
    channel_sender: Sender<CarbonMetricValue>,
    channel_receiver: Receiver<CarbonMetricValue>,
) -> Result<(), Error> {
    // set up output
    let (prefix, carbon_server, carbon_port) = match output {
        Output::CarbonOutput {
            prefix,
            graphite_server,
            graphite_port,
        } => (prefix, graphite_server, graphite_port),
    };

    let carbon_host = format!("{}:{}", carbon_server, carbon_port);

    let mut stream = TcpStream::connect(carbon_host)?;

    loop {
        let metricval = channel_receiver.recv().unwrap();

        let buf = format_carbon(
            &prefix,
            &metricval.metric,
            &metricval.value,
            &metricval.timestamp,
        );

        trace!("carbon_send: sending '{}'", buf);

        let write = stream.write(&[buf.as_bytes(), &[b'\n']].concat());
        if let Err(error) = write {
            debug!(
                "carbon_send: error {:?} while sending '{}', reinjecting into channel",
                error, buf
            );
            channel_sender.send(metricval).unwrap();

            return Err(error.into());
        }
    }
}

pub fn sanitize_carbon(s: &str) -> String {
    s.replace('-', "_").replace('.', "__").replace('/', "_")
}

pub fn format_key(device_name: &str, variable_part: &str, metric_name: &str) -> String {
    format!(
        "{}.{}.{}",
        sanitize_carbon(device_name),
        sanitize_carbon(variable_part),
        metric_name
    )
}

pub fn format_carbon(prefix: &str, metric: &str, value: &str, timestamp: &SystemTime) -> String {
    format!(
        "{}.{} {} {}",
        prefix,
        metric,
        value,
        timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    )
}
