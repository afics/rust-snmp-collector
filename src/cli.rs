use clap::{crate_authors, crate_version, AppSettings, Clap};

#[derive(Clap, Debug, PartialEq)]
pub enum Command {
    /// Verifies if the configuration can be parsed without errors
    ConfigTest,
    /// Loads the configuration and checks if all required MIBs are available
    MibTest,
    /// Performs both config-test and mib-test
    PreflightCheck,
    /// Do the thing!
    Run,
}

#[derive(Clap, Debug)]
#[clap(
    version = crate_version!(),
    author = crate_authors!(", "),
    global_setting = AppSettings::ColoredHelp,
    global_setting = AppSettings::InferSubcommands,
    global_setting = AppSettings::PropagateVersion,
)]
pub struct Opts {
    /// Provide a path to the configuration file
    #[clap(
        short,
        long,
        value_name = "FILE",
        default_value = "/etc/rust-snmp-collector/config.d"
    )]
    pub config: String,
    #[clap(subcommand)]
    pub command: Command,
}