use clap::{crate_authors, crate_version, Parser};

#[derive(Parser, Debug, PartialEq)]
pub enum Command {
    /// Verifies if the configuration can be parsed without errors
    ConfigTest,
    /// Loads the configuration and checks if all required MIBs are available
    MibTest,
    /// Performs both config-test and mib-test
    PreflightCheck,
    /// Display output keys
    ShowOutputKeys,
    /// Do the thing!
    Run,
}

#[derive(Parser, Debug)]
#[clap(
    version = crate_version!(),
    author = crate_authors!(", "),
    infer_subcommands = true,
    propagate_version = true,
)]
pub struct Opts {
    /// Provide a path to the configuration file
    #[clap(short, long, value_name = "FILE")]
    pub config: Option<String>,

    /// Provide a path to a configuration directory. Note: -c and -foo are mutually exclusive
    #[clap(short = 'd', long, value_name = "DIRECTORY", conflicts_with = "config")]
    pub config_dir: Option<String>,
    #[clap(subcommand)]
    pub command: Command,
}
