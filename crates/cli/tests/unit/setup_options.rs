use clap::Parser;

use super::SetupArgs;
use crate::commands::{Cli, Command};

#[test]
fn library_defaults_match_clap_defaults() {
    let cli = Cli::try_parse_from(["xark", "setup"]).unwrap();
    let Command::Setup(parsed) = cli.command else {
        panic!("expected setup command");
    };
    assert_eq!(SetupArgs::default(), parsed);
}
