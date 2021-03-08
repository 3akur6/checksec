mod checksec;
mod elf;

use crate::checksec::checksec;
use clap::{App, Arg};
use std::process::exit;

fn main() {
    let matches = App::new("CheckSec")
        .author("3akur6 <github.com/3akur6>")
        .arg(
            Arg::with_name("files")
                .help("Files to check")
                .multiple(true)
                .value_name("elf"),
        )
        .arg(
            Arg::with_name("ex_files")
                .long("file")
                .value_name("elf")
                .multiple(true)
                .help("File to check (for compatibility with checksec.sh)")
                .takes_value(true),
        )
        .get_matches();

    let files = if matches.is_present("ex_files") {
        matches.values_of("ex_files")
    } else {
        matches.values_of("files")
    };

    let file_names = files.unwrap_or_else(|| {
        println!("{}", matches.usage());
        exit(1);
    });

    for name in file_names {
        checksec(name);
    }
}
