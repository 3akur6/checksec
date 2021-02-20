mod elf;

use clap::{App, Arg};
use colored::*;
use goblin::Object;
use std::fs;
use std::path::Path;
use std::process::{exit, Command};
use std::str;

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

fn checksec(name: &str) {
    use crate::elf::CheckSecResults;

    let output = Command::new("which")
        .arg(name)
        .output()
        .unwrap_or_else(|err| {
            eprintln!("{}", err);
            exit(1);
        });

    if !output.status.success() {
        eprintln!("`{}` not found", name);
        exit(1);
    }

    let which = str::from_utf8(&output.stdout)
        .unwrap_or_else(|err| {
            eprintln!("{}", err);
            exit(1);
        })
        .trim();
    let path = Path::new(which);
    let file = fs::read(path).unwrap_or_else(|err| {
        eprintln!("{}", err);
        exit(1);
    });

    match Object::parse(&file) {
        Ok(obj) => {
            println!("[{}] '{}'", "*".blue().bold(), path.display());
            match obj {
                Object::Elf(elf) => {
                    let checksec = CheckSecResults::parse(&elf);
                    println!("{}", checksec);
                }
                Object::PE(pe) => println!("pe: {:?}", pe),
                Object::Mach(mach) => println!("mach: {:?}", mach),
                Object::Archive(archive) => println!("archive: {:?}", &archive),
                Object::Unknown(magic) => println!("unknown magic: {:?}", magic),
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        }
    }
}
