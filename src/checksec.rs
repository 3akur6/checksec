use colored::*;
use goblin::elf::Elf;
use goblin::Object;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

use crate::elf::{Properties, Relro, PIE};

pub struct CheckSecResults {
    arch: String,
    relro: Relro,
    canary: bool,
    nx: bool,
    pie: PIE,
    fortify: bool,
    address: u64,
    rwx_segments: bool,
}

impl CheckSecResults {
    pub fn parse(elf: &Elf) -> Self {
        CheckSecResults {
            arch: elf.arch(),
            relro: elf.has_relro(),
            canary: elf.has_canary(),
            nx: elf.has_nx(),
            pie: elf.has_pie(),
            fortify: elf.has_fortify(),
            address: elf.address(),
            rwx_segments: elf.has_rwx_segments(),
        }
    }
}

impl fmt::Display for CheckSecResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let padding = "    ";
        writeln!(f, "{}{:<10}{}", padding, "Arch:", self.arch)?;
        writeln!(
            f,
            "{}{:<10}{}",
            padding,
            "RELRO:",
            match self.relro {
                Relro::None => "No RELRO".red(),
                Relro::Partial => "Partial RELRO".yellow(),
                Relro::Full => "Full RELRO".green(),
            }
        )?;
        writeln!(
            f,
            "{}{:<10}{}",
            padding,
            "Stack:",
            match self.canary {
                true => "Canary found".green(),
                false => "No canary found".red(),
            }
        )?;
        writeln!(
            f,
            "{}{:<10}{}",
            padding,
            "NX:",
            match self.nx {
                true => "NX enabled".green(),
                false => "NX disabled".red(),
            }
        )?;
        write!(
            f,
            "{}{:<10}{}",
            padding,
            "PIE:",
            match self.pie {
                PIE::PIE | PIE::DSO => "PIE enabled".to_string().green(),
                _ => {
                    format!("No PIE ({:#x})", self.address).red()
                }
            }
        )?;

        if self.fortify {
            writeln!(f)?;
            write!(f, "{}{:<10}{}", padding, "FORTIFY:", "Enabled".green())?;
        }

        if self.rwx_segments {
            writeln!(f)?;
            write!(f, "{}{:<10}{}", padding, "RWX:", "Has RWX segments".red())?;
        }
        Ok(())
    }
}

pub fn checksec(path: &Path) -> Result<(), Box<dyn Error>> {
    let file = fs::read(path)?;

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
            Ok(())
        }
        Err(err) => Err(Box::new(err)),
    }
}
