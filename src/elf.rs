use colored::*;
use goblin::elf::Elf;
use goblin::elf::{dynamic, header, program_header};
use std::fmt;

pub enum Relro {
    None,
    Partial,
    Full,
}

#[derive(Debug)]
pub enum PIE {
    None,
    PIE,
    DSO,
    REL,
}

pub trait Properties {
    fn arch(&self) -> String;
    fn address(&self) -> u64;
    fn has_relro(&self) -> Relro;
    fn has_canary(&self) -> bool;
    fn has_nx(&self) -> bool;
    fn has_pie(&self) -> PIE;
    fn has_fortify(&self) -> bool;
}

impl Properties for Elf<'_> {
    fn arch(&self) -> String {
        use header::EI_CLASS;

        let machine = header::machine_to_str(self.header.e_machine);
        let file_class = &header::class_to_str(self.header.e_ident[EI_CLASS]).replace("ELF", "");
        let endian = if self.little_endian { "little" } else { "big" };

        vec![machine, file_class, endian].join("-")
    }

    fn address(&self) -> u64 {
        let mut addr = 0;
        if self.header.e_type != header::ET_DYN {
            for header in &self.program_headers {
                if header.p_type == program_header::PT_LOAD && (header.p_vaddr < addr || addr == 0)
                {
                    addr = header.p_vaddr;
                }
            }
        }
        addr
    }

    fn has_relro(&self) -> Relro {
        use Relro::{Full, None, Partial};

        let mut flag = false;
        for header in &self.program_headers {
            if header.p_type == program_header::PT_GNU_RELRO {
                flag = true;
                if let Some(dynamic) = &self.dynamic {
                    for d in &dynamic.dyns {
                        match d.d_tag {
                            dynamic::DT_BIND_NOW => return Full,
                            dynamic::DT_FLAGS => {
                                let flags = d.d_val;
                                if flags & dynamic::DF_BIND_NOW != 0 {
                                    return Full;
                                }
                            }
                            dynamic::DT_FLAGS_1 => {
                                let flags_1 = d.d_val;
                                if flags_1 & dynamic::DF_1_NOW != 0 {
                                    return Full;
                                }
                            }
                            _ => continue,
                        }
                    }
                }
            }
        }
        if flag {
            Partial
        } else {
            None
        }
    }

    fn has_canary(&self) -> bool {
        if let Ok(vec) = self.dynstrtab.to_vec() {
            vec.iter()
                .any(|&ds| ds == "__stack_chk_fail" || ds == "__intel_security_cookie")
        } else {
            false
        }
    }

    fn has_nx(&self) -> bool {
        use program_header::{PF_R, PF_W, PF_X, PT_GNU_STACK};
        for p_header in &self.program_headers {
            if p_header.p_type == PT_GNU_STACK {
                if p_header.p_flags == (PF_R + PF_W + PF_X) {
                    return false;
                } else {
                    return true;
                }
            }
        }
        false
    }

    fn has_pie(&self) -> PIE {
        use dynamic::DF_1_PIE;
        use header::{ET_DYN, ET_EXEC, ET_REL};

        match self.header.e_type {
            ET_EXEC => PIE::None,
            ET_REL => PIE::REL,
            ET_DYN => {
                if let Some(dynamic) = &self.dynamic {
                    if dynamic.info.flags_1 & DF_1_PIE == DF_1_PIE {
                        return PIE::PIE;
                    }
                }
                PIE::DSO
            }
            _ => PIE::None,
        }
    }

    fn has_fortify(&self) -> bool {
        if let Ok(vec) = self.dynstrtab.to_vec() {
            vec.iter().any(|ds| ds.ends_with("_chk"))
        } else {
            false
        }
    }
}

pub struct CheckSecResults {
    pub arch: String,
    pub relro: Relro,
    pub canary: bool,
    pub nx: bool,
    pub pie: PIE,
    pub fortify: bool,
    address: u64,
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
            writeln!(f, "")?;
            write!(f, "{}{:<10}{}", padding, "FORTIFY:", "Enabled".green())?;
        }
        Ok(())
    }
}
