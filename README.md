## checksec

mini binary checksec written in Rust, referring to [checksec.rs](https://github.com/etke/checksec.rs) and [checksec.sh](https://github.com/slimm609/checksec.sh)

with the same colorful output compared to [pwntools/checksec](https://github.com/Gallopsled/pwntools) I mostly used before, which implements in Python, but much faster than it

Usage
-----
```
USAGE:
    checksec [OPTIONS] [--] [elf]...

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --file <elf>...    File to check (for compatibility with checksec.sh)

ARGS:
    <elf>...    Files to check
```
Examples
--------
binary from specified (relative or absolute) path
```zsh
$ ls
start

$ checksec start               # sample from https://pwnable.tw/challenge/#1
[*] '/root/pwn/start'
    Arch:     386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```
multiple binaries checking
```zsh
$ checksec start star b0verflow
[*] '/root/pwn/start'
    Arch:     386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
'star': No such file or directory (os error 2) # wrong spelling, output redirect to stderr
[*] '/root/pwn/b0verfl0w'      # sample from 'X-CTF Quals 2016 - b0verfl0w'
    Arch:     386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```