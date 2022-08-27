
# bn-ebpf-solana

A pure-python Binary Ninja plugin for Solana EBPF.

See our [introductory blog post](https://osec.io/blog/tutorials/2022-08-27-reverse-engineering-solana/).

**Instruction lifting!**
![](/assets/lift.png)

**Solana SDK Structures!**
![](/assets/struct.png)

## Installation

Requirements:
```
pip install lief
```

Copy this directory into your Binary Ninja plugins folder and restart.

## Features

- **Instruction Lifting**: All EBPF instructions are lifted to LLIL
- **Accurate Memory Maps**: We implement Solana-specific memory maps (0x{1/2/3/4}00000000 addresses for data/stack/heap/input)
- **Solana ELF Relocations**: Solana-specific ELF relocations
- **Syscall Function Signatures**: Full signatures for all of the Solana syscalls
- **(partial) Solana SDK Types**: Type definitions for all Solana SDK objects. (fully complete for C, in-progress for Rust)

_TODO:_

- **Solana SDK Signature Matching**: Automatically match common Solana SDK functions.

