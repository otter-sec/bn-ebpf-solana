# bn-ebpf-solana (v1.0.2)
Author: **OtterSec LLC**

_An architecture/binaryview plugin for Solana EBPF._

## Description:

See our [introductory blog post](https://osec.io/blog/tutorials/2022-08-27-reverse-engineering-solana/). **Instruction lifting!** ![](/assets/lift.png) **Solana SDK Structures!** ![](/assets/struct.png) ## Features - **Instruction Lifting**: All EBPF instructions are lifted to LLIL - **Accurate Memory Maps**: We implement Solana-specific memory maps (0x{1/2/3/4}00000000 addresses for data/stack/heap/input) - **Solana ELF Relocations**: Solana-specific ELF relocations - **Syscall Function Signatures**: Full signatures for all of the Solana syscalls - **(partial) Solana SDK Types**: Type definitions for all Solana SDK objects. (fully complete for C, in-progress for Rust)


## Installation Instructions

### Darwin



### Windows



### Linux



## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 3164



## Required Dependencies

The following dependencies are required for this plugin:

 * pip - lief


## License

This plugin is released under a MIT license.
## Metadata Version

2
