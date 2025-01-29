
# bn-ebpf-solana

A pure-python Binary Ninja plugin for Solana EBPF.

## Installation

Clone this [repo](https://github.com/otter-sec/bn-ebpf-solana) in your Binja `plugins` folder, located in the [user folder](https://docs.binary.ninja/guide/index.html#user-folder).

Now install the requirements :
- either by running `Install python3 module` in Binja's `command palette` (Ctrl + P) and install `lief`
- or by going to the [user folder](https://docs.binary.ninja/guide/index.html#user-folder) and installing `lief` within the `venv` enviroment using:

```
pip install lief
```

Currently tested on `lief@0.16.2-d4900dab`

See our [introductory blog post](https://osec.io/blog/tutorials/2022-08-27-reverse-engineering-solana/).

**Instruction lifting!**
![](/assets/lift.png)

**Solana SDK Structures!**
![](/assets/struct.png)



Copy this directory into your Binary Ninja plugins folder and restart.

## Features

- **Instruction Lifting**: All EBPF instructions are lifted to LLIL
- **Accurate Memory Maps**: We implement Solana-specific memory maps (0x{1/2/3/4}00000000 addresses for data/stack/heap/input)
- **Solana ELF Relocations**: Solana-specific ELF relocations
- **Syscall Function Signatures**: Full signatures for all of the Solana syscalls
- **(partial) Solana SDK Types**: Type definitions for all Solana SDK objects. (fully complete for C, in-progress for Rust)

_TODO:_

- **Solana SDK Signature Matching**: Automatically match common Solana SDK functions.

## Debugging

```
[ScriptingProvider] ModuleNotFoundError: No module named 'lief'
```

Is `lief` installed?

Run the following in the Binja python console

```python
import lief
lief.__version__
```

If you get an error, refer to the **Installation** section

