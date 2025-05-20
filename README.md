# bn-ebpf-solana

A pure-python Binary Ninja plugin for Solana EBPF.

## Manual installation (advanced, latest features including MCP)

This is only needed if you wish to tinker with the plugin to modify it.

Clone this [repo](https://github.com/otter-sec/bn-ebpf-solana) in your Binja `plugins` folder, located in the [user folder](https://docs.binary.ninja/guide/index.html#user-folder).

Now install the requirements :
- either by running `Install python3 module` in Binja's `command palette` (Ctrl + P) and install the following modules

```
lief
anthropic
fastmcp
tenacity
rust_demangler  
pygments  
anchorpy  
solana  
solders
```

- or by going to the [user folder](https://docs.binary.ninja/guide/index.html#user-folder) and installing the requirements.txt

Also for the MCP integration to work please install `mcp` globally (outside the binja venv) like so:

```
pip install mcp
```

Make sure to also install [the MCP server](https://github.com/fosdickio/binary_ninja_mcp) using the same procedure by cloning from GitHub.

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

### MCP integration

In order to use the MCP integration please set up your anthropic api key in the settings under

```
MCP settings > Anthropic API Key
```

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
