# bn-ebpf-solana

A pure-python Binary Ninja plugin for Solana EBPF.

## Regular install from plugin manager

Be sure to install both `bn-ebpf-solana` and `binary_ninja_mcp` from the plugin manager

Tested on Binary Ninja `5.0.7486-Stable`

## Manual installation (advanced, latest features)

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


See our [introductory blog post](https://osec.io/blog/tutorials/2022-08-27-reverse-engineering-solana/).

**Instruction lifting!**
![](https://github.com/otter-sec/bn-ebpf-solana/blob/master/assets/lift.png?raw=true)

**Solana SDK Structures!**
![](https://github.com/otter-sec/bn-ebpf-solana/blob/master/assets/struct.png?raw=true)

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

You will now be able to use the side menu on the right, symbolized by an R. 
Click on any function to start prompting the model to call MCP actions, and to ultimately display a Rust version in the side panel

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
