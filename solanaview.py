import os
import pathlib
from lief.ELF import Relocation
from binaryninja import BinaryView, SegmentFlag, SectionSemantics, Symbol, SymbolType, Platform, BackgroundTaskThread, execute_on_main_thread
import binaryninja as bn
import lief
from .idl_utils import fetch_idl_anchorpy
import rust_demangler  # Import rust_demangle for demangling
import re
import html
import time
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtWidgets import QTextEdit, QVBoxLayout
from binaryninjaui import (
    SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler,
    SidebarWidgetLocation, SidebarContextSensitivity
)
from pygments import highlight
from pygments.lexers import RustLexer
from pygments.formatters import HtmlFormatter
import asyncio, json, os
from anthropic import Anthropic
import asyncio, json
from typing import Any, Dict
from anthropic import RateLimitError, APIStatusError
from fastmcp import exceptions as mcp_exc
from tenacity import retry, wait_exponential_jitter, stop_after_attempt, wait_random_exponential
import sys, os

from .sidebar_ui import *

# binja screws up stdout and stderr, fastmcp doesnt like that
def _safe_fd():
    return getattr(_safe_fd, "fd", os.open(os.devnull, os.O_RDWR))

for stream_name in ("stdout", "stderr"):
    stream = getattr(sys, stream_name, None)
    if stream is not None and not hasattr(stream, "fileno"):
        stream.fileno = _safe_fd  


from fastmcp.client import Client
from fastmcp.client.transports import PythonStdioTransport

# were sure to have an entry func, and we find the id in the first memcmp
def find_entry_memcmp_second_arg(bv):
    for function in bv.functions:
        if function.name.endswith("entry"):
            # Get the HLIL
            hlil = function.hlil

            print(hlil)
            
            for block in hlil:
                for instruction in block:
                    memcmp_call = find_memcmp_call(instruction)
                    if(memcmp_call == None):
                        continue

                    return bv.read(memcmp_call.params[1].constant, 32)
    
    return None

def find_memcmp_call(instruction):
    # Check if instruction is a call
    if instruction.operation == bn.HighLevelILOperation.HLIL_CALL:
        if instruction.dest.operation == bn.HighLevelILOperation.HLIL_CONST_PTR:
            target_func = instruction.dest.constant
            target_name = instruction.function.view.get_function_at(target_func)
            if target_name and target_name.name == "memcmp":
                return instruction
            
    # Recursively check child expressions
    for operand in instruction.operands:
        if isinstance(operand, bn.highlevelil.HighLevelILInstruction):
            result = find_memcmp_call(operand)
            if result:
                return result
    
    return None

FUNCTION_SIGS = {
    'abort': 'void abort() __noreturn',
    'sol_panic_': 'void sol_panic_(const char *file_str, int file_str_len, int line, int col) __noreturn',
    'sol_log_': 'void sol_log_(const char *message, int size)',
    'sol_log_64_': 'void sol_log_64_(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);',
    'sol_log_compute_units_': 'void sol_log_compute_units_();',
    'sol_log_pubkey': 'void sol_log_pubkey(SolPubkey *pk);',
    'sol_create_program_address': 'uint64_t sol_create_program_address(const SolSignerSeed *seeds, int num_seeds, const SolPubkey *program_id, SolPubkey *out);',
    'sol_try_find_program_address': 'uint64_t sol_try_find_program_address(const SolSignerSeed *seeds, int num_seeds, const SolPubkey *program_id, SolPubkey *out, uint8_t *out_bump);',
    'sol_sha256': 'uint64_t sol_sha256(const SolBytes *bytes, int bytes_len, uint8_t *result);',
    'sol_keccak256': 'uint64_t sol_keccak256(const SolBytes *bytes, int bytes_len, uint8_t *result);',
    'sol_secp256k1_recover': 'uint64_t sol_secp256k1_recover(const uint8_t *hash, uint64_t recovery_id, const uint8_t *signature, uint8_t *result);',
    'sol_get_clock_sysvar': 'uint64_t sol_get_clock_sysvar(uint8_t *out);',
    'sol_get_epoch_schedule_sysvar': 'uint64_t sol_get_epoch_schedule_sysvar(uint8_t *out);',
    'sol_get_rent_sysvar': 'uint64_t sol_get_rent_sysvar(uint8_t *out);',
    'sol_memcpy_': 'void sol_memcpy_(uint8_t *dst, uint8_t *src, int n);',
    'sol_memmove_': 'void sol_memmove_(uint8_t *dst, uint8_t *src, int n);',
    'sol_memcmp_': 'int sol_memcmp_(uint8_t *s1, uint8_t *s2, int n);',
    'sol_memset_': 'void sol_memset_(uint8_t *s, uint8_t c, int n);',
    'sol_invoke_signed_c': 'uint64_t sol_invoke_signed_c(const SolInstruction *instruction, const SolAccountInfo *accounts, int num_accounts, const SolSignerSeeds *signers, int num_signers);',
    'sol_invoke_signed_rust': 'void sol_invoke_signed_rust(void *instr, void *accounts, int num_accounts, void *seeds, int num_seeds)',
    'sol_set_return_data': 'void sol_set_return_data(const uint8_t *bytes, uint64_t bytes_len);',
    'sol_get_return_data': 'uint64_t sol_get_return_data(const uint8_t *bytes, uint64_t bytes_len, SolPubkey *program_id);',
    'sol_log_data': 'void sol_log_data(SolBytes *, uint64_t);',
    # 'sol_get_processed_sibling_instruction': '', # TODO
    'sol_get_stack_height': 'uint64_t sol_get_stack_height();',
}

STRING_POINTER_SYSCALLS = {
    'sol_log_', 
    'sol_panic_',
    'sol_log_pubkey',
    'sol_memcpy_',
    'sol_memmove_',
    'sol_memcmp_',
    'sol_memset_',
    'sol_set_return_data',
    'sol_get_return_data',
    'sol_log_data',
}

EXTERN_START = 0x1000
EXTERN_SIZE = 0x2000


class SolanaView(BinaryView):
    name = 'Solana'
    long_name = 'Solana'
    detected_id = None

    @classmethod
    def is_valid_for_data(self, data):
        # check for both ebpf and sbpf
        #print("ID: ", data.read(0x24fc7, 32))
        return data.read(0,4) == b'\x7fELF' and (data.read(0x12, 2) == b'\xf7\x00' or data.read(0x12, 2) == b'\x07\x01')

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Platform['Solana']
        self.data = data

        self.extern_data = [0] * EXTERN_SIZE
        self.idl = None
        # Keep track of syscalls for patching
        self.syscalls = {}

    def post_analysis(self):
        self.get_function_at(self.start).name = "entrypoint"
        # analyze the entry func
        for function in self.functions:
            if function.name.endswith("::entry") and "DebugList" not in function.name:
                print("AAAAAAA")
                self.idl = fetch_idl_anchorpy(self, function)


    def demangle_rust_symbol(self, mangled_name):
        """
        Demangle a Rust symbol name to make it more readable.
        """
        try:
            if mangled_name.startswith("_ZN"):
                #remove this
                # https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html#requirements-for-a-symbol-mangling-scheme
                # for readability
                demangled = "::".join(str(rust_demangler.demangle(mangled_name)).split("::")[0:-1])
                return demangled
            return mangled_name
        except Exception as e:
            print(f"Error demangling {mangled_name}: {e}")
            return mangled_name

    def perform_read(self, addr: int, length: int) -> bytes:
        # Override with custom extern data.
        if addr >= EXTERN_START and addr < EXTERN_START + EXTERN_SIZE:
            if addr + length > EXTERN_START + EXTERN_SIZE:
                return b''
            return bytes(self.extern_data[addr - EXTERN_START : addr + length - EXTERN_START])
        else:
            return super().perform_read(addr, length)

    def perform_write(self, addr: int, data: bytes) -> int:
        # Override with custom extern data.
        if addr >= EXTERN_START and addr < EXTERN_START + EXTERN_SIZE:
            self.extern_data[addr - EXTERN_START : addr + len(data) - EXTERN_START] = list(data)
            return len(data)
        else:
            return super().perform_write(addr, data)

    def load_types(self):
        plugin_root = pathlib.Path(os.path.realpath(__file__)).parent

        types = open(plugin_root / 'types.c', 'r').read()

        info = self.parse_types_from_string(types)

        for k in info.types:
            t = info.types[k]
            self.define_type(str(k), str(k), t)
    
    def perform_get_address_size(self):
        return 8

    
    def pointer_sweep(self, needle):
        needle_bytes = needle.to_bytes(8, 'little')   # 64-bit little-endian
        for s in self.segments:
            data = self.read(s.start, s.length)
            off = data.find(needle_bytes)
            while off != -1:
                ea = s.start + off
                print(f"Found {hex(needle)} at {hex(ea)}")
                self.add_user_data_ref(ea, needle)
                off = data.find(needle_bytes, off + 1)

    def init(self):
        print('init')

        self.load_types()

        data_copy = list(self.data[:])
        # Replace SBF with BPF in e_machine so that lief parses relocations properly
        E_MACHINE_LEN = 2
        E_MACHINE_SBF = list(0x107.to_bytes(E_MACHINE_LEN, 'little'))
        E_MACHINE_BPF = list(0x0f7.to_bytes(E_MACHINE_LEN, 'little'))
        E_MACHINE_OFFSET = 0x12
        E_MACHINE = slice(E_MACHINE_OFFSET, E_MACHINE_OFFSET + E_MACHINE_LEN)

        if data_copy[E_MACHINE] == E_MACHINE_SBF:
            data_copy[E_MACHINE] = E_MACHINE_BPF

        p = lief.parse(data_copy)
        
        # Add LOAD segments
        for s in p.segments:
            if s.type == lief.ELF.Segment.TYPE.LOAD:
                self.add_auto_segment((1 << 32) + s.virtual_address, s.virtual_size, s.physical_address, s.physical_size, int(s.flags))

        self.add_auto_segment(2 << 32, 0x8000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_auto_segment(3 << 32, 0x8000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_auto_segment(4 << 32, 0x8000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        
        self.add_user_section("stack", 2 << 32, 0x8000, SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_user_section("heap", 3 << 32, 0x8000, SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_user_section("input", 4 << 32, 0x8000, SectionSemantics.ReadWriteDataSectionSemantics)


        self.add_entry_point(self.start)

        # Special extern section with syscalls.
        self.add_auto_section('extern', EXTERN_START, EXTERN_SIZE, SectionSemantics.ReadOnlyCodeSectionSemantics)

        # Map extern symbols to index.
        extern_map = {}
        curr_extern = 0
        for s in p.symbols:
            if s.type == lief.ELF.Symbol.TYPE.NOTYPE and s.binding == lief.ELF.Symbol.BINDING.GLOBAL:
                # Skip duplicates
                if s.name in extern_map:
                    continue

                extern_map[s.name] = curr_extern

                pos = EXTERN_START + (curr_extern * 16)

                # Define symbol.
                self.define_auto_symbol(Symbol(
                    SymbolType.LibraryFunctionSymbol,
                    pos,
                    s.name
                ))

                self.add_function(pos, Platform['Solana'])
                self.write(pos, bytes([
                    0x85,0x10,0,0,0xff,0xff,0xff,0xff, # syscall marker
                    0x95,0,0,0,0,0,0,0 # exit
                ]))

                # define this to avoid binja mistaking it for the entrypoint
                self.define_auto_symbol(Symbol(
                    SymbolType.FunctionSymbol,
                    pos,
                    "extern_syscall"
                ))


                if s.name in FUNCTION_SIGS:
                    f = self.get_function_at(pos)
                    if f is not None:
                        f.type = FUNCTION_SIGS[s.name]

                curr_extern += 1

        for s in p.sections:
            if s.size != 0:
                self.add_user_section(s.name, (1 << 32) + s.offset, s.size, SectionSemantics.ReadOnlyCodeSectionSemantics)


        # Track syscall locations and types
        self.syscall_info = {}
        for name, idx in extern_map.items():
            pos = EXTERN_START + (idx * 16)
            self.syscall_info[name] = {
                'address': pos,
                'needs_pointer_adjustment': name in STRING_POINTER_SYSCALLS
            }

        # Apply relocations.
        for r in p.dynamic_relocations:
            addr = r.address + (1 << 32)

            try:
                if r.type == Relocation.TYPE.BPF_64_64:
                    lo = int.from_bytes(self.read(addr + 4, 4), 'little')
                    hi = int.from_bytes(self.read(addr + 12, 4), 'little')
                    v = (hi << 32) + lo

                    # if already relocated, bail
                    if v >= 0x100000000:
                        continue

                    v += (1 << 32)
                    lo = v & 0xffffffff
                    hi = v >> 32
                    self.write(addr + 4, lo.to_bytes(4, 'little'))
                    self.write(addr + 12, hi.to_bytes(4, 'little'))

                #32 bit reloc
                elif r.type == 1744830472:
                    print(hex(r.symbol.value), hex(r.address), r.type)
                    print(hex(int.from_bytes(self.read(0x10017e838 + 12, 4), 'little')), hex(int.from_bytes(self.read(0x10017e838 + 4, 4), 'little')))

                    self.pointer_sweep(r.address)

                    for ref in self.get_data_refs(r.address):
                        print("REF: ", ref, hex(r.address))
                        self.write(ref, self.read(r.address + (1<<32) + 4, 4))
                    
                elif r.type == Relocation.TYPE.BPF_64_32:
                    if r.symbol.is_function:
                        # BPF Function
                        target = r.symbol.value + (1 << 32)
                        off = (target - (addr + 8)) // 8
                        if off < 0:
                            off += 0x100000000
                        self.write(addr + 4, off.to_bytes(4, 'little'))
                    else:
                        # Syscall
                        name = r.symbol.name
                        if name in extern_map:
                            idx = extern_map[name]
                            pos = EXTERN_START + (idx * 16)
                            self.write(addr + 4, pos.to_bytes(4, 'little'))
                            self.write(addr + 1, bytes([2 << 4])) # Mark as absolute extern
                            
                            # Store syscall location for later patching
                            self.syscalls[addr] = {
                                'name': name,
                                'needs_pointer_adjustment': name in STRING_POINTER_SYSCALLS
                            }
                        else:
                            print('Unhandled syscall: ', name)
            except Exception as e:
                print('Unhandled relocation type: ', r)

        # Apply function symbols with demangling
        for s in p.symbols:
            if s.is_function:
                demangled_name = self.demangle_rust_symbol(s.name)
                
                self.define_auto_symbol(Symbol(
                    SymbolType.FunctionSymbol,
                    s.value + (1 << 32),
                    demangled_name
                ))

            

        self.fix_all_pointers()
       
        self.add_analysis_completion_event(self.post_analysis)

        return True

    def fix_all_pointers(self):
        """
        Scan through all code and fix any potential pointers that are below 0x100000000
        by adding the program base offset (1 << 32).
        """
        prog_base = 1 << 32
        total_fixed = 0
        
        for segment in self.segments:
            # Skip the extern segment
            if segment.start == EXTERN_START:
                continue
                
            start = segment.start
            end = segment.end
            
            print(f"Scanning segment: 0x{start:x} - 0x{end:x}")
            
            addr = start
            while addr < end - 16:  # Need at least 2 instructions (16 bytes)
                instr = self.read(addr, 8)
                
                #if its a load
                if instr[0] & 0xFF == 0x18:
                    # Get the current immediate value
                    imm_lo = int.from_bytes(self.read(addr + 4, 4), 'little')
                    
                    next_instr = self.read(addr + 8, 8)
                    imm_hi = int.from_bytes(self.read(addr + 12, 4), 'little')
                    
                    full_imm = (imm_hi << 32) | imm_lo
                    
                    #if unrelocated
                    if 0 < full_imm < (1 << 32):
                        new_imm = full_imm + prog_base
                        new_imm_lo = new_imm & 0xFFFFFFFF
                        new_imm_hi = new_imm >> 32
                        
                        # Update the instructions
                        self.write(addr + 4, new_imm_lo.to_bytes(4, 'little'))
                        self.write(addr + 12, new_imm_hi.to_bytes(4, 'little'))
                        
                        print(f"Fixed potential pointer at 0x{addr:x}: 0x{full_imm:x} -> 0x{new_imm:x}")
                        total_fixed += 1
                
                addr += 8  # next instr
        
        print(f"Total pointers fixed: {total_fixed}")


