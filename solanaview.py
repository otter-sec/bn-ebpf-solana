
import os
import pathlib

from lief.ELF import Relocation

from binaryninja import BinaryView, Architecture, SegmentFlag, SectionSemantics, Symbol, SymbolType, Platform
import lief


FUNCTION_SIGS = {
    'abort': 'void abort() __noreturn',
    'sol_panic_': 'void sol_panic_(const char *file_str, int file_str_len, int line, int col) __noreturn',
    'sol_log_': 'void sol_log_(char *message, int size)',
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

EXTERN_START = 0x1000
EXTERN_SIZE = 0x2000

class SolanaView(BinaryView):
    name = 'Solana'
    long_name = 'Solana'

    @classmethod
    def is_valid_for_data(self, data):
        return data.read(0,4) == b'\x7fELF' and data.read(0x12, 2) == b'\xf7\x00'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Platform['Solana']
        self.data = data

        self.extern_data = [0] * EXTERN_SIZE

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

    def init(self):
        print('init')

        self.load_types()

        p = lief.ELF.parse(list(self.data[:]))
        
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

        # Special extern section with syscalls.
        # self.add_auto_segment(EXTERN_START, EXTERN_SIZE, 0, EXTERN_SIZE, SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable)
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

                if s.name in FUNCTION_SIGS:
                    f = self.get_function_at(pos)
                    if f is not None:
                        f.type = FUNCTION_SIGS[s.name]

                curr_extern += 1

        for s in p.sections:
            if s.size != 0:
                self.add_user_section(s.name, (1 << 32) + s.offset, s.size, SectionSemantics.ReadOnlyCodeSectionSemantics)

        # Apply relocations.
        for r in p.dynamic_relocations:
            addr = r.address + (1 << 32)

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
                        print('syscall @ ', hex(addr))
                    else:
                        print('Unhandled syscall: ', name)
            else:
                print('Unhandled relocation type: ', r)

        # Apply function symbols.
        for s in p.symbols:
            if s.is_function:
                # BPF Function
                self.define_auto_symbol(Symbol(
                    SymbolType.FunctionSymbol,
                    s.value + (1 << 32),
                    s.name
                ))

        return True
