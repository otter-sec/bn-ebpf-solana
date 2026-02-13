from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo

from .instr import decode, tT

REGS = [f'r{i}' for i in range(16)]

class EBPF(Architecture):
    name = 'ebpf'
    address_size = 8
    max_instr_length = 16

    regs = { r:RegisterInfo(r, 8) for r in REGS }
    stack_pointer = 'r10'

    def get_instruction_info(self, data, addr):
        instr = decode(data, addr)

        if instr is None:
            return InstructionInfo(length=8)

        return instr.info

    def get_instruction_text(self, data, addr):
        instr = decode(data, addr)

        if instr is None:
            return [tT('unk')], 8

        return instr.text, instr.info.length

    def get_instruction_low_level_il(self, data, addr, il):
        instr = decode(data, addr)

        if instr is None:
            return 8

        instr.llil(il)
        return instr.info.length
