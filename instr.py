
from typing import Callable, List
from dataclasses import dataclass
from binaryninja.function import InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninja.lowlevelil import LowLevelILLabel, LowLevelILFunction

# binary ninja text helpers
def tI(x): return InstructionTextToken(InstructionTextTokenType.InstructionToken, x)
def tR(x): return InstructionTextToken(InstructionTextTokenType.RegisterToken, x)
def tS(x): return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, x)
def tM(x): return InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, x)
def tE(x): return InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, x)
def tA(x,d): return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, x, d)
def tT(x): return InstructionTextToken(InstructionTextTokenType.TextToken, x)
def tN(x,d): return InstructionTextToken(InstructionTextTokenType.IntegerToken, x, d)


def il_jump(il: LowLevelILFunction, target):
    label = il.get_label_for_address(il.arch, target)
    if label is None:
        il.append(il.jump(il.const(8, target)))
    else:
        il.append(il.goto(label))


def il_cond_branch(il: LowLevelILFunction, cond, tdest, fdest):
    t_target = il.get_label_for_address(il.arch, tdest)
    f_target = il.get_label_for_address(il.arch, fdest)

    needs_t = False
    needs_f = False

    if t_target is None:
        needs_t = True
        t_target = LowLevelILLabel()

    if f_target is None:
        needs_f = True
        f_target = LowLevelILLabel()

    il.append(il.if_expr(cond, t_target, f_target))

    if needs_t:
        il.mark_label(t_target)
        il.append(il.jump(tdest))

    if needs_f:
        il.mark_label(f_target)


@dataclass
class Instruction(object):
    text: List[InstructionTextToken]
    info: InstructionInfo
    llil: Callable[[LowLevelILFunction], None]


SZ_MAP = {
    0: 4,
    1: 2,
    2: 1,
    3: 8
}

SZ_NAME = {
    0: 'w',
    1: 'h',
    2: 'b',
    3: 'dw'
}


def lddw(dst, imm):
    return Instruction(
        text=[
            tI(f'lddw'), tT(' '), tR(f'r{dst}'), tT(', '), tN(hex(signed(64, imm)), signed(64, imm))
        ],
        info=InstructionInfo(length=16),
        llil=lambda il: il.append(
            il.set_reg(8, f'r{dst}',
                il.const(8, imm)
            )
        )
    )


def ld(ldop, dst, src, imm):
    pass


def ldx(dst, src, off, sz):
    soff = signed(16, off)

    inner = lambda il: il.load(SZ_MAP[sz],
        il.add(8,
            il.reg(8, f'r{src}'),
            il.sign_extend(8, il.const(2, off))
        )
    )

    ext = lambda il: il.zero_extend(8, inner(il)) if SZ_MAP[sz] != 8 else inner(il)

    return Instruction(
        text=[
            tI(f'ldx{SZ_NAME[sz]}'), tT(' '), tR(f'r{dst}'), tT(', '),
            tM('['), tR(f'r{src}'), (tS('+') if soff > 0 else tS('-')), tN(str(abs(soff)), abs(soff)), tE(']')
        ],
        info=InstructionInfo(length=8),
        llil=lambda il: il.append(
            il.set_reg(8, f'r{dst}', ext(il))
        )
    )


def st(dst, off, imm, sz):
    tr_imm = imm & ((1 << (SZ_MAP[sz])) - 1)
    soff = signed(16, off)
    return Instruction(
        text=[
            tI(f'st{SZ_NAME[sz]}'), tT(' '),
            tM('['), tR(f'r{dst}'), (tS('+') if soff > 0 else tS('-')), tN(str(abs(soff)), abs(soff)), tE(']'),
            tT(', '), tN(hex(imm), imm)
        ],
        info=InstructionInfo(length=8),
        llil=lambda il: il.append(
            il.store(
                SZ_MAP[sz],
                il.add(8,
                    il.reg(8, f'r{dst}'),
                    il.sign_extend(8, il.const(2, off))
                ),
                il.const(SZ_MAP[sz], tr_imm)
            )
        )
    )


def stx(dst, src, off, sz):
    soff = signed(16, off)
    r = lambda il: il.reg(8, f'r{src}')
    v = lambda il: il.low_part(SZ_MAP[sz], r(il)) if SZ_MAP[sz] != 8 else r(il)
    return Instruction(
        text=[
            tI(f'stx{SZ_NAME[sz]}'), tT(' '),
            tM('['), tR(f'r{dst}'), (tS('+') if soff > 0 else tS('-')), tN(str(abs(soff)), abs(soff)), tE(']'),
            tT(', '), tR(f'r{src}')
        ],
        info=InstructionInfo(length=8),
        llil=lambda il: il.append(
            il.store(
                SZ_MAP[sz],
                il.add(8,
                    il.reg(8, f'r{dst}'),
                    il.sign_extend(8, il.const(2, off))
                ),
                v(il)
            )
        )
    )


ALU_OPS = {
    0: ['add', lambda il,a,b,z: il.add(z,a,b)],
    1: ['sub', lambda il,a,b,z: il.sub(z,a,b)],
    2: ['mul', lambda il,a,b,z: il.mult(z,a,b)],
    3: ['div', lambda il,a,b,z: il.div_unsigned(z,a,b)],
    4: ['or', lambda il,a,b,z: il.or_expr(z,a,b)],
    5: ['and', lambda il,a,b,z: il.and_expr(z,a,b)],
    6: ['lsh', lambda il,a,b,z: il.shift_left(z,a,b)],
    7: ['rsh', lambda il,a,b,z: il.logical_shift_right(z,a,b)],
    8: ['neg', lambda il,a,b,z: il.not_expr(z,b)],
    9: ['mod', lambda il,a,b,z: il.mod_unsigned(z,a,b)],
    0xa: ['xor', lambda il,a,b,z: il.xor_expr(z,a,b)],
    0xb: ['mov', lambda il,a,b,z: b],
    0xc: ['arsh', lambda il,a,b,z: il.arith_shift_right(z,a,b)],
}


def signed(size, val):
    if (val >> (size - 1)) & 1:
        return val - (2**size)
    else:
        return val


def alu32(op, s, dst, src, imm) -> Instruction:
    if op in ALU_OPS:
        name, fn = ALU_OPS[op]
        return Instruction(
            text=[tI(name+"32"), tT(' '), tR(f'r{dst}'), tT(', '), (tR(f'r{src}') if s else tN(hex(signed(32, imm)), signed(32, imm)))],
            info=InstructionInfo(length=8),
            llil=lambda il: il.append(
                il.set_reg(
                    8,
                    f'r{dst}',
                    il.zero_extend(
                        8,
                        fn(
                            il,
                            il.reg(4, f'r{dst}'),
                            il.reg(4, f'r{src}') if s else il.const(4, imm),
                            4,
                        )
                    )
                )
            )
        )
    elif op == 0xd:  # bswap
        size = imm
        mask_expr = lambda il: il.const(8, (1 << (size * 8)) - 1)
        if s == 0:  # mask
            name = f'le{size}'
            fn = lambda il,a: il.and_expr(8,a,mask_expr(il))
        else:  # byte swap
            name = f'be{size}'
            byte_cnt = size // 8
            # Generate byte extract and shuffles
            extract = [
                lambda il,a,i=i:
                il.shift_left(8,
                    il.and_expr(8,
                        il.logical_shift_right(8, a, il.const(8, i * 8)),
                        il.const(8, 0xff)
                    ),
                    il.const(8, (byte_cnt - 1 - i) * 8)
                )
                for i in range(byte_cnt)
            ]
            # Join subexpressions into a chain
            fn = lambda il,a,e=extract: il.or_expr(8,e[0](il,a), e[1](il,a))
            for i in range(2,byte_cnt):
                fn = lambda il,a,e=extract,fn=fn,i=i: il.or_expr(8,fn(il,a), e[i](il,a))
        return Instruction(
            text=[tI(name), tT(' '), tR(f'r{dst}')],
            info=InstructionInfo(length=8),
            llil=lambda il: il.append(
                il.set_reg(
                    8,
                    f'r{dst}',
                    fn(
                        il,
                        il.reg(8, f'r{dst}'),
                    )
                )
            )
        )
    else:
        return None


def alu64(op, s, dst, src, imm) -> Instruction:
    if not op in ALU_OPS:
        return None

    name, fn = ALU_OPS[op]

    return Instruction(
        text=[tI(name), tT(' '), tR(f'r{dst}'), tT(', '), (tR(f'r{src}') if s else tN(hex(signed(32, imm)), signed(32, imm)))],
        info=InstructionInfo(length=8),
        llil=lambda il: il.append(
            il.set_reg(
                8,
                f'r{dst}',
                fn(
                    il,
                    il.reg(8, f'r{dst}'),
                    (il.reg(8, f'r{src}') if s else il.sign_extend(8, il.const(4, imm))),
                    8,
                )
            )
        )
    )


JUMP_COND = {
    1: ['jeq', lambda il,a,b: il.compare_equal(8,a,b)],
    2: ['jgt', lambda il,a,b: il.compare_unsigned_greater_than(8,a,b)],
    3: ['jge', lambda il,a,b: il.compare_unsigned_greater_equal(8,a,b)],
    4: ['jset', lambda il,a,b: il.compare_not_equal(8, il.const(8,0), il.and_expr(8,a,b))],
    5: ['jne', lambda il,a,b: il.compare_not_equal(8,a,b)],
    6: ['jsgt', lambda il,a,b: il.compare_signed_greater_than(8,a,b)],
    7: ['jsge', lambda il,a,b: il.compare_signed_greater_equal(8,a,b)],
    0xa: ['jlt', lambda il,a,b: il.compare_unsigned_less_than(8,a,b)],
    0xb: ['jle', lambda il,a,b: il.compare_unsigned_less_equal(8,a,b)],
    0xc: ['jslt', lambda il,a,b: il.compare_signed_less_than(8,a,b)],
    0xd: ['jsle', lambda il,a,b: il.compare_signed_less_equal(8,a,b)],
}


def fmt_jump_offset(off) -> str:
    return f'+{off}' if off > 0 else str(off)


def branch_type(op, s, dst, src, imm, off, addr) -> Instruction:
    if op == 0: # ja
        # target = addr + 8 + (signed(32, imm) * 8)
        target = addr + 8 + (signed(16, off) * 8)
        info = InstructionInfo(length=8)
        info.add_branch(BranchType.UnconditionalBranch, target)
        return Instruction(
            text=[
                tI('ja'), tT(' '),
                tS('<'), tN(fmt_jump_offset(signed(16, off)), signed(16, off)), tS('>'),
            ],
            info=info,
            llil=lambda il: il_jump(il, target)
        )
    elif op == 8: # call
        target = addr + 8 + (signed(32, imm) * 8)
        info = InstructionInfo(length=8)

        if src == 2:
            # Custom marker, hardcoded to extern address.
            info.add_branch(BranchType.CallDestination, imm)
            return Instruction(
                text=[tI('call'), tT(' '), tA(hex(imm), imm)],
                info=info,
                llil=lambda il: il.append(il.call(il.const(8, imm)))
            )
        if imm == 0xffffffff:
            info.add_branch(BranchType.SystemCall)
            return Instruction(
                text=[tI('syscall')],
                info=info,
                llil=lambda il: il.append(il.system_call())
            )
        else:
            # TODO: no idea why but this causes binja to crash:
            info.add_branch(BranchType.CallDestination, target)
            return Instruction(
                text=[tI('call'), tT(' '), tA(hex(target), target)],
                info=info,
                llil=lambda il: il.append(il.call(il.const(8, target))),
            )
    elif op == 9: # ret
        info = InstructionInfo(length=8)
        info.add_branch(BranchType.FunctionReturn)
        return Instruction(
            text=[tI('exit')],
            info=info,
            llil=lambda il: il.append(il.ret(il.pop(8)))
        )
    elif op in JUMP_COND:
        name, cond = JUMP_COND[op]

        tpos = addr + 8 + (signed(16, off) * 8)
        tneg = addr + 8

        info = InstructionInfo(length=8)
        info.add_branch(BranchType.TrueBranch, tpos)
        info.add_branch(BranchType.FalseBranch, tneg)

        return Instruction(
            # e.g: "jgt <+20> r3, 4"
            text=[
                tI(name), tT(' '),
                tS('<'), tN(fmt_jump_offset(signed(16, off)), signed(16, off)), tS('>'),
                tT(' '), tR(f'r{dst}'), tT(', '), (tR(f'r{src}') if s else tN(hex(signed(32, imm)), signed(32, imm)))],
            info=info,
            llil=lambda il: il_cond_branch(
                il,
                cond(
                    il,
                    il.reg(8, f'r{dst}'),
                    (il.reg(8, f'r{src}') if s else il.sign_extend(8, il.const(4, imm))),
                ),
                tpos,
                tneg
            )
        )

    else:
        return None


def decode(data: bytes, addr: int) -> Instruction:
    if len(data) < 8:
        return None

    op = data[0]
    regs = data[1]
    dst = regs & 0xf
    src = (regs >> 4) & 0xf
    off = int.from_bytes(data[2:4], 'little')
    imm = int.from_bytes(data[4:8], 'little')

    aop = (op >> 4) & 0xf
    s = (op >> 3) & 1
    sz = (op >> 3) & 0b11
    ldop = (op >> 3) & 0b11111

    clz = op & 0b111

    if clz == 0b000:
        if ldop == 3: # lddw
            if len(data) < 16:
                return None

            imm2 = int.from_bytes(data[12:16], 'little')
            return lddw(dst, imm | (imm2 << 32))
        else:
            return ld(ldop, dst, src, imm)
    elif clz == 0b001: return ldx(dst, src, off, sz)
    elif clz == 0b010: return st(dst, off, imm, sz)
    elif clz == 0b011: return stx(dst, src, off, sz)
    elif clz == 0b111: return alu64(aop, s, dst, src, imm)
    elif clz == 0b100: return alu32(aop, s, dst, src, imm)
    elif clz == 0b101: return branch_type(aop, s, dst, src, imm, off, addr)


    return None
