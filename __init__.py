from binaryninja import CallingConvention, Architecture, Platform
from binaryninja.typelibrary import TypeLibrary
from binaryninja.types import Type, TypeBuilder

from .ebpf import EBPF
EBPF().register()

class DefaultCallingConvention(CallingConvention):
    name = 'Default'
    int_arg_regs = [f'r{i}' for i in range(1,10)]
    int_return_reg = 'r0'

from .solana import Solana
solana = Solana(Architecture['ebpf'])
solana.default_calling_convention = DefaultCallingConvention(Architecture['ebpf'], 'default')
solana.register('Solana')

from .solanaview import SolanaView
SolanaView.register()
