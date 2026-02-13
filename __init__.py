from binaryninja import CallingConvention, Architecture, log_error_for_exception

try:
    from binaryninjaui import Sidebar
    from .sidebar_ui import LLMDecompSidebarWidgetType
    Sidebar.addSidebarWidgetType(LLMDecompSidebarWidgetType())
except Exception:
    log_error_for_exception("Failed to load LLM Decompiler", "bn-ebpf-solana")

from .idl_utils import *
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
