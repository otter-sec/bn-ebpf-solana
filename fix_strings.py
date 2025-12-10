from binaryninja import PluginCommand, log_info

def fix_sol_log_strings(bv):
    sol_log = bv.get_symbol_by_raw_name('sol_log_')
    if not sol_log:
        log_info("sol_log_ symbol not found")
        return

    count = 0
    for ref in bv.get_code_refs(sol_log.address):
        func = ref.function
        if not func:
            continue

        llil = func.get_llil_at(ref.address)
        if not llil:
            continue

        hlil = llil.hlil
        if not hlil or not hasattr(hlil, 'params') or len(hlil.params) < 2:
            continue

        ptr_param = hlil.params[0]
        len_param = hlil.params[1]

        try:
            if hasattr(ptr_param, 'constant') and hasattr(len_param, 'constant'):
                ptr = ptr_param.constant
                length = len_param.constant
                if length > 0 and length < 4096:
                    bv.define_user_data_var(ptr, bv.parse_type_string(f'char [{length}]')[0])
                    count += 1
        except:
            pass

    log_info(f"Fixed {count} sol_log strings")

PluginCommand.register(
    "Solana\\Fix sol_log strings",
    "Define strings at sol_log_ call sites with correct lengths",
    fix_sol_log_strings
)
