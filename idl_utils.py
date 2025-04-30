import asyncio
import zlib
import struct
import base64
import json
from solders.pubkey import Pubkey
from solana.rpc.async_api import AsyncClient
import binaryninja as bn
from anchorpy import Program, Provider
import base58                           

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"

def fetch_idl_anchorpy(bv, func):
    """
    Three-line recipe:
      1. Provider = AnchorPy wrapper around AsyncClient
      2. Program.fetch_idl(pid, provider) → Idl object | None
      3. Idl.to_json()
    """

    pid = Pubkey(collect_load_cmps(bv, func))

    provider = Provider(AsyncClient(DEFAULT_RPC), None)    
    idl      = asyncio.run(Program.fetch_idl(pid, provider))    # ← Anchor convenience

    if idl is None:
        return None
    return idl.to_json()

# ---------------------------------------------------------------------------
def collect_load_cmps(bv, func):
    """
    Scan the entrypoint and recover the 32-byte program ID by reading the first
    four `lddw` immediate constants (64-bit each, little-endian).
    """
    immediates = []
    INT      = bn.InstructionTextTokenType.IntegerToken

    for bb in func.basic_blocks:
        for dline in bb.get_disassembly_text():  # ← single value per iter ✔
            if dline is None:
                continue

            tokens = dline.tokens
            if not tokens or tokens[1].text.strip() != "lddw":
                continue

            const_tok = next((t for t in tokens if t.type == INT), None)
            if const_tok:
                immediates.append(int(const_tok.text, 0) & 0xFFFFFFFFFFFFFFFF)
                if len(immediates) == 4:
                    res = b"".join(v.to_bytes(8, "little") for v in immediates)
                    print(res)
                    print(base58.b58encode(res))
                    return res
    return None


def program_id_from_entry(func) -> bytes | None:
    """
    Try to recover the hard-coded 32-byte program ID in an Anchor entrypoint.
    Returns raw bytes or None if nothing matched.
    """
    offs = collect_load_cmps(None, func)
    if len(offs) == 4:
        raw = (offs[0].to_bytes(8, "little") +
               offs[8].to_bytes(8, "little") +
               offs[16].to_bytes(8, "little") +
               offs[24].to_bytes(8, "little"))
        return raw
    return None

# were sure to have an entry func, and we find the id in the first memcmp
def find_entry_memcmp_second_arg(bv, func):
    for function in bv.functions:
        #match the anchor entrypoint
        if function.name.endswith("::entry") and len(function.type.children) == 6:
            # Get the HLIL
            hlil = function.hlil

            print("HLIL: ", hlil)
            print(hlil == None)

            for block in hlil:
                print("BLOCK: ", block)
                for instruction in block:
                    memcmp_call = find_memcmp_call(instruction)
                    if(memcmp_call == None):
                        continue

                    sol_id = bv.read(memcmp_call.params[1].constant, 32)
                    print(sol_id)
                    return sol_id
    
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


def print_idl(bv, func):
    pubkey = Pubkey(collect_load_cmps(bv, func))
    print(asyncio.run(fetch_idl_raw(pubkey, DEFAULT_RPC)))

async def fetch_idl_raw(pid: Pubkey, rpc: str):
    """Fetch, decompress and parse the IDL without Anchor helpers."""
    conn = AsyncClient(rpc)
    idl_addr = idl_pda(pid)                                    # PDA derivation logic :contentReference[oaicite:1]{index=1}
    resp = await conn.get_account_info(idl_addr)
    await conn.close()

    acc = resp.value
    if acc is None:
        raise ValueError("No IDL account found on-chain for this program.")

    raw = base64.b64decode(acc.data[0])

    # Anchor layout: discriminator[8] | zlib_len<u32> | zlib_bytes[..]
    (length,) = struct.unpack_from("<I", raw, 8)
    compressed = raw[12:12 + length]
    idl_json = json.loads(zlib.decompress(compressed))
    return idl_json

def idl_pda(program_id: Pubkey) -> Pubkey:
    seed = b"anchor:idl"
    return Pubkey.find_program_address([seed], program_id)[0]
