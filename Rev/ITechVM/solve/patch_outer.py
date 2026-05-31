#!/usr/bin/env python3
from pathlib import Path
import importlib.util
import random
import sys


IMAGE_MAGIC = b"ITEC"
IMAGE_VERSION = 1
PASSWORD_TEXT = b"$ivm_gate_seed_for_blf_path_26$"
PASSWORD = int.from_bytes(PASSWORD_TEXT, "little")
CALL_MUTATE_OFFS = 0x8AD
HEADER_SIZE = 4 + 1 + 128 + 3 + 128 + 4


def load_compiler_module(path: Path):
    spec = importlib.util.spec_from_file_location("itechvm_compiler", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def fnv1a_hash(data: bytes) -> int:
    hash_val = 0x3140101438
    for byte in data:
        b = 0
        for j in range(8):
            b |= (byte << (8 * j))
        hash_val = (hash_val * 8675309) ^ b
    return hash_val & 0xFFFFFFFFFFFFFFFF


def compile_payload(compiler) -> bytes:
    compiler.tryXor = True
    compiler.forceXor = False
    opmap = compiler.OpcodeMap()
    labs = {}
    random.seed(0x5150)

    payload = bytearray()
    for insn in (
        "BANK 1",
        f"SET A0, 0x{PASSWORD:x}",
        "SET S0, A0",
    ):
        encoded, _ = compiler.compile_insn(insn, opmap, labs, quiet=True)
        payload.extend(encoded)
    return bytes(payload)


def rebuild_header(template: bytes, code: bytes, entrypoint: int) -> bytes:
    modulus = int.from_bytes(template[3:131], "little")
    exponent = int.from_bytes(template[131:134], "little")
    signature = pow(fnv1a_hash(code), exponent, modulus)
    xor = (signature ^ entrypoint) & 0xFFFFFFFF
    return (
        IMAGE_MAGIC
        + IMAGE_VERSION.to_bytes(1, "little")
        + modulus.to_bytes(128, "little")
        + exponent.to_bytes(3, "little")
        + signature.to_bytes(128, "little")
        + xor.to_bytes(4, "little")
    )


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "handout" / "crackme.itech"
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else root / "solve" / "code_outer_solved.itech"
    compiler_path = root / "vendor" / "Compiler" / "compile.py"

    compiler = load_compiler_module(compiler_path)
    payload = compile_payload(compiler)
    data = src.read_bytes()
    code = bytearray(data[HEADER_SIZE:])

    inject_start = CALL_MUTATE_OFFS - len(payload)
    if inject_start < 0:
        raise ValueError("payload does not fit before mutate call")

    code[inject_start:CALL_MUTATE_OFFS] = payload
    header = rebuild_header(data[:HEADER_SIZE], bytes(code), inject_start)
    dst.write_bytes(header + code)

    print(f"patched {src} -> {dst}")
    print(f"payload bytes     : {len(payload)}")
    print(f"entrypoint        : 0x{inject_start:x}")
    print(f"mutate call offs  : 0x{CALL_MUTATE_OFFS:x}")
    print(f"outer password    : {PASSWORD_TEXT.decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
