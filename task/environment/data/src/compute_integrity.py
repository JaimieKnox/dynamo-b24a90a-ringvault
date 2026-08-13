#!/usr/bin/env python3
"""Compute FNV-1a integrity hash over ct_eq function bytes for two-pass build."""
import struct
import subprocess
import sys


def main():
    binary = sys.argv[1]

    nm_out = subprocess.check_output(["nm", binary]).decode()
    ct_eq_addr = None
    cookie_addr = None
    for line in nm_out.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 3:
            if parts[2] == "ct_eq":
                ct_eq_addr = int(parts[0], 16)
            elif parts[2] == "integrity_cookie":
                cookie_addr = int(parts[0], 16)

    if ct_eq_addr is None:
        for line in nm_out.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3 and "ct_eq" in parts[2]:
                ct_eq_addr = int(parts[0], 16)
                break

    if ct_eq_addr is None:
        print("0ULL")
        return

    with open(binary, "rb") as f:
        elf = f.read()

    e_phoff = struct.unpack_from("<Q", elf, 32)[0]
    e_phentsize = struct.unpack_from("<H", elf, 54)[0]
    e_phnum = struct.unpack_from("<H", elf, 56)[0]

    def vaddr_to_offset(addr):
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack_from("<I", elf, off)[0]
            if p_type != 1:
                continue
            p_offset, p_vaddr = struct.unpack_from("<QQ", elf, off + 8)
            p_filesz = struct.unpack_from("<Q", elf, off + 32)[0]
            if p_vaddr <= addr < p_vaddr + p_filesz:
                return p_offset + (addr - p_vaddr)
        return None

    fn_offset = vaddr_to_offset(ct_eq_addr)
    if fn_offset is None:
        print("0ULL")
        return

    fn_bytes = elf[fn_offset : fn_offset + 128]

    cookie_bytes = bytes(16)
    if cookie_addr is not None:
        co = vaddr_to_offset(cookie_addr)
        if co is not None:
            cookie_bytes = elf[co : co + 16]

    h = 0xCBF29CE484222325
    for b in cookie_bytes:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    for b in fn_bytes:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF

    print(f"0x{h:016x}ULL")


if __name__ == "__main__":
    main()
