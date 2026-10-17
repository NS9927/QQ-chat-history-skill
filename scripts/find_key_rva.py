"""定位 wrapper.node 里 nt_sqlite3_key_v2 包装函数的 RVA。

用法:
    python find_key_rva.py "C:/Program Files/Tencent/QQNT/versions/<ver>/resources/app/wrapper.node"
"""
import argparse
import re
import struct


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("wrapper_node")
    args = ap.parse_args()

    data = open(args.wrapper_node, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    dirs_off = opt_off + (112 if magic == 0x20B else 96)

    sec_off = opt_off + opt_size
    sections = []
    for i in range(num_sections):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\x00").decode(errors="replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        sections.append((name, vaddr, vsize, rawptr, rawsize))

    def off2rva(off):
        for _n, vaddr, _vs, rawptr, rawsize in sections:
            if rawptr <= off < rawptr + rawsize:
                return vaddr + (off - rawptr)
        return None

    _pdata_rva, pdata_sz = struct.unpack_from("<II", data, dirs_off + 3 * 8)
    pdata = next((s for s in sections if s[0] == ".pdata"), None)
    if pdata is None:
        raise SystemExit(".pdata not found")

    needle = b"nt_sqlite3_key_v2: db=%p zDb=%s"
    for hit in [m.start() for m in re.finditer(re.escape(needle), data)]:
        str_rva = off2rva(hit)
        if str_rva is None:
            continue
        for m in re.finditer(b"\x48\x8d[\x05\x0d\x15\x1d]", data):
            lea_off = m.start()
            lea_rva = off2rva(lea_off)
            if lea_rva is None:
                continue
            disp = struct.unpack_from("<i", data, lea_off + 3)[0]
            if (lea_rva + 7 + disp) & 0xFFFFFFFFFFFFFFFF != str_rva:
                continue
            _name, _va, _vs, pdata_raw, _rs = pdata
            for i in range(pdata_sz // 12):
                begin, end, _unwind = struct.unpack_from("<III", data, pdata_raw + i * 12)
                if begin <= lea_rva < end:
                    print("string   RVA = " + hex(str_rva))
                    print("LEA      RVA = " + hex(lea_rva))
                    print("function RVA = " + hex(begin))
                    print("usage: python hook_key.py --rva " + hex(begin))
                    return
    raise SystemExit("target function not found; QQ version may have changed")


if __name__ == "__main__":
    main()
