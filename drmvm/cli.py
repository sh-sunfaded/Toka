"""
drmvm.cli — コマンドラインインターフェース

使用例:
    # 3段パイプラインでVMブロックを展開（鍵既知）
    python -m drmvm.cli decrypt-block dump.bin --desc 0xb39ec:0xc12:0xb39ec:0x14bc --out ref.bin

    # 既知平文ブートストラップで鍵Kを回収
    python -m drmvm.cli recover-key dump.bin --desc 0xb39ec:0xc12:0xb39ec:0x14bc --ref ref_block.bin

    # mailslot暗号ボディの復号（k0範囲走査）
    python -m drmvm.cli mailslot body.bin --out plain.txt

    # 既知パターン候補の走査 + サンプルパッチ検証
    python -m drmvm.cli scan-patches dump.bin

    # movabs隠れコードの検出
    python -m drmvm.cli find-movabs code.bin
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .config import PROFILES, get_profile
from .pipeline import Descriptor, Pipeline, load_image


def _open_out(path: Optional[str], data: bytes) -> None:
    if path:
        with open(path, "wb") as f:
            f.write(data)
        print(f"wrote {len(data)} bytes -> {path}")
    else:
        sys.stdout.buffer.write(data)


def cmd_decrypt_block(args) -> int:
    cfg = get_profile(args.profile)
    image = load_image(args.image)
    pipe = Pipeline(cfg, image)
    desc = Descriptor.parse(args.desc)
    key = int(args.key, 0) if args.key else None
    out = pipe.decrypt_block(desc, rol13_key=key)
    _open_out(args.out, out)
    return 0


def cmd_recover_key(args) -> int:
    cfg = get_profile(args.profile)
    image = load_image(args.image)
    with open(args.ref, "rb") as f:
        ref = f.read()
    pipe = Pipeline(cfg, image)
    desc = Descriptor.parse(args.desc)
    key = pipe.recover_key(desc, ref, verbose=True)
    if key is None:
        print("FAILED: no candidate K satisfied the reference", file=sys.stderr)
        return 1
    print(f"recovered rol13 key K = {key:#x}")
    return 0


def cmd_mailslot(args) -> int:
    from . import mailslot
    with open(args.body, "rb") as f:
        body = f.read()
    if args.k0:
        plain = mailslot.decode_body(body, int(args.k0, 0))
    else:
        k0 = mailslot.recover_k0(body)
        if k0 is None:
            print("FAILED: k0 not found in default range", file=sys.stderr)
            return 1
        print(f"k0 = {k0:#x}", file=sys.stderr)
        plain = mailslot.decode_body(body, k0)
    _open_out(args.out, plain)
    return 0


def cmd_scan_patches(args) -> int:
    from .patches import (SAMPLE_PATCH_G, filter_patch_l_by_lea,
                          find_patch_l_candidates, verify_patch)
    image = load_image(args.image)
    cands = find_patch_l_candidates(image)
    lea = filter_patch_l_by_lea(image, cands)
    print(f"shr rdx,0x20 sites: {len(cands)}"
          f" (with preceding lea rdx,[rsp+X]: {len(lea)})")
    for c in cands:
        print(f"  rva={c:#x}{'  <-- lea rdx,[rsp+X]' if c in lea else ''}")
    st = verify_patch(image, SAMPLE_PATCH_G)
    print(f"sample patch @ {st.patch.rva:#x}: {st.status} ({st.detail}) {st.patch.note}")
    return 0


def cmd_find_movabs(args) -> int:
    from .disasm import decode_imm64, find_movabs, imm64_le
    with open(args.file, "rb") as f:
        data = f.read()
    base = int(args.base, 0) if args.base else 0
    for site in find_movabs(data):
        imm_val = int.from_bytes(site.imm, "big")
        print(f"{base + site.offset:#x}: movabs r{site.reg}, 0x{imm_val:016x}"
              f" (hidden code LE={imm64_le(site.imm).hex()})")
        try:
            for insn in decode_imm64(site.imm, addr=base + site.offset):
                print(f"    {insn.mnemonic} {insn.op_str}")
        except RuntimeError as e:
            print(f"    ({e})")
    return 0


def cmd_stage0(args) -> int:
    from .unpack import decrypt_stream, find_descriptors
    with open(args.file, "rb") as f:
        data = f.read()
    descs = find_descriptors(data)
    print(f"descriptors found: {len(descs)}")
    for d in descs:
        print(f"  off={d.offset:#x} fields={[hex(x) for x in d.fields]}")
    if args.decrypt:
        size = int(args.size, 0)
        init_key = int(args.init_key, 0)
        out = decrypt_stream(data, size, init_key)
        _open_out(args.out, out)
    return 0


def cmd_enumerate(args) -> int:
    """既知展開結果と整合する先頭N bit候補の列挙（ブートストラップの前段）。"""
    from .vmcode import HuffmanTable, enumerate_prefixes_from_reference
    cfg = get_profile(args.profile)
    image = load_image(args.image)
    desc = Descriptor.parse(args.desc)
    with open(args.ref, "rb") as f:
        ref = f.read()
    key_rva, key_size, tbl_rva, tbl_size = cfg.key_pair(desc.off2)
    table = HuffmanTable(image[tbl_rva:tbl_rva + tbl_size])
    cands = enumerate_prefixes_from_reference(table, ref, min_bits=args.bits)
    print(f"{len(cands)} candidate first-{args.bits}-bit values")
    for c in cands:
        print(f"0x{c:08x}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="drmvm",
        description="VM bytecode toolkit (SPN/rol13/Huffman pipeline)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_image(sp):
        sp.add_argument("image",
                        help="dump image (RVA==offset, header auto-stripped)")

    sp = sub.add_parser("decrypt-block", help="decrypt+expand a VM block")
    add_image(sp)
    sp.add_argument("--profile", default="sample", choices=sorted(PROFILES))
    sp.add_argument("--desc", required=True, help="off1:size1:off2:size2")
    sp.add_argument("--key", help="rol13 key K (hex). default: profile value")
    sp.add_argument("--out", help="output file (default stdout)")
    sp.set_defaults(func=cmd_decrypt_block)

    sp = sub.add_parser("recover-key", help="known-plaintext bootstrap for rol13 key")
    add_image(sp)
    sp.add_argument("--profile", default="sample", choices=sorted(PROFILES))
    sp.add_argument("--desc", required=True)
    sp.add_argument("--ref", required=True, help="known expanded plaintext block")
    sp.set_defaults(func=cmd_recover_key)

    sp = sub.add_parser("mailslot", help="decrypt a mailslot message body")
    sp.add_argument("body")
    sp.add_argument("--k0", help="known k0 (hex). default: range scan")
    sp.add_argument("--out")
    sp.set_defaults(func=cmd_mailslot)

    sp = sub.add_parser("scan-patches",
                        help="scan known byte-pattern sites / verify sample patch")
    add_image(sp)
    sp.set_defaults(func=cmd_scan_patches)

    sp = sub.add_parser("find-movabs", help="find movabs-hidden code")
    sp.add_argument("file")
    sp.add_argument("--base", default="0", help="base address for display (hex)")
    sp.set_defaults(func=cmd_find_movabs)

    sp = sub.add_parser("stage0", help="packer descriptor scan / rolling-key decrypt")
    sp.add_argument("file")
    sp.add_argument("--decrypt", action="store_true")
    sp.add_argument("--size", default="0", help="packed size for key derivation (hex)")
    sp.add_argument("--init-key", default="0", help="initKey (hex)")
    sp.add_argument("--out")
    sp.set_defaults(func=cmd_stage0)

    sp = sub.add_parser("enumerate",
                        help="enumerate first-N-bit stream candidates from reference")
    add_image(sp)
    sp.add_argument("--profile", default="sample", choices=sorted(PROFILES))
    sp.add_argument("--desc", required=True)
    sp.add_argument("--ref", required=True, help="known expanded plaintext block")
    sp.add_argument("--bits", type=int, default=32)
    sp.set_defaults(func=cmd_enumerate)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
