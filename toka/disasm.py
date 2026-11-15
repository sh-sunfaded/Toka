"""
toka.disasm — 難読化対応 x86-64 逆アセンブル支援

対象の平文x86は線形disasm不能（実測の教訓）:
  (1) jmp-over-jmp: 実データをまたぐ短jmpで線形逆アセンブルを崩す
      → 再帰下降ディスアセンブラ（capstone）で追う
  (2) movabs即値に実コードを隠す: 例:
      movabs rcx, 0x105b8b4c08c48348
      → 即値の LE バイト列 48 83 c4 08 4c 8b 5b 10 は
        「add rsp,8; mov r11,[rbx+0x10]」という実命令
      → 逆読みが止まったら即値LEバイト列を命令として手動デコードする

本モジュールは (2) のパターン検出を純Pythonで行い、命令デコードは
capstone（あれば）で行う。capstone が無い環境でもパターン検出・
即値抽出は動作する。

使用例:
    from toka.disasm import find_movabs, decode_imm64
    for site in find_movabs(code):
        for insn in decode_imm64(site.imm, addr=base + site.offset):
            print(f"{insn.address:#x}  {insn.mnemonic} {insn.op_str}")
"""
from __future__ import annotations

import struct
from typing import Iterator, List, NamedTuple


class MovabsSite(NamedTuple):
    offset: int       # movabs 命令の先頭オフセット
    reg: int           # 0..7 (rax..rdi)
    imm: bytes         # 即値8バイトの BE 並び（.hex() が即値のhex表記と一致）。
                       # imm64_le() でLE並び = 実コードバイト列に変換する。


def find_movabs(data: bytes, offset: int = 0) -> Iterator[MovabsSite]:
    """REX.W movabs r64, imm64（48 B8+r .. 48 BF+r）を走査検出する。"""
    i = offset
    end = len(data) - 10
    while i <= end:
        if data[i] == 0x48 and 0xB8 <= data[i + 1] <= 0xBF:
            yield MovabsSite(i, data[i + 1] - 0xB8,
                             bytes(reversed(data[i + 2:i + 10])))
            i += 10
        else:
            i += 1


def imm64_le(imm: bytes) -> bytes:
    """即値8バイトを LE 並び（実コードバイト列）に変換。"""
    if len(imm) != 8:
        raise ValueError("imm must be 8 bytes")
    return bytes(reversed(imm))


def decode_imm64(imm: bytes, addr: int = 0) -> list:
    """movabs即値のLEバイト列を実命令としてデコードする。

    capstone が無い場合は RuntimeError（生バイト列はメッセージに含む）。
    戻り値は capstone の命令オブジェクト列。
    """
    code = imm64_le(imm)
    try:
        import capstone  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            f"capstone required to decode instructions; raw LE bytes: {code.hex()}"
        ) from e
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    out = []
    for insn in md.disasm(code, addr):
        out.append(insn)
        if insn.address + insn.size >= addr + 8:
            break
    return out


def find_jmp_over_jmp(data: bytes, offset: int = 0) -> Iterator[int]:
    """EB xx（jmp short）によるデータスキップの着地点を列挙する。

    jmp-over-jmp 難読化の走査用: 着地点 = offset + 2 + disp8。
    """
    i = offset
    end = len(data) - 2
    while i <= end:
        if data[i] == 0xEB:
            yield i + 2 + struct.unpack_from("<b", data, i + 1)[0]
            i += 2
        else:
            i += 1


def smart_disasm(data: bytes, base: int = 0, start: int = 0,
                 max_insn: int = 200) -> List:
    """再帰下降風の逆アセンブル（capstone 必須）。

    - EB jmp-short は jmp-over-jmp とみなしてデータをまたぐ
    - movabs に到達したら即値LEバイトを隠れ実コードとして出力に混ぜる
      （本来の movabs 自体はスキップ）
    - 直接 jmp はイメージ内なら着地へ追う
    """
    try:
        import capstone  # type: ignore
    except ImportError as e:
        raise RuntimeError("capstone required for smart_disasm") from e
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    result: List = []
    pc = start
    seen = set()
    while len(result) < max_insn and pc < len(data):
        if pc in seen:
            break
        seen.add(pc)
        if data[pc] == 0xEB:  # jmp short → データスキップ
            pc = pc + 2 + struct.unpack_from("<b", data, pc + 1)[0]
            continue
        if data[pc] == 0x48 and pc + 1 < len(data) and 0xB8 <= data[pc + 1] <= 0xBF:
            for insn in decode_imm64(bytes(reversed(data[pc + 2:pc + 10])),
                                      addr=base + pc):
                result.append(insn)
            pc += 10
            continue
        insns = list(md.disasm(data[pc:pc + 16], base + pc, count=1))
        if not insns:
            pc += 1
            continue
        insn = insns[0]
        result.append(insn)
        pc += insn.size
        if insn.mnemonic == "jmp":
            try:
                target = int(insn.op_str, 0) - base
            except ValueError:
                break
            if 0 <= target < len(data):
                pc = target
            else:
                break
    return result
