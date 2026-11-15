"""
drmvm.vmcode — VMバイトコード層（Huffman復号 + LZSS展開エンジン）

3段パイプラインの第3段:

  S（rol13出力のバイト列）はビットストリーム（LSB-first）として読まれ、
  Huffman 1シンボル復号器で1命令ずつフェッチされ、
  LZSS型展開エンジンが平文x86を組立出力する。

Huffmanテーブル形式（3バイト/エントリ、ルート256エントリ）:
    entry = (word: uint16 LE, extra: uint8)
    word bit15 = 葉フラグ、bits0-14 = シンボル（葉）または子基底（ノード）
    ルートは「次の8ビット」で索引する高速表:
      - 葉   : extra = 実コード長（<=8）。コード = 8bit索引の下位 extra ビット。
      - ノード: 8ビット消費後、child = (word & 0x7fff) + 次ビット で降下。
    ※ byte+2 の意味（深度/開始bit索引）は降下後の葉では消費しない解釈。
      実装は既存実装との突合せで検証すること。
    ※ 未使用エントリは (0,0)。base=0 への降下は即エラーにする
      （ゼロ埋めテーブルで無限ループする事故を防ぐ — 実測で発見済み）。

VM命令セット（シンボル値 = mode | data。mode = sym & 0x300, data = sym & 0xff）:
    0x000 リテラル   : data を1バイト出力
    0x100 acc組立   : acc==0 → acc=data / それ以外は acc=(acc<<8)|data
                      （解釈: acc>=0x100 の状態で更に組立命令が来ると失敗
                        = 最大2バイト組立の実測解釈）
    0x200 RLE       : count=(acc==0?1:acc)、unit=data∈{1,2,4} で
                      直前 unit バイトを count 回複写。accは消費して0に。
    0x300 LZ        : len=data、dist=acc+data で履歴から len バイト複写
                      （重複コピー可: emit は周期 dist）。accは消費して0に。
    終端: 出力が size2 に到達した時点で成功（フェッチ失敗/履歴不足は失敗）。

acc の持続性: リテラルでは acc を変更しない。0x200/0x300 が消費して 0 にする。
（accのクリア条件は実データ未確定 — 実ダンプでの検証対象。）
"""
from __future__ import annotations

import struct
from typing import Dict, List, NamedTuple, Optional, Sequence, Set, Tuple

M32 = 0xFFFFFFFF
MAX_DESCEND = 128  # Huffman降下の異常検出上限


class BitReader:
    """LSB-first ビットリーダー（バイト内 bit0 から）。"""

    def __init__(self, data: bytes, bitpos: int = 0):
        self.data = data
        self.pos = bitpos

    def read1(self) -> int:
        if (self.pos >> 3) >= len(self.data):
            raise IndexError("bitstream exhausted")
        b = (self.data[self.pos >> 3] >> (self.pos & 7)) & 1
        self.pos += 1
        return b

    def peek(self, n: int) -> int:
        """次の n ビットを LSB-first の整数として覗く（位置は進めない）。"""
        v = 0
        for k in range(n):
            idx = self.pos + k
            if (idx >> 3) >= len(self.data):
                raise IndexError("bitstream exhausted")
            v |= ((self.data[idx >> 3] >> (idx & 7)) & 1) << k
        return v

    def consume(self, n: int) -> None:
        self.pos += n

    @property
    def consumed_bits(self) -> int:
        return self.pos


class HuffmanTable:
    """3バイト/エントリのHuffman表（ルート256）。"""

    def __init__(self, raw: bytes):
        if len(raw) % 3 != 0:
            raise ValueError("table size must be a multiple of 3")
        self.raw = bytes(raw)
        self.entries: List[Tuple[int, int]] = [
            (raw[i] | (raw[i + 1] << 8), raw[i + 2]) for i in range(0, len(raw), 3)
        ]
        if len(self.entries) < 256:
            raise ValueError("table needs at least the 256 root entries")

    # ------------------------------------------------------------ 復号

    def decode_symbol(self, reader: BitReader) -> int:
        """1シンボルを復号してビットを消費する。"""
        idx = reader.peek(8)
        word, extra = self.entries[idx]
        if word & 0x8000:
            reader.consume(extra)
            return word & 0x7FFF
        reader.consume(8)
        base = word & 0x7FFF
        if base == 0:
            raise ValueError("corrupt table: unused entry at root index "
                             f"{idx:#x}")
        for _ in range(MAX_DESCEND):
            b = reader.read1()
            if base + b >= len(self.entries):
                raise ValueError("corrupt table: child index out of range")
            word, extra = self.entries[base + b]
            if word & 0x8000:
                return word & 0x7FFF
            base = word & 0x7FFF
            if base == 0:
                raise ValueError("corrupt table: unused entry in descend")
        raise ValueError("huffman descend too deep (corrupt table?)")

    # ------------------------------------------------------------ 符号表再構築

    def codes(self) -> Dict[int, Tuple[int, int]]:
        """シンボル -> (コードビット LSB-first 整数, 長さ) の辞書。

        テーブルを逆読みして全シンボルの符号を復元する
        （逆構築。ブートストラップ鍵回収の基盤）。
        未使用エントリ (word=0) は辿らない。
        """
        out: Dict[int, Tuple[int, int]] = {}
        for r in range(256):
            word, extra = self.entries[r]
            if word & 0x8000:
                sym = word & 0x7FFF
                length = extra
                if not (1 <= length <= 8):
                    continue
                code = r & ((1 << length) - 1)
                out.setdefault(sym, (code, length))
            else:
                base0 = word & 0x7FFF
                if base0 == 0:
                    continue  # unused root entry
                # 8ビット消費 → 1ビットずつ降下
                stack: List[Tuple[int, int, int]] = [(base0, r & 0xFF, 8)]
                while stack:
                    base, pref, plen = stack.pop()
                    for b in (0, 1):
                        if base + b >= len(self.entries):
                            continue
                        word2, _extra2 = self.entries[base + b]
                        if word2 & 0x8000:
                            sym = word2 & 0x7FFF
                            out.setdefault(sym, (pref | (b << plen), plen + 1))
                        else:
                            base2 = word2 & 0x7FFF
                            if base2 != 0 and plen + 1 < 64:
                                stack.append((base2, pref | (b << plen), plen + 1))
        return out


def _pack_entry(word: int, extra: int) -> bytes:
    return bytes((word & 0xFF, (word >> 8) & 0xFF, extra & 0xFF))


def build_table(codes: Dict[int, Tuple[int, int]]) -> bytes:
    """(シンボル -> (コード, 長さ)) からテーブル生バイト列を構築する。

    HuffmanTable.codes() の逆。合成データでのラウンドトリップ検証、
    および解析対象テーブルの形式検証に使う。衝突する前置きは拒否する。
    未使用の子スロットは (0,0) のまま残る（実テーブルと同じ）。
    """
    entries: List[Optional[Tuple[int, int]]] = [None] * 256

    def alloc_pair() -> int:
        base = len(entries)
        entries.extend([None, None])
        return base

    for sym, (bits, length) in codes.items():
        if length <= 8:
            mask = (1 << length) - 1
            for r in range(256):
                if (r & mask) == bits:
                    if entries[r] is not None:
                        raise ValueError(f"root conflict at {r:#x}")
                    entries[r] = (0x8000 | sym, length)
        else:
            r8 = bits & 0xFF
            if entries[r8] is None:
                entries[r8] = (alloc_pair(), 0)
            elif entries[r8][0] & 0x8000:
                raise ValueError(f"root conflict at {r8:#x}")
            base = entries[r8][0]
            for bitidx in range(8, length - 1):
                b = (bits >> bitidx) & 1
                e = entries[base + b]
                if e is None:
                    nb = alloc_pair()
                    entries[base + b] = (nb, 0)
                    base = nb
                elif not (e[0] & 0x8000):
                    base = e[0]
                else:
                    raise ValueError("prefix conflict (leaf under path)")
            b = (bits >> (length - 1)) & 1
            if entries[base + b] is not None:
                raise ValueError(f"child conflict at {base + b:#x}")
            entries[base + b] = (0x8000 | sym, 0)

    out = bytearray()
    for e in entries:
        out += _pack_entry(*(e if e is not None else (0, 0)))
    return bytes(out)


def encode_stream(symbols: Sequence[int], codes: Dict[int, Tuple[int, int]],
                 pad_to_byte: bool = True) -> bytes:
    """シンボル列をビットストリーム（LSB-first）にエンコード。検証・テスト用。"""
    bits: List[int] = []
    for s in symbols:
        code, length = codes[s]
        for k in range(length):
            bits.append((code >> k) & 1)
    if pad_to_byte:
        while len(bits) % 8:
            bits.append(0)
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for k in range(8):
            if i + k < len(bits):
                byte |= bits[i + k] << k
        out.append(byte)
    return bytes(out)


# ---------------------------------------------------------------- 命令シミュレータ

def simulate_command(mode: int, data: int, out: bytes, acc: int,
                     out_limit: int) -> Tuple[bool, bytes, int]:
    """単一VM命令の効果を純関数として計算する。

    戻り値: (ok, emit_bytes, new_acc)。
    expand() と enumerate_prefixes_from_reference()（および
    pipeline の段階的検証）が同一の意味論を共有するための
    単一の真実源。
    """
    if mode == 0x000:  # リテラル
        if len(out) + 1 > out_limit:
            return False, b"", acc
        return True, bytes((data,)), acc
    if mode == 0x100:  # acc 組立（最大2バイトの解釈）
        if acc == 0:
            return True, b"", data
        if acc >= 0x100:
            return False, b"", acc
        return True, b"", ((acc << 8) | data) & M32
    if mode == 0x200:  # RLE
        count = acc if acc else 1
        if data not in (1, 2, 4):
            return False, b"", acc
        if len(out) < data:
            return False, b"", acc
        emit = out[-data:] * count
        if len(out) + len(emit) > out_limit:
            return False, b"", acc
        return True, emit, 0
    if mode == 0x300:  # LZ 後方参照（周期 dist の重複コピーを含む）
        length = data
        dist = acc + data
        if dist == 0 or dist > len(out):
            return False, b"", acc
        base = out[-dist:]
        emit = (base * (length // dist + 1))[:length]
        if len(out) + len(emit) > out_limit:
            return False, b"", acc
        return True, emit, 0
    return False, b"", acc


class ExpandResult(NamedTuple):
    out: bytes
    ok: bool
    consumed_bits: int
    error: Optional[str] = None


def expand(stream: bytes, out_size: int, table: HuffmanTable) -> ExpandResult:
    """LZSS型VM展開エンジン。

    stream = rol13出力 S。out_size = 記述子 size2（展開後サイズ）。
    出力が out_size 到達で成功（ストリームの余りは報告のみ）。
    """
    reader = BitReader(stream)
    out = bytearray()
    acc = 0

    def fail(msg: str) -> ExpandResult:
        return ExpandResult(bytes(out), False, reader.consumed_bits, msg)

    while len(out) < out_size:
        try:
            sym = table.decode_symbol(reader)
        except IndexError:
            return fail("bitstream exhausted before output complete")
        okflag, emit, acc = simulate_command(sym & 0x300, sym & 0xFF,
                                              bytes(out), acc, out_size)
        if not okflag:
            return fail(f"command rejected at {len(out)} (sym={sym:#x})")
        out += emit
        if len(out) == out_size:
            return ExpandResult(bytes(out), True, reader.consumed_bits)
    return ExpandResult(bytes(out), True, reader.consumed_bits)


def enumerate_prefixes_from_reference(table: HuffmanTable, ref: bytes,
                                      min_bits: int = 32) -> List[int]:
    """既知展開結果と整合するコマンド列のDFS列挙 → 先頭min_bits候補を網羅。

    既知平文ブートストラップの中核。
    「既知展開結果の先頭を再現するコマンド列」だけを辿るため、
    全シンボル組み合わせの爆発は起きない（実測では数千候補に収まる）。

    各状態 (bits, nbits, out, acc) から:
      - 全シンボルの効果を simulate_command で計算
      - 出力が ref の前置きと一致するものだけ継続
      - 符号長の累積が min_bits に達したら S0 候補として記録して打ち切り
    """
    codes = table.codes()
    mask = (1 << min_bits) - 1
    candidates: Set[int] = set()
    stack: List[Tuple[int, int, bytes, int]] = [(0, 0, b"", 0)]
    seen: Set[Tuple[int, int, bytes, int]] = {stack[0]}
    while stack:
        bits, nbits, out, acc = stack.pop()
        for sym, (code, clen) in codes.items():
            okflag, emit, nacc = simulate_command(sym & 0x300, sym & 0xFF,
                                                  out, acc, len(ref))
            if not okflag:
                continue
            new_out = out + emit
            if ref[:len(new_out)] != new_out:
                continue
            nb = bits | (code << nbits)
            nl = nbits + clen
            if nl >= min_bits:
                candidates.add(nb & mask)
            else:
                state = (nb, nl, new_out, nacc)
                if state not in seen:
                    seen.add(state)
                    stack.append(state)
    return sorted(candidates)
