"""
drmvm.ciphers — 暗号層（SPN連鎖 + rol13ローリング層）

学マス DMM版 DRM の3段パイプライン（フェーズAH/D1で確定済み）の下位2層を一般化した実装:

  格納形 C --SPN chain_fwd--> M --rol13 fwd(K)--> S --Huffman/LZSS展開--> 平文x86

rol13層（dwordローリング。フェーズT/X/Y/AHで確定、完全再現済み）:
    out_i = rol32(in_i ^ esi_i, 13) - i          (mod 2^32)
    esi_0 = K,  esi_{i+1} = esi_i + i  (すなわち esi_i = K + i*(i-1)/2)
    端数バイト (len % 4) は無処理でそのまま通す。
    逆変換: in_i = ror32(out_i + i, 13) ^ esi_i
    鍵回収（既知平文ブートストラップ）: K = M0 ^ ror32(S0, 13)
    （M0=SPN直後の先頭dword、S0=Huffmanストリーム先頭32bit）

SPN連鎖（0x1400c5e60 / T=0x1400c6cc0。フェーズAG/AH確定）:
    out_i = T(in_i) ^ in_{i-1}   (prev 初期値 0、連鎖には前ブロックの *入力* を使う)
    16バイトブロック、floor(size/16) ブロックのみ変換、端数 (size & 15) は無処理。

T はデータ駆動: ラウンド数 = word[key+2] >> 1（0x000e → 7ラウンド）、
ラウンド鍵は key+4 から 1ラウンド 0x20 バイト、S-box 4枚（各256 dword）は
バイト索引 lookup + XOR。ラウンド内の正確な演算順は解析メモの記載からの
再構成であり、実ダンプとの検証は必須。archive-ah/spn.py が正のときは
``t_func`` を差し替えれば連鎖ロジック（確定済み部分）はそのまま使える。

同一保護（PCR/ウマ娘系）への一般化: 鍵素材・S-box・ラウンド数はすべて
GameConfig で与える。学マス実測値は drmvm.config.GAKUMAS 参照。
"""
from __future__ import annotations

import struct
from typing import Callable, List, Optional, Sequence

M32 = 0xFFFFFFFF


def rol32(v: int, n: int = 13) -> int:
    """32bit 左ローテート。"""
    return ((v << n) | (v >> (32 - n))) & M32


def ror32(v: int, n: int = 13) -> int:
    """32bit 右ローテート。"""
    return ((v >> n) | (v << (32 - n))) & M32


def bswap32(v: int) -> int:
    """32bit バイトスワップ。"""
    return struct.unpack("<I", struct.pack(">I", v & M32))[0]


class Rol13:
    """dword ローリング層（フェーズT確定レシピ）。

    Attributes:
        key: 32bit 鍵 K。学マス VM ブロック鍵は 0xaf27a866（実行時導出・決定論的）。
    """

    def __init__(self, key: int):
        self.key = key & M32

    def fwd(self, data: bytes) -> bytes:
        """ローリング適用（復号方向）。端数はそのまま。"""
        n = len(data) >> 2
        out = bytearray(data)
        esi = self.key
        for i in range(n):
            (c,) = struct.unpack_from("<I", data, i * 4)
            p = (rol32(c ^ esi, 13) - i) & M32
            struct.pack_into("<I", out, i * 4, p)
            esi = (esi + i) & M32
        return bytes(out)

    def inv(self, data: bytes) -> bytes:
        """逆方向（再暗号化・検証用）。"""
        n = len(data) >> 2
        out = bytearray(data)
        esi = self.key
        for i in range(n):
            (o,) = struct.unpack_from("<I", data, i * 4)
            c = ror32((o + i) & M32, 13) ^ esi
            struct.pack_into("<I", out, i * 4, c)
            esi = (esi + i) & M32
        return bytes(out)

    @staticmethod
    def derive_key(m0: int, s0: int) -> int:
        """既知平文ブートストラップの鍵導出式: K = M0 ^ ror32(S0, 13)。

        M0 = SPN連鎖直後の先頭dword、S0 = Huffmanビットストリーム先頭32bit。
        """
        return (m0 ^ ror32(s0 & M32, 13)) & M32


class SPN:
    """SPNブロック暗号（16B・入力フィードバック連鎖）。

    Args:
        key_material: 鍵素材（学マスでは .rsrc 由来 0xf4 バイト）。
            word[0]=整合性マジック(0x0100), word[1]=ラウンド選択(0x000e),
            以降 = ラウンド鍵（1ラウンドあたり 0x20 バイト）。
        sboxes: 4枚の S-box。各 256 dword をリスト化したもの。
            学マスでは RVA 0xc82e0/0xc86e0/0xc8ae0/0xc8ee0。
        t_func: T 関数の差し替え用。None なら _default_t（再構成実装）。

    注意: 連鎖式 out_i = T(in_i) ^ in_{i-1} はダンプ解析で確定済み。
    _default_t のラウンド内演算順は解析メモからの再構成であり、
    実ダンプ（dump1[0xb39ec:+0xc12] → v1d 展開形）での検証が必要。
    """

    def __init__(self, key_material: bytes, sboxes: Optional[Sequence[Sequence[int]]] = None,
                 t_func: Optional[Callable[[bytes], bytes]] = None):
        self.key = bytes(key_material)
        if len(self.key) < 4:
            raise ValueError("key material too short")
        w0, w1 = struct.unpack_from("<HH", self.key, 0)
        self.magic = w0
        self.rounds = w1 >> 1  # 0x000e -> 7
        self.sboxes = sboxes
        self._t_func = t_func or self._default_t

    # ---------------------------------------------------------------- T 関数

    def t(self, block: bytes) -> bytes:
        """1ブロック（16B）への変換 T。"""
        return self._t_func(block)

    def _default_t(self, block: bytes) -> bytes:
        """解析メモ（第57/58次）からの再構成実装。

        各ラウンド: 4dword を
          (1) bswap + 前半ラウンド鍵 XOR（key+4 + r*0x20 から 0x10 バイト）
          (2) S-box 4枚: ブロックの各バイト j (0..15) について
              dword[j//4] ^= sbox[j//4][byte_j]   （バイト索引 lookup + XOR）
          (3) 後半ラウンド鍵 XOR（key+4 + r*0x20 + 0x10 から 0x10 バイト）
        ※ 演算順・S-box適用方法は要実機検証。不一致時は t_func で差し替え。
        """
        if not self.sboxes:
            raise ValueError("sboxes required for default T; inject t_func instead")
        d = list(struct.unpack("<4I", block))
        for r in range(self.rounds):
            pre = struct.unpack_from("<4I", self.key, 4 + 0x20 * r)
            post = struct.unpack_from("<4I", self.key, 4 + 0x20 * r + 0x10)
            for j in range(4):
                d[j] = bswap32(d[j]) ^ pre[j]
            for j in range(16):
                di = j >> 2
                byte = (d[di] >> (8 * (j & 3))) & 0xFF
                d[di] ^= self.sboxes[di][byte] & M32
            for j in range(4):
                d[j] ^= post[j]
        return struct.pack("<4I", *d)

    # ---------------------------------------------------------------- 連鎖

    def chain_fwd(self, data: bytes) -> bytes:
        """連鎖変換: out_i = T(in_i) ^ in_{i-1}（prev 初期値 0、prev=前ブロック入力）。

        floor(size/16) ブロックのみ変換し、端数 (size & 15) は無処理。
        """
        nb = len(data) >> 4
        out = bytearray(data)
        prev = b"\x00" * 16
        for i in range(nb):
            blk = data[i * 16:(i + 1) * 16]
            t = self.t(blk)
            out[i * 16:(i + 1) * 16] = bytes(a ^ b for a, b in zip(t, prev))
            prev = blk
        return bytes(out)


def load_sboxes(image: bytes, rvas: Sequence[int], size: int = 0x400) -> List[List[int]]:
    """ダンプイメージから S-box 4枚（各256 dword）を読み出す。"""
    return [list(struct.unpack_from("<256I", image, rva)) for rva in rvas]
