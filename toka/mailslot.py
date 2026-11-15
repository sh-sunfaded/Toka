"""
toka.mailslot — mailslotメッセージボディの復号と鍵回収

Windows mailslot 大型メッセージの暗号化ボディ:
    c[i] = p[i] ^ (k & 0xff)
    k    = ror32(k + i, 7)      （バイト毎に更新）
    k0   = 32bit ラン毎鍵

観測上 k0 は特定の高域帯に収まるため、デフォルトは
0xfff80000..0xffffffff の範囲走査。既知平文（ボディ先頭の
"-- Version\\r\\n"）で検証する。
※ i の更新タイミング（処理前/処理後）の解釈は本実装で固定しており、
  実データと1バイトずれた場合は update の i を調整すること。

NumPy が導入されている環境では recover_k0 は toka.fastpath の
ベクトル化走査に自動委譲される（結果は等価・testsで検証）。
"""
from __future__ import annotations

from typing import Optional

from . import fastpath

M32 = 0xFFFFFFFF
DEFAULT_K0_LO = 0xFFF80000
DEFAULT_K0_HI = 0x100000000  # exclusive
DEFAULT_KNOWN_PREFIX = b"-- Version\r\n"


def _ror32(v: int, n: int = 7) -> int:
    return ((v >> n) | (v << (32 - n))) & M32


def decode_body(body: bytes, k0: int) -> bytes:
    """暗号ボディ -> 平文。"""
    out = bytearray()
    k = k0 & M32
    for i, c in enumerate(body):
        out.append(c ^ (k & 0xFF))
        k = _ror32((k + i) & M32, 7)
    return bytes(out)


def encode_body(plain: bytes, k0: int) -> bytes:
    """平文 -> 暗号ボディ（テスト・検証用の順方向）。"""
    out = bytearray()
    k = k0 & M32
    for i, p in enumerate(plain):
        out.append(p ^ (k & 0xFF))
        k = _ror32((k + i) & M32, 7)
    return bytes(out)


def _matches(body: bytes, known: bytes, k0: int) -> bool:
    k = k0 & M32
    for i in range(len(known)):
        if (body[i] ^ (k & 0xFF)) != known[i]:
            return False
        k = _ror32((k + i) & M32, 7)
    return True


def recover_k0(body: bytes, known_prefix: bytes = DEFAULT_KNOWN_PREFIX,
               lo: int = DEFAULT_K0_LO, hi: int = DEFAULT_K0_HI) -> Optional[int]:
    """既知平文で k0 を範囲走査により回収する。見つからなければ None。

    NumPy があれば候補軸のベクトル化走査を使う（toka.fastpath）。
    """
    if len(known_prefix) == 0 or len(body) == 0:
        raise ValueError("need at least one known plaintext byte")
    if fastpath.HAVE_NUMPY:
        return fastpath.recover_k0(body, known_prefix, lo, hi)
    known = known_prefix[:min(len(known_prefix), len(body))]
    for k0 in range(lo, hi):
        if _matches(body, known, k0):
            return k0
    return None
