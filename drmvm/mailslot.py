"""
drmvm.mailslot — mailslot報告ボディの復号と鍵回収

DRMのエラー報告（mailslot大型メッセージ）の暗号化ボディ:
    c[i] = p[i] ^ (k & 0xff)
    k    = ror32(k + i, 7)      （バイト毎に更新）
    k0   = 32bit ラン毎鍵

観測上 k0 は 0xfff8c5xx 帯に収まる（フェーズQ実測）ため、
デフォルトは 0xfff80000..0xffffffff の範囲走査（数十万件・数秒）。
既知平文（ボディ先頭の "-- Version\\r\\n"）で検証する。
※ i の更新タイミング（処理前/処理後）の解釈は本実装で固定しており、
  実運用の decode_body.py と1バイトずれた場合は update の i を調整すること。

純Python実装。外部依存なし。
"""
from __future__ import annotations

from typing import Optional

M32 = 0xFFFFFFFF
DEFAULT_K0_LO = 0xFFF80000
DEFAULT_K0_HI = 0x100000000  # exclusive
DEFAULT_KNOWN_PREFIX = b"-- Version\r\n"


def _ror32(v: int, n: int = 7) -> int:
    return ((v >> n) | (v << (32 - n))) & M32


def decode_body(body: bytes, k0: int) -> bytes:
    """暗号ボディ -> 平文（DRM環境スナップショット全文）。"""
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
    """既知平文で k0 を範囲走査により回収する。見つからなければ None。"""
    n = min(len(known_prefix), len(body))
    if n == 0:
        raise ValueError("need at least one known plaintext byte")
    known = known_prefix[:n]
    for k0 in range(lo, hi):
        if _matches(body, known, k0):
            return k0
    return None
