"""
toka.fastpath — 任意依存 (NumPy) による高速化レイヤ

コアは一貫して標準ライブラリのみで動作する。NumPy が導入されている
環境では暗号層のホットパスが自動的にベクトル化実装に切り替わる。
両者の結果の等価性は tests の等価性検証で担保する（NumPy が無い
環境では当該テストはスキップされる）。

高速化の狙いどころ:

  - rol13 fwd/inv（dwordローリング）
      鍵ストリーム esi_i = K + i*(i-1)/2 は閉形式なので、
      データ全体を一括ベクトル化できる。
  - SPN連鎖 out_i = T(in_i) ^ in_{i-1}
      T(in_i) は全ブロック独立なので、ブロック一括処理 + 隣接XORで
      逐次ループを排除できる。
  - mailslot k0 範囲走査
      候補ごとの鍵更新列は候補軸で独立。候補配列全体の状態を
      一括して進めることで、Pythonループを排除する。
  - ブートストラップ鍵回収
      候補 × 先頭ウィンドウの rol13 を一括計算し、先頭数シンボルで
      棄却する（toka.pipeline の段階的検証と組み合わせる）。

ベクトル化しない箇所（逐次依存が本質的）:

  - Stage0 ローリングキー復号（鍵更新に加算キャリーが絡む逐次再帰）
  - Huffman/LZSS 展開（ビット毎の状態機械）
"""
from __future__ import annotations

from typing import List, Optional, Sequence

try:
    import numpy as _np
    HAVE_NUMPY = True
except ImportError:  # pragma: no cover - 環境依存
    _np = None
    HAVE_NUMPY = False

M32 = 0xFFFFFFFF


def _require_numpy() -> None:
    if _np is None:
        raise RuntimeError("toka.fastpath requires numpy (not installed)")


def _u32(v: int):
    """NumPy uint32 スカラー（dtype 保存のため明示的に包む）。"""
    return _np.uint32(v & M32)


def _tri32(n: int):
    """i*(i-1)/2 mod 2^32 の配列（uint32）。esi_i = K + tri_i に対応。"""
    i = _np.arange(n, dtype=_np.uint64)
    tri = (i * (i - 1)) // 2          # i=0,1 は 0（i-1 のwrapも積で消える）
    return (tri & M32).astype(_np.uint32)


def rol13_fwd(key: int, data: bytes) -> bytes:
    """Rol13 fwd のベクトル化。端数バイトはそのまま通す。"""
    _require_numpy()
    n = len(data) >> 2
    if n == 0:
        return bytes(data)
    x = _np.frombuffer(data, dtype=_np.uint32, count=n)
    esi = _u32(key) + _tri32(n)
    y = x ^ esi
    rol = (y << _u32(13)) | (y >> _u32(19))
    out = rol - _np.arange(n, dtype=_np.uint32)
    return out.tobytes() + data[n * 4:]


def rol13_inv(key: int, data: bytes) -> bytes:
    """Rol13 inv のベクトル化。"""
    _require_numpy()
    n = len(data) >> 2
    if n == 0:
        return bytes(data)
    x = _np.frombuffer(data, dtype=_np.uint32, count=n)
    esi = _u32(key) + _tri32(n)
    y = x + _np.arange(n, dtype=_np.uint32)
    ror = (y >> _u32(13)) | (y << _u32(19))
    out = ror ^ esi
    return out.tobytes() + data[n * 4:]


def rol13_fwd_batch(data: bytes, keys: Sequence[int]) -> List[bytes]:
    """複数鍵で rol13 fwd を一括計算し、鍵ごとのストリーム列を返す。

    ブートストラップ鍵回収の段階的検証（先頭ウィンドウ棄却）用。
    """
    _require_numpy()
    n = len(data) >> 2
    nk = len(keys)
    if n == 0:
        return [b""] * nk
    x = _np.frombuffer(data, dtype=_np.uint32, count=n)
    k = _np.asarray(keys, dtype=_np.uint32).reshape(nk, 1)
    esi = k + _tri32(n)[None, :]
    y = x[None, :] ^ esi
    rol = (y << _u32(13)) | (y >> _u32(19))
    out = rol - _np.arange(n, dtype=_np.uint32)[None, :]
    raw = out.tobytes()                      # 行優先: 鍵iの n dword が連続
    w = n * 4
    return [raw[i * w:(i + 1) * w] for i in range(nk)]


def _bswap32(a):
    """uint32 配列のバイトスワップ（ビット演算のみ・view不使用）。"""
    x = a
    return (((x & _u32(0x000000FF)) << _u32(24))
            | ((x & _u32(0x0000FF00)) << _u32(8))
            | ((x & _u32(0x00FF0000)) >> _u32(8))
            | (x >> _u32(24)))


def spn_chain_fwd(key_material: bytes, rounds: int,
                  sboxes: Sequence[Sequence[int]], data: bytes) -> bytes:
    """SPN連鎖 chain_fwd のベクトル化（既定T想定・ブロック一括処理）。

    out_i = T(in_i) ^ in_{i-1}（prev 初期値 0、連鎖には前ブロック入力）。
    floor(size/16) ブロックのみ変換、端数は無処理。
    """
    _require_numpy()
    nb = len(data) >> 4
    if nb == 0:
        return bytes(data)
    ins = _np.frombuffer(data, dtype=_np.uint32, count=nb * 4).reshape(nb, 4)
    sb = [_np.asarray(s, dtype=_np.uint32) for s in sboxes]
    d = ins.copy()
    for r in range(rounds):
        pre = _np.frombuffer(key_material, dtype=_np.uint32, count=4,
                             offset=4 + 0x20 * r)
        post = _np.frombuffer(key_material, dtype=_np.uint32, count=4,
                              offset=4 + 0x20 * r + 0x10)
        # (1) bswap + 前半ラウンド鍵
        d = _bswap32(d) ^ pre[None, :]
        # (2) S-box 4枚: 各バイト j → dword[j//4] ^= sbox[j//4][byte_j]
        for j in range(16):
            di = j >> 2
            sh = _u32(8 * (j & 3))
            b = ((d[:, di] >> sh) & _u32(0xFF)).astype(_np.uint8)
            d[:, di] ^= sb[di][b]
        # (3) 後半ラウンド鍵
        d ^= post[None, :]
    # 連鎖: out_i = T(in_i) ^ in_{i-1}
    d[1:] ^= ins[:-1]
    return d.tobytes() + data[nb * 16:]


def _ror32(a, n: int):
    return (a >> _u32(n)) | (a << _u32(32 - n))


def recover_k0(body: bytes, known_prefix: bytes, lo: int, hi: int,
               chunk: int = 1 << 20) -> Optional[int]:
    """mailslot k0 範囲走査のベクトル化。

    候補全体の鍵状態を一括で進め、既知平文との一致で絞り込む。
    c[i] ^ (k & 0xff) == known[i] は (k & 0xff) == c[i] ^ known[i] と等価。
    見つからなければ None（純実装と同じ戻り値）。
    """
    _require_numpy()
    n = min(len(known_prefix), len(body))
    for base in range(lo, hi, chunk):
        stop = min(base + chunk, hi)
        ks = _np.arange(base, stop, dtype=_np.uint64).astype(_np.uint32)
        mask = _np.ones(len(ks), dtype=bool)
        k = ks
        for i in range(n):
            want = _np.uint8(body[i] ^ known_prefix[i])
            mask &= (k & _u32(0xFF)).astype(_np.uint8) == want
            if not mask.any():
                break
            if i + 1 < n:
                k = _ror32(k + _u32(i), 7)
        hits = _np.flatnonzero(mask)
        if len(hits):
            return int(ks[hits[0]])
    return None
