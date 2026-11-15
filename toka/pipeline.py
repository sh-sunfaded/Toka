"""
toka.pipeline — 3段パイプライン統合と鍵回収（ブートストラップ）

  格納形 C --SPN chain_fwd--> M --rol13 fwd(K)--> S --expand--> 平文x86

  格納形   = ダンプ内の VM バイトコードブロック
  M        = SPN連鎖直後（Huffman圧縮 + rol13 の前段）
  S        = rol13 出力 = Huffman/LZSS ビットストリーム
  平文x86  = 既知の展開結果ダンプと一致検証する相手

記述子: {off1, size1, off2, size2}（実測例 = 0xb39ec:0xc12:0xb39ec:0x14bc）。
鍵・テーブル選択: off2 >= 閾値(0xa8000) → 高域ペア (SPN鍵 0x106256 /
Huffman表 0x1055b4)、未満 → 低域ペア (0x1054c0 / 0x104800)。

鍵回収 = 既知平文ブートストラップ（2^32総当たり不要）:
  (1) Huffman表から全シンボル符号を再構築し、「既知展開結果の先頭を
      再現するコマンド列」をDFS列挙してストリーム先頭32bit候補を網羅
      （実測では数千候補に収まる）
  (2) 各候補 S0 から K = M0 ^ ror32(S0, 13) を導出
  (3) K でストリームを rol13 fwd → expand し、既知の展開結果と一致検証

最適化（本モジュール）: (3) を段階的検証にする。
  各候補について全ストリームの rol13 fwd + 全展開を行う代わりに、
  先頭ウィンドウ（既定8 dword）だけを計算し、
    - 展開が ref と矛盾する/命令が拒否される → 即棄却
    - ウィンドウを使い切った場合のみフル検証
  の2段で処理する。ゴミ候補のほとんどは最初の数シンボルで棄却される
  ため、候補数にほぼ比例した高速化となる（結果は単純実装と同一）。
  NumPy があれば先頭ウィンドウの一括計算に toka.fastpath を使う。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from . import fastpath
from .ciphers import Rol13, SPN, load_sboxes, rol13_fwd_pure
from .config import GameConfig
from .vmcode import (BitReader, HuffmanTable, enumerate_prefixes_from_reference,
                     expand, simulate_command)


@dataclass(frozen=True)
class Descriptor:
    """VMブロック記述子 {off1, size1, off2, size2}。"""
    off1: int
    size1: int
    off2: int
    size2: int

    @classmethod
    def parse(cls, spec: str) -> "Descriptor":
        """"0xb39ec:0xc12:0xb39ec:0x14bc" 形式の文字列から構築。"""
        parts = [int(p, 0) for p in spec.split(":")]
        if len(parts) != 4:
            raise ValueError(f"descriptor needs 4 fields: {spec!r}")
        return cls(*parts)

    def __str__(self) -> str:
        return f"{self.off1:#x}:{self.size1:#x}:{self.off2:#x}:{self.size2:#x}"


def load_image(path: str) -> bytes:
    """ダンプイメージを読み込む。採取ツール由来の先頭テキストヘッダ
    （"REGION ..." 行）を検出したら除去する。
    除去後は RVA == ファイルオフセット。
    """
    with open(path, "rb") as f:
        data = f.read()
    if data.startswith(b"REGION "):
        nl = data.find(b"\n")
        if nl != -1:
            return data[nl + 1:]
    return data


class Pipeline:
    """3段パイプライン。イメージ（ダンプ）から鍵素材とHuffman表を取る。

    SPN は原則としてイメージ内の鍵素材+S-boxから自動構築するが、
    テストや「SPN通過済みの M が手元にある」場合は decrypt_block /
    recover_key に spn を明示渡し（恒等Tなど）できる。
    """

    def __init__(self, cfg: GameConfig, image: bytes):
        self.cfg = cfg
        self.image = bytes(image)
        self._tables: Dict[Tuple[int, int], Tuple[SPN, HuffmanTable]] = {}

    # ------------------------------------------------------------ 構成部品

    def _table_for(self, off2: int) -> Tuple[SPN, HuffmanTable]:
        key_rva, key_size, tbl_rva, tbl_size = self.cfg.key_pair(off2)
        cache_key = (key_rva, tbl_rva)
        if cache_key not in self._tables:
            key = self.image[key_rva:key_rva + key_size]
            sboxes = load_sboxes(self.image, self.cfg.sbox_rvas)
            spn = SPN(key, sboxes=sboxes)
            table = HuffmanTable(self.image[tbl_rva:tbl_rva + tbl_size])
            self._tables[cache_key] = (spn, table)
        return self._tables[cache_key]

    # ------------------------------------------------------------ 復号

    def decrypt_block(self, desc: Descriptor, rol13_key: Optional[int] = None,
                      spn: Optional[SPN] = None) -> bytes:
        """格納形ブロックを3段パイプラインで展開する。

        rol13_key=None なら cfg.rol13_key を使う。戻り値 = 展開済み平文。
        展開が失敗した場合は RuntimeError。
        """
        if rol13_key is None:
            rol13_key = self.cfg.rol13_key
        if rol13_key is None:
            raise ValueError("rol13 key unknown — run recover_key() first")
        stored = self.image[desc.off1:desc.off1 + desc.size1]
        if len(stored) != desc.size1:
            raise ValueError("block truncated in image")
        auto_spn, table = self._table_for(desc.off2)
        M = (spn if spn is not None else auto_spn).chain_fwd(stored)
        S = Rol13(rol13_key).fwd(M)
        res = expand(S, desc.size2, table)
        if not res.ok:
            raise RuntimeError(f"expand failed at {res.error}")
        return res.out

    # ------------------------------------------------------------ 鍵回収

    def recover_key(self, desc: Descriptor, ref_expanded: bytes,
                    spn: Optional[SPN] = None,
                    verbose: bool = False) -> Optional[int]:
        """既知平文ブートストラップで rol13 鍵 K を回収する。

        desc: 対象ブロック記述子。ref_expanded: 既知の展開結果。
        戻り値: 回収された K。失敗時 None。
        """
        stored = self.image[desc.off1:desc.off1 + desc.size1]
        auto_spn, table = self._table_for(desc.off2)
        M = (spn if spn is not None else auto_spn).chain_fwd(stored)
        return recover_rol13_key(M, ref_expanded, desc.size2, table,
                                 verbose=verbose)


def _probe_window(S_win: bytes, ref: bytes, out_size: int,
                  table: HuffmanTable) -> Optional[bool]:
    """先頭ウィンドウのみで展開を試みる段階検証（棄却フィルタ）。

    戻り値:
        False : ref との矛盾・命令拒否・表破損で棄却。
        None  : ウィンドウを使い切った（フル検証が必要）。
        True  : out_size に到達し ref 前置きと一致（フル検証で確定）。

    expand() と decode_symbol / simulate_command を共有するため、
    命令意味論は単一の真実源のまま変えていない。
    """
    reader = BitReader(S_win)
    out = bytearray()
    acc = 0
    while len(out) < out_size:
        try:
            sym = table.decode_symbol(reader)
        except IndexError:
            return None       # ウィンドウ枯渇 → フル検証へ
        except ValueError:
            return False      # ゴミストリーム（表と不整合）→ 棄却
        okflag, emit, acc = simulate_command(sym & 0x300, sym & 0xFF,
                                            bytes(out), acc, out_size)
        if not okflag:
            return False
        new = out + emit
        if ref[:len(new)] != new:
            return False      # 既知平文との矛盾 → 棄却
        out = new
    return True


def _verify_full(key: int, M: bytes, ref: bytes, out_size: int,
                 table: HuffmanTable) -> bool:
    """全ストリームでの rol13 fwd + expand による最終検証。"""
    S = Rol13(key).fwd(M)
    try:
        res = expand(S, out_size, table)
    except (ValueError, IndexError):
        return False
    return bool(res.ok and res.out == ref)


def recover_rol13_key(M: bytes, ref_expanded: bytes, out_size: int,
                      table: HuffmanTable, verbose: bool = False,
                      window_dwords: int = 8) -> Optional[int]:
    """SPN通過済みストリーム M から鍵を回収する（段階的検証・既定）。

    M: SPN連鎖直後のバイト列。ref_expanded: 展開結果の既知平文。
    out_size: 展開後サイズ（記述子 size2）。
    window_dwords: 段階的検証の先頭ウィンドウ幅（dword数）。

    各候補は (1) 先頭ウィンドウのみの展開で棄却 → (2) 生き残りのみ
    フル検証、の2段で処理される。結果は _recover_naive と同一。
    """
    (m0,) = struct.unpack_from("<I", M, 0)
    ref = ref_expanded[:out_size]
    candidates = enumerate_prefixes_from_reference(table, ref, min_bits=32)
    if verbose:
        print(f"[bootstrap] {len(candidates)} S0 candidates")
    keys = [Rol13.derive_key(m0, s0) for s0 in candidates]
    wd = max(1, min(window_dwords, len(M) >> 2))
    win = M[:wd * 4]
    if fastpath.HAVE_NUMPY and len(keys) > 1:
        windows: Sequence[bytes] = fastpath.rol13_fwd_batch(win, keys)
    else:
        windows = [rol13_fwd_pure(k, win) for k in keys]
    for key, s_win in zip(keys, windows):
        probe = _probe_window(s_win, ref, out_size, table)
        if probe is False:
            continue
        if _verify_full(key, M, ref, out_size, table):
            return key
    return None


def _recover_naive(M: bytes, ref_expanded: bytes, out_size: int,
                   table: HuffmanTable) -> Optional[int]:
    """単純全数検証（等価性テスト用の参照実装）。

    recover_rol13_key の最適化前のロジック。結果は同一であることが
    テストで担保される。
    """
    (m0,) = struct.unpack_from("<I", M, 0)
    ref = ref_expanded[:out_size]
    for s0 in enumerate_prefixes_from_reference(table, ref, min_bits=32):
        key = Rol13.derive_key(m0, s0)
        if _verify_full(key, M, ref, out_size, table):
            return key
    return None
