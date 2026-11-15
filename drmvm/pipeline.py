"""
drmvm.pipeline — 3段パイプライン統合と鍵回収（ブートストラップ）

  格納形 C --SPN chain_fwd--> M --rol13 fwd(K)--> S --expand--> 平文x86

  格納形   = ダンプ内の VM バイトコードブロック（dump1 の 0xb39ec:+0xc12 など）
  M        = SPN連鎖直後（Huffman圧縮 + rol13 の前段）
  S        = rol13 出力 = Huffman/LZSS ビットストリーム
  平文x86  = v1d（280ログ時点ダンプ）の展開形と一致検証する相手

記述子: {off1, size1, off2, size2}（idx13 = 0xb39ec:0xc12:0xb39ec:0x14bc）。
鍵・テーブル選択: off2 >= 閾値(0xa8000) → 高域ペア (SPN鍵 0x106256 /
Huffman表 0x1055b4)、未満 → 低域ペア (0x1054c0 / 0x104800)。

鍵回収 = 既知平文ブートストラップ（第58次AH開発、2^32総当たり不要）:
  (1) Huffman表から全シンボル符号を再構築し、「既知展開結果の先頭を
      再現するコマンド列」をDFS列挙してストリーム先頭32bit候補を網羅
      （実測14028候補）
  (2) 各候補 S0 から K = M0 ^ ror32(S0, 13) を導出
  (3) K で全ストリームを rol13 fwd → expand し、既知の展開結果と一致検証
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .ciphers import Rol13, SPN, load_sboxes
from .config import GameConfig
from .vmcode import HuffmanTable, enumerate_prefixes_from_reference, expand


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
    """ダンプイメージを読み込む。GKM_DUMP 由来の先頭テキストヘッダ
    （"REGION image addr=..." 行）を検出したら除去する。
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

        desc: 対象ブロック記述子。ref_expanded: 既知の展開結果（v1d など）。
        戻り値: 回収された K。失敗時 None。
        """
        stored = self.image[desc.off1:desc.off1 + desc.size1]
        auto_spn, table = self._table_for(desc.off2)
        M = (spn if spn is not None else auto_spn).chain_fwd(stored)
        return recover_rol13_key(M, ref_expanded, desc.size2, table,
                                 verbose=verbose)


def recover_rol13_key(M: bytes, ref_expanded: bytes, out_size: int,
                      table: HuffmanTable, verbose: bool = False) -> Optional[int]:
    """SPN通過済みストリーム M から鍵を回収する（下位ルーチン）。

    M: SPN連鎖直後のバイト列。ref_expanded: 展開結果の既知平文。
    out_size: 展開後サイズ（記述子 size2）。
    """
    (m0,) = struct.unpack_from("<I", M, 0)
    ref = ref_expanded[:out_size]
    candidates = enumerate_prefixes_from_reference(table, ref, min_bits=32)
    if verbose:
        print(f"[bootstrap] {len(candidates)} S0 candidates")
    for s0 in candidates:
        key = Rol13.derive_key(m0, s0)
        S = Rol13(key).fwd(M)
        try:
            res = expand(S, out_size, table)
        except (ValueError, IndexError):
            continue  # ゴミストリーム: 表と整合しない候補は読み飛ばす
        if res.ok and res.out == ref:
            return key
    return None
