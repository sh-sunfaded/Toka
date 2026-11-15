"""
drmvm.config — ゲーム別設定（プロファイル）

同一保護（学マス DMM版 / PCR / ウマ娘系）は鍵素材・テーブル・閾値が
異なるだけでパイプライン構造は共通。全ゲーム依存値はここに集約する。

GAKUMAS プロファイルの値はすべて学マス実測（フェーズAF/AG/AH、
2026-11 版 md5 f4859cea1de70fa17ab0ca2cfb36880d に対応）。
他タイトルを攻略する場合は実測値を調査して GameConfig を1つ追加する。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class GameConfig:
    name: str
    image_base: int = 0x140000000
    # SPN鍵 / Huffman表: (rva, size) の高域・低域ペア（閾値で選択）
    spn_key_high: Tuple[int, int] = (0x106256, 0xF4)
    spn_key_low: Tuple[int, int] = (0x1054C0, 0xF4)
    huff_table_high: Tuple[int, int] = (0x1055B4, 0xCA2)
    huff_table_low: Tuple[int, int] = (0x104800, 0xCC0)
    expand_threshold: int = 0xA8000  # dword@0x1400ba2f4
    sbox_rvas: Tuple[int, ...] = (0xC82E0, 0xC86E0, 0xC8AE0, 0xC8EE0)
    rol13_key: Optional[int] = None  # 実測済みならここに（学マス=0xaf27a866）
    descriptors: Dict[str, Tuple[int, int, int, int]] = field(default_factory=dict)
    mailslot_name: str = ""
    # Stage1（自己復号パッカー）関連
    stage1_region: Tuple[int, int] = (0xA8000, 0xEC000)
    stage1_oep: int = 0x1400AA8A0
    descriptor_sig: int = 0x4E4E4F4B  # LE bytes 4B 4F 4E 4E

    def key_pair(self, off2: int) -> Tuple[int, int, int, int]:
        """off2 → (SPN鍵rva, size, Huffman表rva, size)。閾値で分岐。"""
        if off2 >= self.expand_threshold:
            k = self.spn_key_high
            t = self.huff_table_high
        else:
            k = self.spn_key_low
            t = self.huff_table_low
        return (k[0], k[1], t[0], t[1])

    def desc(self, name: str) -> Tuple[int, int, int, int]:
        return self.descriptors[name]


GAKUMAS = GameConfig(
    name="gakumas",
    rol13_key=0xAF27A866,  # 第58次AH回収値（実行時導出・決定論的）
    descriptors={
        # idx13: 280チェック実行部（REF）。dump1格納形 ↔ v1d展開形の既知対
        "idx13": (0xB39EC, 0xC12, 0xB39EC, 0x14BC),
    },
    mailslot_name="ErrLog-Pec02AF",
)

PROFILES: Dict[str, GameConfig] = {"gakumas": GAKUMAS}


def get_profile(name: str) -> GameConfig:
    if name not in PROFILES:
        raise KeyError(f"unknown profile {name!r}; available: {sorted(PROFILES)}")
    return PROFILES[name]
