"""
toka.unpack — KONN形式 自己復号パッカー（Stage0→Stage1）の脱壳

パッカー構造（KONN形式の不変量）:
  パック済みデータ --MapViewOfFile--> descriptor(8×i32, sig 0x4E4E4F4B,
  stride 0x20, 実行時にスタックへ復号) --> ローリングキー復号 -->
  Stage1（復号済みコード領域・OEP はプロファイル指定） -->
  Stage2 = バイトコードVM（VEH依存のオンデマンド復号で静的エミュレーション
  不可 → toka.pipeline で扱う）

ローリングキー復号（dwordストリーム）:
    key0 = (~size + initKey) & 0xffffffff
    plain_i = key_i ^ chunk_i
    key_{i+1} = (i^2) ^ (chunk_i + i + key_i)      ※ chunk は暗文側の値
  順方向（encrypt）も同型で可逆のため、roundtrip検証が可能。
  ※ 鍵更新に加算キャリーが絡む逐次再帰のため、この層はベクトル化しない。

Stage1 実行エミュレーションは Unicorn が導入されている環境でのみ動作
（任意依存）。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Tuple

M32 = 0xFFFFFFFF
DESCRIPTOR_SIG = 0x4E4E4F4B


def decrypt_stream(data: bytes, size: int, init_key: int) -> bytes:
    """ローリングキー復号（plain = key ^ chunk, key = i^2 ^ (chunk+i+key)）。"""
    key = (~size + init_key) & M32
    out = bytearray(len(data))
    for i in range(len(data) >> 2):
        (chunk,) = struct.unpack_from("<I", data, i * 4)
        struct.pack_into("<I", out, i * 4, key ^ chunk)
        key = ((i * i) ^ ((chunk + i + key) & M32)) & M32
    out[len(data) & ~3:] = data[len(data) & ~3:]
    return bytes(out)


def encrypt_stream(data: bytes, size: int, init_key: int) -> bytes:
    """順方向（テスト・再パック検証用）。decrypt_stream と可逆。"""
    key = (~size + init_key) & M32
    out = bytearray(len(data))
    for i in range(len(data) >> 2):
        (plain,) = struct.unpack_from("<I", data, i * 4)
        chunk = key ^ plain
        struct.pack_into("<I", out, i * 4, chunk)
        key = ((i * i) ^ ((chunk + i + key) & M32)) & M32
    out[len(data) & ~3:] = data[len(data) & ~3:]
    return bytes(out)


@dataclass(frozen=True)
class PackerDescriptor:
    offset: int
    fields: Tuple[int, ...]  # 8 × i32

    @property
    def sig(self) -> int:
        return self.fields[0]


def find_descriptors(data: bytes, sig: int = DESCRIPTOR_SIG,
                    expect_fields: int = 8) -> List[PackerDescriptor]:
    """イメージ中の記述子（sig で始まる 8×i32 塊、4バイト境界）を列挙する。"""
    found: List[PackerDescriptor] = []
    for off in range(0, len(data) - 4 * expect_fields + 1, 4):
        (v,) = struct.unpack_from("<I", data, off)
        if v == sig:
            fields = struct.unpack_from("<8I", data, off)
            found.append(PackerDescriptor(off, fields))
    return found


class Stage1Runner:
    """Unicorn による Stage1 エミュレーション → 復号済みイメージの採取。

    image_base / oep / region は GameConfig（toka.config）から与える。
    Unicorn が無い環境では RuntimeError。
    注意（エミュレーション実装の教訓）: コードフック内の RIP 直接書換のみ
    有効（begin=end+1）、INTR フック redirect / emu_stop 後 resume は不可、
    0x7FF00000 番地はマップ不可。
    """

    def __init__(self, image_base: int, oep: int, region: Tuple[int, int],
                 stack_base: int = 0x200000, stack_size: int = 0x200000):
        self.image_base = image_base
        self.oep = oep
        self.region = region
        self.stack_base = stack_base
        self.stack_size = stack_size

    def run(self, packed_image: bytes, entry: int, timeout_ms: int = 30_000) -> bytes:
        try:
            import unicorn  # type: ignore
        except ImportError as e:
            raise RuntimeError("Stage1 emulation requires the 'unicorn' package") from e
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        size = len(packed_image)
        uc.mem_map(self.image_base, (size + 0xFFF) & ~0xFFF)
        uc.mem_write(self.image_base, packed_image)
        uc.mem_map(self.stack_base, self.stack_size)
        uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP,
                     self.stack_base + self.stack_size - 0x1000)
        reached = [False]

        def hook_code(uc_, address, size_, user):
            if address == self.oep:
                reached[0] = True
                uc_.emu_stop()

        uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)
        uc.emu_start(entry, 0, timeout=timeout_ms * 1000)
        if not reached[0]:
            raise RuntimeError("OEP not reached within timeout")
        lo, hi = self.region
        return uc.mem_read(self.image_base + lo, hi - lo)
