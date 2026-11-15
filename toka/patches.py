"""
toka.patches — 既知バイトパターンの定義と状態検証

パターン適用の対象は実行時復号領域に存在するため、適用検証は
メモリダンプイメージ（RVA==オフセット）に対して行う。

各パッチは (rva, origバイト列, newバイト列) で定義し、verify は
ダンプに対して状態を分類する:
    ORIG_MATCH      : 元バイト列が見える = 未適用（適用候補）
    ALREADY_PATCHED : newバイト列が見える = 適用済み
    NOT_PRESENT     : どちらも無い = 実行時復号前 or 別フェーズ
    MISMATCH        : その位置に別のバイト列 = 誤アドレス/版違い

サンプル定義: hi32比較命令列 (shr rdx,0x20) の走査と、
既知分岐サイト (rva 0xddeb8, 75 0a -> 90 90) の検証。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, NamedTuple, Optional


@dataclass(frozen=True)
class Patch:
    rva: int
    orig: bytes
    new: bytes
    note: str = ""

    def __str__(self) -> str:
        return (f"rva={self.rva:#x} {self.orig.hex()} -> {self.new.hex()}"
                f"{'  # ' + self.note if self.note else ''}")


class PatchStatus(NamedTuple):
    patch: Patch
    status: str  # ORIG_MATCH / ALREADY_PATCHED / NOT_PRESENT / MISMATCH
    detail: str = ""


def scan_pattern(image: bytes, pattern: bytes, limit: Optional[int] = None) -> List[int]:
    """イメージ内のパターン出現位置（= RVA）を全列挙する。"""
    hits: List[int] = []
    off = image.find(pattern)
    while off != -1:
        hits.append(off)
        if limit is not None and len(hits) >= limit:
            break
        off = image.find(pattern, off + 1)
    return hits


def verify_patch(image: bytes, patch: Patch) -> PatchStatus:
    """単一パッチの状態検証。"""
    at = image[patch.rva:patch.rva + len(patch.orig)]
    if not at:
        return PatchStatus(patch, "NOT_PRESENT", "rva outside image")
    if at == patch.orig:
        return PatchStatus(patch, "ORIG_MATCH", "unpatched, ready")
    if image[patch.rva:patch.rva + len(patch.new)] == patch.new:
        return PatchStatus(patch, "ALREADY_PATCHED", "patched")
    return PatchStatus(patch, "MISMATCH", f"found {at.hex()}")


def verify_patchset(image: bytes, patches: Iterable[Patch]) -> List[PatchStatus]:
    """パッチ群の一括検証レポート。"""
    return [verify_patch(image, p) for p in patches]


# --------------------------------------------------------------------------
# 実測ベースのサンプル定義
# --------------------------------------------------------------------------

# hi32比較命令列: lea rdx,[rsp+X]; shr rdx,0x20; call の形で現れる検知点の
#   共通パターン。shr rdx,0x20 (48 c1 ea 20) を
#   xor edx,edx + 2nop (33 d2 90 90) に置換する（hi32が常に0である規約と
#   意味等価になる）。
PATCH_L_SIG = b"\x48\xc1\xea\x20"       # shr rdx, 0x20
PATCH_L_NEW = b"\x33\xd2\x90\x90"       # xor edx, edx; nop; nop


def find_patch_l_candidates(image: bytes) -> List[int]:
    """イメージ内の候補（shr rdx,0x20 の位置）を列挙する。

    検知点との選別は「直前が lea rdx,[rsp+X]（48 8d 54/94 24）」の確認で
    行う。平文時点のダンプでのみ見つかる点に注意
    （暗号領域には出現しない = NOT_PRESENT 相当）。
    """
    return scan_pattern(image, PATCH_L_SIG)


def filter_patch_l_by_lea(image: bytes, candidates: Iterable[int]) -> List[int]:
    """候補のうち直前に lea rdx,[rsp+disp] を持つものだけに絞り込む。"""
    keep = []
    for h in candidates:
        before = image[max(0, h - 8):h]
        if b"\x48\x8d\x54\x24" in before or b"\x48\x8d\x94\x24" in before:
            keep.append(h)
    return keep


# 既知分岐サイト: 特定条件で早期リターンするパスの無条件化
#   cmp byte [entry+0x10], 0; jnz <handler path>  (0xddeb8: 75 0a)
#   → nop化で正規の早期リターン (mov eax,1; add rsp,0x68; ret) を常時通る。
SAMPLE_PATCH_G = Patch(
    rva=0xDDEB8, orig=b"\x75\x0a", new=b"\x90\x90",
    note="known branch site: always take the early-return path",
)
