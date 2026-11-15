"""
drmvm.patches — パッチテーブルと適用検証

wine側メモリパッチ（poll-and-patch）の対象は「実行時復号領域」に
存在するため、適用検証はダンプイメージ（RVA==オフセット）に対して
行う（第60次: verify_patches.py の手法を一般化）。

各パッチは (rva, origバイト列, newバイト列) で定義し、verify は
ダンプに対して状態を分類する:
    ORIG_MATCH      : 元バイト列が見える = パッチ未適用（適用候補）
    ALREADY_PATCHED : newバイト列が見える = 適用済み
    NOT_PRESENT     : どちらも無い = 実行時復号前 or 別フェーズ
    MISMATCH        : その位置に別のバイト列 = 誤アドレス/版違い

Patch-L の33箇所は「lea rdx,[rsp+X]; shr rdx,0x20; call」パターン
（wineで第2引数hi32=0x6fffになるのを悪用する地雷）を、パターン走査で
ダンプから自動列挙できる。Patch-G（Htsysm02AF常時合格化）の実測値も定義済み。
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
# 学マス実測パッチ定義（第59/60次）
# --------------------------------------------------------------------------

# Patch-L: アンチWine地雷族 33箇所の共通パターン。
#   lea rcx/rdx,[rsp+X]; shr rdx,0x20; call → 第2引数hi32がwineでは0x6fff。
#   shr rdx,0x20 (48 c1 ea 20) を xor edx,edx + 2nop (33 d2 90 90) に
#   置換する（Windows意味完全等価）。
PATCH_L_SIG = b"\x48\xc1\xea\x20"       # shr rdx, 0x20
PATCH_L_NEW = b"\x33\xd2\x90\x90"       # xor edx, edx; nop; nop


def find_patch_l_candidates(image: bytes) -> List[int]:
    """ダンプ内の Patch-L 候補（shr rdx,0x20 の位置）を列挙する。

    本物の地雷33箇所との選別は「直前が lea rdx,[rsp+X]（48 8d 54/94 24）」
    の確認と、既知グループ（[0xDA650]9 / [0xDFA38]3 / [0xE8430]14 / 直接7）
    との照合で行う。平文時点のダンプでのみ見つかる点に注意
    （暗号領域は出現しない = NOT_PRESENT 相当）。
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


# Patch-G: Htsysm02AF 存在検査の無条件合格化（第59次特定・第60次バイト訂正済み）。
#   cmp byte [entry+0x10], 0; jnz <driver path>  (0xddeb8: 75 0a)
#   → nop化で mov eax,1; add rsp,0x68; ret を常時通る。
GAKUMAS_PATCH_G = Patch(
    rva=0xDDEB8, orig=b"\x75\x0a", new=b"\x90\x90",
    note="Htsysm02AF: bypass driver-existence check (always return 1)",
)

# 代替 Patch-T（診断用格下げ）: [0xCCC00]=0 一括無力化は
# 他の正当経路参照の可能性があるため本線では使わない。
