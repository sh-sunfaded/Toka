"""
drmvm — DMMゲームDRM仮想マシン解析ツールキット

学マス DMM版 (gakumas.exe) のDRM逆解析（NixOS + Wine 11.21、
wine-nixキャンバス第1〜60次）で確立した解読技法を、同一保護
（PCR/ウマ娘系）へ転用可能な形に一般化したパッケージ。

  格納形 C --SPN連鎖--> M --rol13ローリング(K)--> S --Huffman/LZSS VM--> 平文x86

レイヤ構成:
    ciphers    下位2暗号層（SPN連鎖 + rol13 dwordローリング）
    vmcode     VMバイトコード層（Huffman復号 + LZSS型展開エンジン）
    pipeline   3段統合 + 既知平文ブートストラップ鍵回収
    config     ゲーム別プロファイル（鍵素材・テーブル・閾値の集約）
    mailslot   mailslot報告ボディ復号 + k0範囲走査
    unpack     Stage1自己復号パッカー脱壳（ローリングキー + Unicorn）
    disasm     難読化x86解析支援（movabs隠蔽コード・jmp-over-jmp）
    patches    wineメモリパッチ定義 + 適用検証（Patch-L/G）
    cli        コマンドライン（python -m drmvm.cli）

使用例:
    from drmvm import Descriptor, Pipeline, load_image
    from drmvm.config import GAKUMAS
    pipe = Pipeline(GAKUMAS, load_image("dump1.bin"))
    plain = pipe.decrypt_block(Descriptor.parse("0xb39ec:0xc12:0xb39ec:0x14bc"))
"""
from .config import GAKUMAS, PROFILES, GameConfig, get_profile
from .ciphers import Rol13, SPN, bswap32, load_sboxes, rol32, ror32
from .vmcode import (BitReader, ExpandResult, HuffmanTable, build_table,
                     encode_stream, enumerate_prefixes_from_reference, expand,
                     simulate_command)
from .pipeline import Descriptor, Pipeline, load_image, recover_rol13_key
from .mailslot import decode_body, encode_body, recover_k0
from .unpack import (PackerDescriptor, Stage1Runner, decrypt_stream,
                     encrypt_stream, find_descriptors)
from .disasm import (MovabsSite, decode_imm64, find_jmp_over_jmp, find_movabs,
                     imm64_le, smart_disasm)
from .patches import (GAKUMAS_PATCH_G, Patch, PatchStatus, filter_patch_l_by_lea,
                      find_patch_l_candidates, scan_pattern, verify_patch,
                      verify_patchset)

__version__ = "0.1.0"

__all__ = [
    # config
    "GAKUMAS", "PROFILES", "GameConfig", "get_profile",
    # ciphers
    "Rol13", "SPN", "bswap32", "load_sboxes", "rol32", "ror32",
    # vmcode
    "BitReader", "ExpandResult", "HuffmanTable", "build_table", "encode_stream",
    "enumerate_prefixes_from_reference", "expand", "simulate_command",
    # pipeline
    "Descriptor", "Pipeline", "load_image", "recover_rol13_key",
    # mailslot
    "decode_body", "encode_body", "recover_k0",
    # unpack
    "PackerDescriptor", "Stage1Runner", "decrypt_stream", "encrypt_stream",
    "find_descriptors",
    # disasm
    "MovabsSite", "decode_imm64", "find_jmp_over_jmp", "find_movabs",
    "imm64_le", "smart_disasm",
    # patches
    "GAKUMAS_PATCH_G", "Patch", "PatchStatus", "filter_patch_l_by_lea",
    "find_patch_l_candidates", "scan_pattern", "verify_patch", "verify_patchset",
]
