"""
toka — 仮想マシン形式の解析ツールキット

パックされたx86イメージ内部で動作する独自の仮想マシン形式の解析で
確立した解読技法を、特定の製品に依存しない形に一般化したパッケージ。

  格納形 C --SPN連鎖--> M --rol13ローリング(K)--> S --Huffman/LZSS VM--> 平文x86

レイヤ構成:
    ciphers    下位2暗号層（SPN連鎖 + rol13 dwordローリング）
    vmcode     VMバイトコード層（Huffman復号 + LZSS型展開エンジン）
    pipeline   3段統合 + 既知平文ブートストラップ鍵回収（段階的検証）
    fastpath   任意依存 (NumPy) のベクトル化高速パス
    config     対象別プロファイル（鍵素材・テーブル・閾値の集約）
    mailslot   mailslotメッセージ復号 + k0範囲走査
    unpack     Stage1自己復号パッカー脱壳（ローリングキー + Unicorn）
    disasm     難読化x86解析支援（movabs隠蔽コード・jmp-over-jmp）
    cli        コマンドライン（python -m toka.cli）

使用例:
    from toka import Descriptor, Pipeline, load_image
    from toka.config import PROFILES
    profile = next(iter(PROFILES.values()))
    pipe = Pipeline(profile, load_image("dump.bin"))
    plain = pipe.decrypt_block(Descriptor.parse("0x1000:0x40:0x1000:0x80"))
"""
from .config import SAMPLE, PROFILES, GameConfig, get_profile
from .ciphers import Rol13, SPN, bswap32, load_sboxes, rol13_fwd_pure, rol13_inv_pure, rol32, ror32
from .vmcode import (BitReader, ExpandResult, HuffmanTable, build_table,
                     encode_stream, enumerate_prefixes_from_reference, expand,
                     simulate_command)
from .pipeline import Descriptor, Pipeline, load_image, recover_rol13_key
from .mailslot import decode_body, encode_body, recover_k0
from .unpack import (PackerDescriptor, Stage1Runner, decrypt_stream,
                     encrypt_stream, find_descriptors)
from .disasm import (MovabsSite, decode_imm64, find_jmp_over_jmp, find_movabs,
                     imm64_le, smart_disasm)
from . import fastpath

__version__ = "0.3.0"

__all__ = [
    # config
    "SAMPLE", "PROFILES", "GameConfig", "get_profile",
    # ciphers
    "Rol13", "SPN", "bswap32", "load_sboxes", "rol13_fwd_pure", "rol13_inv_pure",
    "rol32", "ror32",
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
    # fastpath
    "fastpath",
]
