#!/usr/bin/env python3
"""toka 自動検証スイート。

純標準ライブラリのみ・外部ダンプ不要で、パッケージ全体の意味論を
合成データで検証する（実データとの突合はREADMEの実機検証チェックリスト参照）。

NumPy が導入されている環境では、ベクトル化実装（toka.fastpath）と
純Python実装の等価性検証も自動実行される。無い環境ではスキップされる。

実行:  python3 tests/test_toka.py   （終了コード 0=全PASS）
"""
import os
import random
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toka import (Descriptor, SAMPLE, HuffmanTable, Pipeline, Rol13, SPN,
                   build_table, decode_body, decrypt_stream, encode_body,
                   encrypt_stream, enumerate_prefixes_from_reference, expand,
                   find_descriptors, find_jmp_over_jmp, find_movabs, get_profile,
                   imm64_le, load_image, recover_k0, recover_rol13_key,
                   simulate_command)
from toka.ciphers import rol13_fwd_pure, rol13_inv_pure, rol32, ror32
from toka.fastpath import HAVE_NUMPY
from toka.pipeline import _recover_naive
from toka.vmcode import BitReader, encode_stream

M32 = 0xFFFFFFFF
TESTS = []


class SkipTest(Exception):
    """環境依存（NumPy未導入等）でスキップする検証を表す。"""


def test(fn):
    TESTS.append((fn.__name__, fn))
    return fn


def requires_numpy():
    if not HAVE_NUMPY:
        raise SkipTest("numpy not installed")


# ============================================================ 共通素材

# LSB-first 正規ハフマン符号（長さ 2,2,3,4,4,5,6,7 — 接頭辞自由・衝突なし）
CODES = {
    0x041: (0x0, 2),    # LIT 'A'
    0x042: (0x2, 2),    # LIT 'B'
    0x302: (0x1, 3),    # LZ len=2 (dist=acc+2)
    0x102: (0x5, 4),    # acc 組立 data=5
    0x202: (0xD, 4),    # RLE unit=2
    0x043: (0x3, 5),    # LIT 'C'
    0x058: (0x13, 6),   # LIT 'X'
    0x059: (0x33, 7),   # LIT 'Y'
}
# 実測で修正済みのテストプラン（LZに十分な履歴がある版）
PLAN = [0x041, 0x042, 0x302, 0x043, 0x058, 0x059, 0x102, 0x202]
PLAN_OUT = b"ABABCXYXYXY"          # 11 bytes


def make_table():
    return HuffmanTable(build_table(CODES))


def chain_inv_identity(M: bytes) -> bytes:
    """SPN恒等T連鎖の逆: in_i = M_i ^ in_{i-1}（格納形を作る側）。"""
    out = bytearray(M)
    for i in range(0, len(M) - 15, 16):
        if i == 0:
            continue
        blk = bytes(a ^ b for a, b in zip(M[i:i + 16], out[i - 16:i]))
        out[i:i + 16] = blk
    return bytes(out)


# ============================================================ ciphers

@test
def test_rol13_roundtrip():
    k = 0x13579BDF
    data = bytes(range(256))
    enc = Rol13(k).fwd(data)
    assert enc != data
    assert Rol13(k).inv(enc) == data
    # 端数バイトは無処理
    data2 = data + b"\xaa\xbb"
    out2 = Rol13(k).fwd(data2)
    assert out2[256:] == b"\xaa\xbb"
    assert Rol13(k).inv(out2) == data2


@test
def test_rol13_recipes():
    k = 0x12345678
    data = struct.pack("<2I", 0x11111111, 0x22222222)
    out = Rol13(k).fwd(data)
    e0 = (rol32(0x11111111 ^ k, 13) - 0) & M32
    e1 = (rol32(0x22222222 ^ k, 13) - 1) & M32          # esi_1 = K + 0
    assert struct.unpack_from("<I", out, 0)[0] == e0
    assert struct.unpack_from("<I", out, 4)[0] == e1


@test
def test_rol13_derive_key():
    K = 0xDEADBEEF
    M = b"\x01\x02\x03\x04"
    S = Rol13(K).fwd(M)
    m0 = struct.unpack("<I", M)[0]
    s0 = struct.unpack("<I", S)[0]
    assert Rol13.derive_key(m0, s0) == K


@test
def test_rol13_pure_roundtrip():
    k = 0xABCD1234
    data = bytes((i * 7 + 3) & 0xFF for i in range(300))
    assert rol13_inv_pure(k, rol13_fwd_pure(k, data)) == data


@test
def test_spn_identity_chain():
    spn = SPN(b"\x00\x01\x0e\x00", t_func=lambda b: b)
    data = bytes(range(48))
    out = spn.chain_fwd(data)
    assert out[:16] == data[:16]                                   # prev=0
    assert out[16:32] == bytes(a ^ b for a, b in zip(data[16:32], data[:16]))
    assert out[32:48] == bytes(a ^ b for a, b in zip(data[32:48], data[16:32]))
    # 端数ブロックは無処理
    out3 = spn.chain_fwd(data + b"\xff\xee")
    assert out3[48:] == b"\xff\xee"


@test
def test_spn_default_t_deterministic():
    sboxes = [list(range(256))] * 4
    key = b"\x00\x01\x0e\x00" + b"\x00" * (0x20 * 7)
    spn = SPN(key, sboxes=sboxes)
    assert spn.rounds == 7 and spn.magic == 0x0100
    blk = b"\x11" * 16
    assert spn.t(blk) == spn.t(blk)          # 決定論的
    assert len(spn.t(blk)) == 16


# ============================================================ vmcode

@test
def test_huffman_build_codes_roundtrip():
    tbl = make_table()
    got = tbl.codes()
    for sym, (code, length) in CODES.items():
        assert got.get(sym) == (code, length), (hex(sym), got.get(sym))


@test
def test_huffman_decode_roundtrip():
    tbl = make_table()
    syms = [0x041, 0x302, 0x102, 0x202, 0x058, 0x059, 0x043, 0x042, 0x302]
    # 末尾シンボルは peek(8) のため下駄が必要（実運用でもストリームに余裕がある）
    stream = encode_stream(syms, CODES) + b"\x00\x00"
    reader = BitReader(stream)
    dec = [tbl.decode_symbol(reader) for _ in syms]
    assert dec == syms


@test
def test_huffman_unused_root_is_error():
    raw = build_table({0x041: (0x0, 2)})   # root≡0 mod4 のみ有効
    tbl = HuffmanTable(raw)
    try:
        tbl.decode_symbol(BitReader(b"\x01\x00"))
        assert False, "unused entry must raise"
    except ValueError:
        pass


@test
def test_build_table_rejects_conflict():
    try:
        build_table({0x1: (0x0, 2), 0x2: (0x4, 3)})   # 0x4 & 3 == 0 前置き衝突
        assert False, "conflicting codes must raise"
    except ValueError:
        pass


@test
def test_expand_plan():
    tbl = make_table()
    # encode_stream のバイトパディングが末尾シンボルの root peek(8) を
    # まかなう（実データでもストリームには余裕がある）
    S = encode_stream(PLAN, CODES)          # 33bit -> 5B
    res = expand(S, len(PLAN_OUT), tbl)
    assert res.ok, res.error
    assert res.out == PLAN_OUT == b"ABABCXYXYXY"


@test
def test_expand_partial_and_exhaust():
    tbl = make_table()
    # out_size に達した時点で成功（残りビットは無視）
    S = encode_stream(PLAN, CODES)
    res = expand(S, 1, tbl)
    assert res.ok and res.out == b"A"
    # ストリーム枯渇
    res2 = expand(b"", 5, tbl)
    assert not res2.ok and res2.error
    # コマンド拒否（LZに履歴が無い）
    S3 = encode_stream([0x302], CODES)
    res3 = expand(S3, 4, tbl)
    assert not res3.ok and "rejected" in res3.error


@test
def test_simulate_command_semantics():
    lim = 16
    # LIT
    ok, emit, acc = simulate_command(0x000, 0x41, b"", 0, lim)
    assert ok and emit == b"A" and acc == 0
    ok, _, _ = simulate_command(0x000, 0x41, b"X" * 16, 0, 16)
    assert not ok                                        # 出力上限超過
    # acc 組立: 最大2バイト
    ok, emit, acc = simulate_command(0x100, 0x05, b"", 0, lim)
    assert ok and emit == b"" and acc == 5
    ok, _, acc = simulate_command(0x100, 0x06, b"", 5, lim)
    assert ok and acc == 0x0506
    ok, _, acc = simulate_command(0x100, 0x07, b"", 0x0506, lim)
    assert not ok and acc == 0x0506                      # acc>=0x100 で失敗
    # RLE unit=1 / unit=2 / 不正unit
    ok, emit, acc = simulate_command(0x200, 1, b"ABC", 0, lim)
    assert ok and emit == b"C" and acc == 0
    ok, emit, acc = simulate_command(0x200, 2, b"ABCD", 2, lim)
    assert ok and emit == b"CDCD" and acc == 0
    ok, _, _ = simulate_command(0x200, 3, b"ABCD", 1, lim)
    assert not ok                                        # unit∈{1,2,4}
    ok, emit, acc = simulate_command(0x200, 4, b"ABCDEFGH", 1, lim)
    assert ok and emit == b"EFGH"                       # unit=4
    # LZ: 履歴不足 / 通常コピー
    ok, _, _ = simulate_command(0x300, 2, b"", 0, lim)
    assert not ok
    ok, emit, acc = simulate_command(0x300, 2, b"ABC", 0, lim)
    assert ok and emit == b"BC" and acc == 0
    # 未知モード
    ok, _, _ = simulate_command(0x400, 0, b"", 0, lim)
    assert not ok


@test
def test_enumerate_includes_true_s0():
    tbl = make_table()
    plan2 = PLAN + [0x043] * 10                        # 計83bit >= 32bit
    ref2 = PLAN_OUT + b"C" * 10
    S = encode_stream(plan2, CODES)
    true_s0 = struct.unpack_from("<I", S + b"\x00" * 4, 0)[0]
    cands = enumerate_prefixes_from_reference(tbl, ref2, min_bits=32)
    assert true_s0 in cands, f"S0={true_s0:#x} not in {len(cands)} cands"
    assert 0 < len(cands) < 10000                       # 有界（爆発しない）


@test
def test_recover_rol13_key():
    tbl = make_table()
    plan2 = PLAN + [0x043] * 10                    # 83bit -> 11B
    ref2 = PLAN_OUT + b"C" * 10
    K = 0x9E3779B9
    S = encode_stream(plan2, CODES)
    assert len(S) == 11
    M = Rol13(K).inv(S)
    assert recover_rol13_key(M, ref2, len(ref2), tbl) == K
    # 誤鍵では既知平文と一致しない（ゴミストリームは例外でも失敗でもよい）
    try:
        wrong = expand(Rol13(0).fwd(M), len(ref2), tbl)
        assert wrong.out != ref2
    except (ValueError, IndexError):
        pass


@test
def test_recover_key_staged_equivalence():
    """段階的検証（最適化版）と単純実装の結果が一致すること。"""
    tbl = make_table()
    plan2 = PLAN + [0x043] * 10
    ref2 = PLAN_OUT + b"C" * 10
    K = 0x9E3779B9
    M = Rol13(K).inv(encode_stream(plan2, CODES))
    # 既定ウィンドウ
    assert recover_rol13_key(M, ref2, len(ref2), tbl) == K
    assert _recover_naive(M, ref2, len(ref2), tbl) == K
    # 極小/極大ウィンドウでも同一結果
    assert recover_rol13_key(M, ref2, len(ref2), tbl, window_dwords=1) == K
    assert recover_rol13_key(M, ref2, len(ref2), tbl, window_dwords=64) == K
    # 既知平文を壊した場合は両方とも None
    broken = ref2[:-1] + bytes((ref2[-1] ^ 1,))
    assert recover_rol13_key(M, broken, len(broken), tbl) is None
    assert _recover_naive(M, broken, len(broken), tbl) is None


# ============================================================ fastpath（NumPy）

@test
def test_fastpath_rol13_equivalence():
    requires_numpy()
    from toka import fastpath
    rng = random.Random(0xC0FFEE)
    for size in (0, 1, 3, 4, 15, 16, 63, 64, 255, 256, 1000):
        data = bytes(rng.randrange(256) for _ in range(size))
        for k in (0, 1, 0xDEADBEEF, 0xFFFFFFFF):
            assert fastpath.rol13_fwd(k, data) == rol13_fwd_pure(k, data), (size, k)
            assert fastpath.rol13_inv(k, data) == rol13_inv_pure(k, data), (size, k)


@test
def test_fastpath_rol13_batch_equivalence():
    requires_numpy()
    from toka import fastpath
    rng = random.Random(0xBEEF)
    data = bytes(rng.randrange(256) for _ in range(100))
    keys = [0, 1, 0x13579BDF, 0x9E3779B9, 0xFFFFFFFF]
    batch = fastpath.rol13_fwd_batch(data, keys)
    assert len(batch) == len(keys)
    for k, row in zip(keys, batch):
        assert row == rol13_fwd_pure(k, data)


@test
def test_fastpath_spn_chain_equivalence():
    requires_numpy()
    from toka import fastpath
    rng = random.Random(42)
    sboxes = [[rng.randrange(1 << 32) for _ in range(256)] for _ in range(4)]
    key = b"\x00\x01\x0e\x00" + bytes(rng.randrange(256)
                                      for _ in range(0xF4 - 4))
    spn = SPN(key, sboxes=sboxes)
    assert spn.rounds == 7
    for nb in (1, 2, 5, 33):
        data = bytes(rng.randrange(256) for _ in range(16 * nb + 3))
        fast = fastpath.spn_chain_fwd(key, spn.rounds, sboxes, data)
        pure = spn._chain_fwd_loop(data)
        assert fast == pure, nb


@test
def test_fastpath_recover_k0_equivalence():
    requires_numpy()
    from toka import fastpath
    k0 = 0x1234
    lo, hi = 0x1000, 0x1800
    body = encode_body(b"-- Version\r\nhello world", k0)
    assert fastpath.recover_k0(body, b"-- Version\r\n", lo, hi) == k0
    # mailslot経由（NumPy自動選択）とも一致
    assert recover_k0(body, b"-- Version\r\n", lo, hi) == k0
    # 一致候補が無い範囲は None
    assert fastpath.recover_k0(body, b"XXXXXXXX", lo, hi) is None


# ============================================================ pipeline / config

@test
def test_descriptor_parse():
    d = Descriptor.parse("0x1000:0x40:0x1000:0x80")
    assert (d.off1, d.size1, d.off2, d.size2) == (0x1000, 0x40, 0x1000, 0x80)
    assert str(d) == "0x1000:0x40:0x1000:0x80"
    try:
        Descriptor.parse("1:2:3")
        assert False
    except ValueError:
        pass


@test
def test_config_profile():
    cfg = get_profile("sample")
    assert cfg.rol13_key == 0x13579BDF
    assert cfg.key_pair(cfg.expand_threshold)[0] == cfg.spn_key_high[0]       # 高域
    assert cfg.key_pair(cfg.expand_threshold - 1)[0] == cfg.spn_key_low[0]   # 低域
    assert cfg.desc("demo") == (0x1000, 0x40, 0x1000, 0x80)
    try:
        get_profile("nope")
        assert False
    except KeyError:
        pass


@test
def test_load_image_strips_header():
    payload = b"\x48\x8b\x01\x90"
    blob = b"REGION image addr=0x140000000 size=0x1000\n" + payload
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(blob)
        path = f.name
    try:
        assert load_image(path) == payload
        with open(path, "wb") as f:
            f.write(payload)
        assert load_image(path) == payload            # ヘッダ無しはそのまま
    finally:
        os.unlink(path)


@test
def test_pipeline_e2e_identity_spn():
    tbl_raw = build_table(CODES)
    tbl = HuffmanTable(tbl_raw)
    plan3 = PLAN + [0x043] * 120                   # 633bit -> 80B (5ブロック)
    ref3 = PLAN_OUT + b"C" * 120
    K = 0xDEADBEEF
    S = encode_stream(plan3, CODES)
    assert len(S) == 80
    M = Rol13(K).inv(S)
    stored = chain_inv_identity(M)

    off2 = SAMPLE.expand_threshold                  # 閾値以上 → 高域ペア
    key_rva, key_size, tbl_rva, tbl_size = SAMPLE.key_pair(off2)
    need = max(tbl_rva + tbl_size, 0x1000 + len(stored),
               max(SAMPLE.sbox_rvas) + 0x400)        # S-box 4枚（各256 dword）
    image = bytearray(need + 0x100)
    image[tbl_rva:tbl_rva + len(tbl_raw)] = tbl_raw          # Huffman表(高域)
    image[key_rva:key_rva + key_size] = b"\x00\x01\x0e\x00" + b"\x00" * (key_size - 4)
    off1 = 0x1000
    image[off1:off1 + len(stored)] = stored

    desc = Descriptor(off1, len(stored), off2, len(ref3))
    ident = SPN(b"\x00\x01\x0e\x00", t_func=lambda b: b)
    pipe = Pipeline(SAMPLE, bytes(image))

    out = pipe.decrypt_block(desc, rol13_key=K, spn=ident)
    assert out == ref3, (out[:16].hex(), ref3[:16].hex())
    assert pipe.recover_key(desc, ref3, spn=ident) == K


# ============================================================ mailslot

@test
def test_mailslot_roundtrip_and_recover():
    k0 = 0xFFF8C5A3
    plain = b"-- Version\r\n" + b"secret payload 123"
    body = encode_body(plain, k0)
    assert body != plain
    assert decode_body(body, k0) == plain
    assert recover_k0(body) == k0                     # 0xfff80000.. からの走査
    assert decode_body(body, k0 ^ 0xFF) != plain


# ============================================================ unpack

@test
def test_unpack_rolling_key_roundtrip():
    data = bytes((i * 7 + 3) & 0xFF for i in range(200))
    enc = encrypt_stream(data, size=0x1000, init_key=0x12345)
    assert enc != data
    assert decrypt_stream(enc, 0x1000, 0x12345) == data


@test
def test_unpack_find_descriptors():
    blob = bytearray(64)
    struct.pack_into("<8I", blob, 16, 0x4E4E4F4B, 1, 2, 3, 4, 5, 6, 7)
    found = find_descriptors(bytes(blob))
    assert len(found) == 1
    assert found[0].offset == 16 and found[0].sig == 0x4E4E4F4B
    assert found[0].fields[3] == 3


# ============================================================ disasm

@test
def test_find_movabs_vector():
    imm_val = 0x105B8B4C08C48348
    code = b"\x48\xb9" + struct.pack("<Q", imm_val) + b"\x90\x90"
    sites = list(find_movabs(code))
    assert len(sites) == 1
    s = sites[0]
    assert s.offset == 0 and s.reg == 1                        # rcx
    assert s.imm.hex() == "105b8b4c08c48348"                  # 即値のhex表記
    assert imm64_le(s.imm).hex() == "4883c4084c8b5b10"         # 隠れ実コード
    try:
        import capstone  # noqa: F401
        have_cs = True
    except ImportError:
        have_cs = False
    if have_cs:
        insns = toka_decode(s.imm)
        assert insns[0].mnemonic == "add"
    else:
        try:
            toka_decode(s.imm)
            assert False
        except RuntimeError as e:
            assert "4883c4084c8b5b10" in str(e)


def toka_decode(imm):
    from toka import decode_imm64
    return decode_imm64(imm)


@test
def test_find_jmp_over_jmp():
    data = b"\xeb\x04DATA" + b"\x90"
    assert list(find_jmp_over_jmp(data)) == [6]


# ============================================================ cli

@test
def test_cli_mailslot_smoke():
    import subprocess
    k0 = 0xFFF8C5A3
    plain = b"-- Version\r\ncli smoke"
    with tempfile.TemporaryDirectory() as td:
        body_path = os.path.join(td, "body.bin")
        out_path = os.path.join(td, "plain.txt")
        with open(body_path, "wb") as f:
            f.write(encode_body(plain, k0))
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rc = subprocess.call([sys.executable, "-m", "toka.cli", "mailslot",
                              body_path, "--k0", hex(k0), "--out", out_path],
                             cwd=repo)
        assert rc == 0
        with open(out_path, "rb") as f:
            assert f.read() == plain


@test
def test_recover_key_short_stream_rejected():
    tbl = HuffmanTable(build_table(CODES))
    for short in (b"", b"\x01", b"\x01\x02\x03"):
        try:
            recover_rol13_key(short, b"AB", 2, tbl)
            raise AssertionError("short M accepted: %r" % short)
        except ValueError:
            pass


@test
def test_cli_version_flag():
    import subprocess
    from toka import __version__
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.check_output(
        [sys.executable, "-m", "toka.cli", "--version"], cwd=repo)
    assert __version__.encode() in out


@test
def test_cli_decrypt_block_bad_key_clean_error():
    import subprocess
    import tempfile
    tbl_raw = build_table(CODES)
    S = encode_stream([0x041] * 130, CODES)
    M = Rol13(0xDEADBEEF).inv(S)
    stored = chain_inv_identity(M)
    off2 = SAMPLE.expand_threshold
    key_rva, key_size, tbl_rva, tbl_size = SAMPLE.key_pair(off2)
    need = max(tbl_rva + tbl_size, 0x1000 + len(stored),
               max(SAMPLE.sbox_rvas) + 0x400)
    image = bytearray(need + 0x100)
    image[tbl_rva:tbl_rva + len(tbl_raw)] = tbl_raw
    image[key_rva:key_rva + key_size] = struct.pack("<HH", 0x0100, 0x0000) \
        + b"\x00" * (key_size - 4)        # rounds=0 -> identity T
    image[0x1000:0x1000 + len(stored)] = stored
    with tempfile.TemporaryDirectory() as td:
        dump_path = os.path.join(td, "dump.bin")
        with open(dump_path, "wb") as f:
            f.write(bytes(image))
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        desc = "0x1000:%d:0x%x:130" % (len(stored), off2)
        p = subprocess.run(
            [sys.executable, "-m", "toka.cli", "decrypt-block", dump_path,
             "--desc", desc, "--key", "0x1234"],
            cwd=repo, capture_output=True, text=True)
        assert p.returncode == 1, (p.returncode, p.stderr)
        assert "FAILED" in p.stderr
        assert "Traceback" not in p.stderr


# ============================================================ runner

def main() -> int:
    failed = 0
    skipped = 0
    for name, fn in TESTS:
        try:
            fn()
            print(f"PASS  {name}")
        except SkipTest as e:
            skipped += 1
            print(f"SKIP  {name}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
    print(f"\n{len(TESTS) - failed - skipped}/{len(TESTS)} passed"
          f"{f' ({skipped} skipped)' if skipped else ''}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
