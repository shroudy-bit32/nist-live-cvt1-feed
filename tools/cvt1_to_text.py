#!/usr/bin/env python3
"""
CVT1 binary packs → plain-text hash lists for DFIR tools.

Magnet AXIOM, FTK, and similar tools expect .txt files with one hex digest
per line (MD5 and/or SHA-1; SHA-256 is also emitted for tools that accept it).

Reads the CVT1 header + raw digest payload produced by stream_http_hash_filter.py:

  struct: <IIIQI  → magic, version, algo, updated_unix, count
  payload: count × raw digests (16 / 20 / 32 bytes)

Default inputs under ./clean_packs:
  clean_md5.bin → clean_md5.txt
  clean_sha1.bin → clean_sha1.txt
  clean_sha256.bin → clean_sha256.txt
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

CVT1_MAGIC = 0x31545643  # "CVT1" little-endian
CVT1_VERSION = 1
HEADER_FMT = "<IIIQI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

ALGO_MD5 = 1
ALGO_SHA1 = 2
ALGO_SHA256 = 3

ALGO_DIGEST_SIZE: Dict[int, int] = {
    ALGO_MD5: 16,
    ALGO_SHA1: 20,
    ALGO_SHA256: 32,
}

ALGO_NAME: Dict[int, str] = {
    ALGO_MD5: "MD5",
    ALGO_SHA1: "SHA-1",
    ALGO_SHA256: "SHA-256",
}

DEFAULT_PACKS = (
    "clean_md5.bin",
    "clean_sha1.bin",
    "clean_sha256.bin",
)


class Cvt1Error(ValueError):
    pass


def read_cvt1_header(path: Path) -> Tuple[int, int, int, int, int]:
    with path.open("rb") as f:
        raw = f.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        raise Cvt1Error(f"{path}: truncated CVT1 header ({len(raw)} bytes)")
    magic, version, algo, updated_unix, count = struct.unpack(HEADER_FMT, raw)
    if magic != CVT1_MAGIC:
        raise Cvt1Error(
            f"{path}: bad magic 0x{magic:08X} (expected 0x{CVT1_MAGIC:08X})"
        )
    if version != CVT1_VERSION:
        raise Cvt1Error(f"{path}: unsupported CVT1 version {version}")
    if algo not in ALGO_DIGEST_SIZE:
        raise Cvt1Error(f"{path}: unknown algo id {algo}")
    if count < 0:
        raise Cvt1Error(f"{path}: negative digest count")
    return magic, version, algo, updated_unix, count


def iter_cvt1_hex_digests(path: Path) -> Tuple[int, int, Iterator[str]]:
    """Return (algo, count, iterator of lowercase hex digests)."""
    _magic, _version, algo, _ts, count = read_cvt1_header(path)
    digest_size = ALGO_DIGEST_SIZE[algo]
    expected = HEADER_SIZE + count * digest_size
    actual = path.stat().st_size
    if actual < expected:
        raise Cvt1Error(
            f"{path}: file too small ({actual} bytes, need >= {expected} for count={count})"
        )

    def _gen() -> Iterator[str]:
        with path.open("rb") as f:
            f.seek(HEADER_SIZE)
            remaining = count
            # Read in chunks to keep memory flat on large packs.
            chunk_digests = max(1, (1024 * 1024) // digest_size)
            while remaining > 0:
                n = min(remaining, chunk_digests)
                block = f.read(n * digest_size)
                if len(block) < n * digest_size:
                    raise Cvt1Error(f"{path}: unexpected EOF while reading digests")
                for i in range(0, len(block), digest_size):
                    yield block[i : i + digest_size].hex()
                remaining -= n

    return algo, count, _gen()


def convert_pack(bin_path: Path, txt_path: Path) -> int:
    algo, count, digests = iter_cvt1_hex_digests(bin_path)
    txt_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with txt_path.open("w", encoding="ascii", newline="\n") as out:
        for h in digests:
            out.write(h)
            out.write("\n")
            written += 1
    if written != count:
        raise Cvt1Error(f"{bin_path}: wrote {written} lines, header count={count}")
    print(
        f"[+] {bin_path.name} ({ALGO_NAME[algo]}) → {txt_path.name} ({written} hashes)",
        file=sys.stderr,
    )
    return written


def resolve_inputs(input_dir: Path, files: Optional[List[str]]) -> List[Path]:
    names = files if files else list(DEFAULT_PACKS)
    paths: List[Path] = []
    for name in names:
        p = Path(name)
        if not p.is_absolute() and len(p.parts) == 1:
            p = input_dir / p
        paths.append(p)
    return paths


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "-i",
        "--input-dir",
        type=Path,
        default=Path("clean_packs"),
        help="directory containing CVT1 .bin packs (default: clean_packs)",
    )
    ap.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="directory for .txt outputs (default: same as --input-dir)",
    )
    ap.add_argument(
        "files",
        nargs="*",
        help="optional .bin paths or basenames (default: clean_md5/sha1/sha256.bin)",
    )
    args = ap.parse_args()

    in_dir = args.input_dir
    out_dir = args.output_dir if args.output_dir is not None else in_dir
    packs = resolve_inputs(in_dir, args.files or None)

    if not packs:
        print("[!] no input packs", file=sys.stderr)
        return 2

    total = 0
    try:
        for bin_path in packs:
            if not bin_path.is_file():
                raise Cvt1Error(f"missing CVT1 pack: {bin_path}")
            txt_path = out_dir / (bin_path.stem + ".txt")
            total += convert_pack(bin_path, txt_path)
    except Cvt1Error as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print(f"[+] Wrote {total} digest line(s) → {out_dir.resolve()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
