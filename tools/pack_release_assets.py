#!/usr/bin/env python3
"""
Package final CVT1 .bin / DFIR .txt outputs for GitHub Releases.

GitHub caps a single release asset at 2 GiB. Compression can't help here --
measured on 3,000,000 real SHA-256 digests, gzip -9 / zip -9 on the raw
.bin land at ~100.0% of the original size (cryptographic digests are close
to uniformly random bytes, no redundancy for DEFLATE to exploit) -- so this
tool does exactly one thing: split any file over --limit-mib into raw,
uncompressed, numbered parts. No .gz, no .zip -- just clean_<name>_partNN.<ext>
pieces, zero-padded so `ls`/`cat`/glob order matches numeric order.

  .bin  -- Part 1 carries the ORIGINAL file's CVT1 header verbatim (the same
           total count as the unsplit file); parts 2..N are pure payload
           continuation with no header of their own. This means
             cat clean_<algo>_part*.bin > clean_<algo>_full.bin
           reconstructs a byte-exact copy of the original single CVT1 file,
           not just "the same digests in some other form". A lone part 1 is
           intentionally incomplete on its own (its header promises more
           records than are physically present) -- same as any multi-volume
           archive piece; any CVT1 reader will correctly refuse to treat it
           as complete rather than silently under-reading it.

  .txt  -- Plain hex-per-line text has no header, so splitting on line
           boundaries and reassembling with a plain `cat` is exact with no
           special-casing needed.

Every part is size-checked after being written; anything still over the
limit gets the whole file re-split at a higher part count and retried. Raw
input is deleted only once every part has been written and verified -- this
never hands the workflow an asset that would fail GitHub's validation.
"""

from __future__ import annotations

import argparse
import math
import struct
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stream_http_hash_filter import (  # noqa: E402
    ALGO_MD5,
    ALGO_SHA1,
    ALGO_SHA256,
    CVT1_MAGIC,
    CVT1_VERSION,
    DIGEST_SIZE_BY_ALGO,
)

HEADER_FMT = "<IIIQI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

DEFAULT_LIMIT_MIB = 1500  # "1.5 GB", comfortably under GitHub's 2048 MiB hard cap
MAX_SPLIT_ATTEMPTS = 6
NAME_PAD = 2  # clean_sha256_part01.bin ... grows automatically past 99 parts

ALGO_NAME = {ALGO_MD5: "md5", ALGO_SHA1: "sha1", ALGO_SHA256: "sha256"}


class PackError(RuntimeError):
    pass


def read_cvt1_header(path: Path) -> tuple:
    with path.open("rb") as f:
        raw = f.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        raise PackError(f"{path}: truncated CVT1 header")
    magic, version, algo, ts, count = struct.unpack(HEADER_FMT, raw)
    if magic != CVT1_MAGIC or version != CVT1_VERSION:
        raise PackError(f"{path}: not a CVT1 v{CVT1_VERSION} file")
    if algo not in DIGEST_SIZE_BY_ALGO:
        raise PackError(f"{path}: unknown algo id {algo}")
    return magic, version, algo, ts, count


def part_name(stem: str, idx: int, num_parts: int, ext: str) -> str:
    width = max(NAME_PAD, len(str(num_parts)))
    return f"{stem}_part{idx:0{width}d}.{ext}"


# ---------------------------------------------------------------------------
# .bin: header-preserving split so a plain `cat` reconstructs the whole
# ---------------------------------------------------------------------------

def split_bin_into(path: Path, num_parts: int) -> List[Path]:
    if num_parts <= 1:
        return [path]
    magic, version, algo, ts, count = read_cvt1_header(path)
    digest_size = DIGEST_SIZE_BY_ALGO[algo]
    records_per_part = max(1, math.ceil(count / num_parts))
    stem = path.stem  # e.g. "clean_sha256"
    out_paths: List[Path] = []
    with path.open("rb") as f:
        f.seek(HEADER_SIZE)
        remaining = count
        idx = 1
        while remaining > 0:
            n = min(records_per_part, remaining)
            block = f.read(n * digest_size)
            if len(block) != n * digest_size:
                raise PackError(f"{path}: truncated while splitting")
            out_path = path.parent / part_name(stem, idx, num_parts, "bin")
            with out_path.open("wb") as out:
                if idx == 1:
                    # Original header verbatim -- TOTAL count, not just this
                    # part's -- so concatenating every part reproduces the
                    # exact original file byte-for-byte.
                    out.write(struct.pack(HEADER_FMT, magic, version, algo, ts, count))
                out.write(block)
            out_paths.append(out_path)
            remaining -= n
            idx += 1
    return out_paths


def process_bin(path: Path, limit_bytes: int) -> List[Path]:
    _magic, _version, algo, _ts, count = read_cvt1_header(path)
    digest_size = DIGEST_SIZE_BY_ALGO[algo]
    payload_bytes = count * digest_size
    usable = max(1, limit_bytes - HEADER_SIZE)
    num_parts = max(1, math.ceil(payload_bytes / usable)) if payload_bytes else 1
    return _split_verify_retry(path, limit_bytes, num_parts, split_bin_into)


# ---------------------------------------------------------------------------
# .txt: line-boundary split, no header, `cat` reassembles exactly
# ---------------------------------------------------------------------------

def split_txt_into(path: Path, num_parts: int) -> List[Path]:
    if num_parts <= 1:
        return [path]
    total_lines = 0
    with path.open("r", encoding="ascii") as f:
        for _ in f:
            total_lines += 1
    lines_per_part = max(1, math.ceil(total_lines / num_parts))
    stem = path.stem  # e.g. "clean_sha256"
    out_paths: List[Path] = []
    with path.open("r", encoding="ascii") as f:
        idx = 1
        buf: List[str] = []
        for line in f:
            buf.append(line)
            if len(buf) >= lines_per_part:
                out_path = path.parent / part_name(stem, idx, num_parts, "txt")
                out_path.write_text("".join(buf), encoding="ascii", newline="\n")
                out_paths.append(out_path)
                buf = []
                idx += 1
        if buf:
            out_path = path.parent / part_name(stem, idx, num_parts, "txt")
            out_path.write_text("".join(buf), encoding="ascii", newline="\n")
            out_paths.append(out_path)
    return out_paths


def process_txt(path: Path, limit_bytes: int) -> List[Path]:
    raw_size = path.stat().st_size
    num_parts = max(1, math.ceil(raw_size / limit_bytes)) if raw_size else 1
    return _split_verify_retry(path, limit_bytes, num_parts, split_txt_into)


# ---------------------------------------------------------------------------

def _split_verify_retry(path: Path, limit_bytes: int, num_parts: int, split_fn) -> List[Path]:
    for attempt in range(MAX_SPLIT_ATTEMPTS):
        units = split_fn(path, num_parts)
        oversized = [u for u in units if u.stat().st_size > limit_bytes]
        if not oversized:
            if units != [path]:
                path.unlink()
            print(
                f"[+] {path.name}: {len(units)} part(s), all under "
                f"{limit_bytes / 1024**2:.0f} MiB",
                file=sys.stderr,
            )
            return units
        for u in units:
            if u != path:
                u.unlink(missing_ok=True)
        print(
            f"    [pack] {path.name}: attempt {attempt + 1} with num_parts={num_parts} "
            "still had an oversized part -- doubling and retrying",
            file=sys.stderr,
        )
        num_parts *= 2

    raise PackError(f"{path}: could not split under {limit_bytes} bytes after {MAX_SPLIT_ATTEMPTS} attempts")


def discover_default_files(directory: Path) -> List[Path]:
    out = []
    for pattern in ("clean_*.bin", "clean_*.txt"):
        for p in sorted(directory.glob(pattern)):
            if "_part" in p.name:
                continue  # don't reprocess a previous run's leftovers
            out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("-d", "--dir", type=Path, default=Path("clean_packs"))
    ap.add_argument(
        "--files", nargs="*", default=None,
        help="specific filenames (relative to --dir) to process; default: all clean_*.bin/.txt in --dir",
    )
    ap.add_argument("--limit-mib", type=int, default=DEFAULT_LIMIT_MIB)
    args = ap.parse_args()

    if not args.dir.is_dir():
        print(f"[!] no such directory: {args.dir}", file=sys.stderr)
        return 2

    files = (
        [args.dir / name for name in args.files] if args.files else discover_default_files(args.dir)
    )
    if not files:
        print(f"[!] no clean_*.bin / clean_*.txt files found under {args.dir}", file=sys.stderr)
        return 2

    limit_bytes = args.limit_mib * 1024 * 1024
    try:
        total = 0
        for path in files:
            if not path.is_file():
                raise PackError(f"missing input: {path}")
            if path.suffix == ".bin":
                total += len(process_bin(path, limit_bytes))
            else:
                total += len(process_txt(path, limit_bytes))
    except PackError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print(f"[+] done: {total} output file(s) in {args.dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
