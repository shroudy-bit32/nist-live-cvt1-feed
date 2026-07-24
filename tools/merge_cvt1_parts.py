#!/usr/bin/env python3
"""
Merge scatter-gather CVT1 part chunks into final exact-unique release packs.

The main carve job (stream_http_hash_filter.py --parts-dir ...) periodically
compacts its shard files into part_NNNNN_{md5,sha1,sha256}.bin triples,
uploads each one, and deletes it locally -- never holding more than one
checkpoint window's worth of data on the runner's disk, and never losing
more than that if the job times out or crashes.

Each part is already internally sorted + exact-unique (native CarveEngine
checkpoint: sort + std::unique per shard). It is NOT deduped against other
parts. This script does that final cross-part step with the same technique
used everywhere else in this pipeline -- an external k-way merge over
already-sorted runs (merge_sorted_raw_runs) -- not an in-memory set, so RAM
stays flat regardless of how many parts or how many total hashes there are.

Intended to run in its own small, dependency-light job (no C++ build, no
pybind11) that downloads every part_*.bin asset and then calls this:

    gh release download "$CHUNKS_TAG" --pattern "part_*.bin" --dir chunks_dl
    python tools/merge_cvt1_parts.py -i chunks_dl -o clean_packs
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stream_http_hash_filter import (  # noqa: E402  (reuse battle-tested code)
    ALGO_MD5,
    ALGO_SHA1,
    ALGO_SHA256,
    CVT1_MAGIC,
    CVT1_VERSION,
    PACK_NAME_BY_ALGO,
    merge_sorted_raw_runs,
    write_cvt1_from_raw,
)

HEADER_FMT = "<IIIQI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

ALGO_SUFFIX = {ALGO_MD5: "md5", ALGO_SHA1: "sha1", ALGO_SHA256: "sha256"}
SUFFIX_DIGEST_SIZE = {"md5": 16, "sha1": 20, "sha256": 32}


class MergeError(ValueError):
    pass


def _payload_only(part_path: Path, digest_size: int, tmp_dir: Path) -> Path:
    """Strip the CVT1 header off one part, leaving a plain sorted-unique run
    that merge_sorted_raw_runs can consume (and will delete when it's done)."""
    with part_path.open("rb") as f:
        header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            raise MergeError(f"{part_path}: truncated CVT1 header")
        magic, version, algo, _ts, count = struct.unpack(HEADER_FMT, header)
        if magic != CVT1_MAGIC:
            raise MergeError(f"{part_path}: bad CVT1 magic")
        if version != CVT1_VERSION:
            raise MergeError(f"{part_path}: unsupported CVT1 version {version}")
        expected = HEADER_SIZE + count * digest_size
        actual = part_path.stat().st_size
        if actual < expected:
            raise MergeError(
                f"{part_path}: truncated payload ({actual} bytes, need {expected})"
            )
        payload = f.read(count * digest_size)
    out = tmp_dir / (part_path.stem + ".raw")
    out.write_bytes(payload)
    return out


def merge_one_algo(
    parts: List[Path], suffix: str, out_dir: Path, tmp_dir: Path, updated_unix: int
) -> int:
    digest_size = SUFFIX_DIGEST_SIZE[suffix]
    algo = {16: ALGO_MD5, 20: ALGO_SHA1, 32: ALGO_SHA256}[digest_size]
    runs = [_payload_only(p, digest_size, tmp_dir) for p in parts]
    unique_raw = tmp_dir / f"unique_{suffix}.raw"
    n = merge_sorted_raw_runs(runs, digest_size, unique_raw)  # consumes+deletes runs
    pack_name = PACK_NAME_BY_ALGO[algo]
    write_cvt1_from_raw(unique_raw, out_dir / pack_name, algo, updated_unix)
    unique_raw.unlink(missing_ok=True)
    return n


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "-i",
        "--parts-dir",
        type=Path,
        required=True,
        help="directory containing downloaded part_NNNNN_{md5,sha1,sha256}.bin chunks",
    )
    ap.add_argument("-o", "--output", type=Path, default=Path("clean_packs"))
    ap.add_argument(
        "--tmp-dir",
        type=Path,
        default=None,
        help="scratch dir for header-stripped runs (default: <output>/.merge_tmp)",
    )
    args = ap.parse_args()

    if not args.parts_dir.is_dir():
        print(f"[!] no such parts dir: {args.parts_dir}", file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)
    tmp_dir = args.tmp_dir if args.tmp_dir is not None else (args.output / ".merge_tmp")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    ts = int(time.time())
    total = 0
    any_found = False
    try:
        for suffix in ("md5", "sha1", "sha256"):
            parts = sorted(args.parts_dir.glob(f"part_*_{suffix}.bin"))
            if not parts:
                print(f"[!] no parts found for {suffix}", file=sys.stderr)
                continue
            any_found = True
            print(f"[*] {suffix}: merging {len(parts)} part(s)...", file=sys.stderr)
            n = merge_one_algo(parts, suffix, args.output, tmp_dir, ts)
            print(f"[+] {suffix}: {n} exact-unique digest(s)", file=sys.stderr)
            total += n
    except MergeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    finally:
        try:
            next(tmp_dir.iterdir())
        except StopIteration:
            tmp_dir.rmdir()
        except (FileNotFoundError, OSError):
            pass

    if not any_found:
        print("[!] no part_*.bin files found anywhere -- nothing merged", file=sys.stderr)
        return 2

    print(f"[+] total {total} unique digest(s) -> {args.output.resolve()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
