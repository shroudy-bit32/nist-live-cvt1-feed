#!/usr/bin/env python3
"""
HTTP stream → clean CVT1 hash packs.

RDSv3 zip path (default) — root fix for GitHub runner disk limits
-----------------------------------------------------------------
Do NOT extract the full .db to disk and do NOT load it all into RAM.

  Writer thread:  HTTP zip stream → inflate only
                  RDS_*_modern/RDS_*_modern.db → fixed-size ring buffer
  Reader thread:  sequential SQLite *page carve* (same bytes you'd read
                  from a local .db file, in file order) → pull MD5/SHA-1/
                  SHA-256 text/blob cells → CVT1 packs

Why not sqlite3.connect on the ring?
  The engine needs random xRead across the whole file. A 10 GiB ring of a
  16+ GiB DB cannot satisfy that. Sequential page carving *does* walk every
  page once (like reading the file from offset 0 to EOF) and extracts inline
  hash cells without keeping the file.

Ring size default is 512 MiB (safe on ~7 GiB GHA runners). Use --ring-mb
10240 only on a machine that actually has that RAM.

Full-scan path (default for zip carve, --max-keep 0)
----------------------------------------------------
Exact online unique (no hash loss, free-runner safe):

  Carve → in-memory set (dedup window) → spill sorted unique runs to disk
       → k-way merge unique → CVT1 packs

NSRL modern has ~940M FILE rows but only ~72M distinct SHA-256. Filtering
duplicates online keeps peak disk near the unique payload (~5 GiB), not the
duplicate-inflated row count. Bloom-skip is intentionally NOT used for drops:
false positives would lose real hashes.

Also supports: gzip/text feeds; optional --mode sqlite-disk (temp .db + SQL).
"""

from __future__ import annotations

import argparse
import heapq
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import zlib
from datetime import date
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CHUNK_SIZE = 64 * 1024
DEFAULT_RING_MB = 512

CVT1_MAGIC = 0x31545643
CVT1_VERSION = 1
ALGO_MD5 = 1
ALGO_SHA1 = 2
ALGO_SHA256 = 3
DIGEST_SIZE_BY_ALGO: Dict[int, int] = {
    ALGO_MD5: 16,
    ALGO_SHA1: 20,
    ALGO_SHA256: 32,
}
ALGO_BY_DIGEST_SIZE: Dict[int, int] = {
    16: ALGO_MD5,
    20: ALGO_SHA1,
    32: ALGO_SHA256,
}
PACK_NAME_BY_ALGO: Dict[int, str] = {
    ALGO_MD5: "clean_md5.bin",
    ALGO_SHA1: "clean_sha1.bin",
    ALGO_SHA256: "clean_sha256.bin",
}

ZIP_LOCAL_SIG = b"PK\x03\x04"
ZIP_CENTRAL_SIG = b"PK\x01\x02"
ZIP_EOCD_SIG = b"PK\x05\x06"
ZIP_DATA_DESC_SIG = b"PK\x07\x08"

DEFAULT_ZIP_MEMBER = "RDS_*_modern/RDS_*_modern.db"

HTTP_USER_AGENT = "CUDA_VT-stream-hash-filter/2.0"
NSRL_DOWNLOAD_PAGE = (
    "https://www.nist.gov/itl/csd/secure-systems-and-applications/"
    "national-software-reference-library-nsrl/nsrl-download-0"
)
NSRL_S3_BASE = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS"
_S3_ZIP_HREF = re.compile(
    r"https?://s3\.amazonaws\.com/rds\.nsrl\.nist\.gov/RDS/"
    r"rds_[^\"\s<>]+/RDS_[^\"\s<>]+\.zip",
    re.IGNORECASE,
)
_FULL_MODERN_ZIP_NAME = re.compile(
    r"^RDS_(\d{4}\.\d{2}\.\d+)_modern\.zip$",
    re.IGNORECASE,
)

_HEX_DIGEST = re.compile(
    r"(?i)^(?:md5:|sha1:|sha-1:|sha256:|sha-256:)?([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$"
)


def looks_like_digest(hex_str: str) -> bool:
    n = len(hex_str)
    return n in (32, 40, 64) and all(c in "0123456789abcdef" for c in hex_str)


def _rds_version_key(version: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _modern_zip_url(version: str) -> str:
    return f"{NSRL_S3_BASE}/rds_{version}/RDS_{version}_modern.zip"


def _is_full_modern_zip_url(url: str) -> Optional[str]:
    """Return RDS version if URL is full modern.zip (not minimal/delta)."""
    name = url.rstrip("/").rsplit("/", 1)[-1]
    m = _FULL_MODERN_ZIP_NAME.fullmatch(name)
    return m.group(1) if m else None


def _http_url_exists(url: str, timeout: int = 30) -> bool:
    req = Request(url, method="HEAD", headers={"User-Agent": HTTP_USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except HTTPError as exc:
        return 200 <= exc.code < 300
    except URLError:
        return False


def _candidate_rds_versions(years_back: int = 5) -> List[str]:
    """Quarterly RDS version candidates, newest first (incl. possible .2/.3 revisions)."""
    today = date.today()
    out: List[str] = []
    for year in range(today.year, today.year - years_back - 1, -1):
        for month in (12, 9, 6, 3):
            if year == today.year and month > today.month:
                continue
            for rev in range(9, 0, -1):
                out.append(f"{year}.{month:02d}.{rev}")
    return out


def discover_latest_rds_modern_zip(timeout: int = 60) -> str:
    """
    Resolve the newest full RDSv3 modern zip URL.

    Prefers links on the official NIST download page, then falls back to
    HEAD-probing S3 for RDS_*_modern.zip (excludes *_minimal* and *_delta*).
    """
    versions: Dict[str, str] = {}

    try:
        req = Request(NSRL_DOWNLOAD_PAGE, headers={"User-Agent": HTTP_USER_AGENT})
        with urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", "replace")
        for href in _S3_ZIP_HREF.findall(html):
            ver = _is_full_modern_zip_url(href)
            if ver:
                versions[ver] = href
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        print(f"[!] NIST page discovery failed: {exc}", file=sys.stderr)

    if versions:
        latest = max(versions, key=_rds_version_key)
        url = versions[latest]
        print(f"[*] Discovered latest full modern zip from NIST page: {latest}", file=sys.stderr)
        return url

    print("[*] Falling back to S3 HEAD probe for RDS_*_modern.zip …", file=sys.stderr)
    for ver in _candidate_rds_versions():
        url = _modern_zip_url(ver)
        if _http_url_exists(url, timeout=min(30, timeout)):
            print(f"[*] Discovered latest full modern zip via S3: {ver}", file=sys.stderr)
            return url

    raise RuntimeError(
        "Could not discover a full RDS_*_modern.zip "
        "(not minimal/delta). Pass an explicit URL instead."
    )


def hex_to_raw(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def digest_only_filter(line: str) -> Optional[str]:
    line = line.strip().lower()
    m = _HEX_DIGEST.match(line)
    if m:
        return m.group(1).lower()
    if looks_like_digest(line):
        return line
    return None


def default_filter(line: str) -> Optional[str]:
    line = line.strip()
    if not line or line[0] in "#;":
        return None
    lower = line.lower()
    if "filename" in lower and ("sha" in lower or "md5" in lower):
        return None
    found: List[str] = []
    for m in re.finditer(
        r"(?i)\b(?:md5:|sha1:|sha-1:|sha256:|sha-256:)?([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b",
        line,
    ):
        h = m.group(1).lower()
        if looks_like_digest(h):
            found.append(h)
    if not found:
        return None
    if "," in line or '"' in line:
        if any(x in lower for x in (".apk", ".ipa", "/usr/", ".deb", ".rpm")):
            if not any(x in lower for x in (".exe", ".dll", ".sys", ".msi")):
                return None
    for pref_len in (64, 40, 32):
        for h in found:
            if len(h) == pref_len:
                return h
    return found[0]


# ---------------------------------------------------------------------------
# Ring buffer (SPSC-style with lock; writer throttled when full)
# ---------------------------------------------------------------------------

class ByteRing:
    """Fixed-capacity circular byte buffer. Absolute read/write counters."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1024 * 1024:
            raise ValueError("ring capacity must be >= 1 MiB")
        self.cap = capacity
        self.buf = bytearray(capacity)
        self._w = 0
        self._r = 0
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)
        self._eof = False
        self._error: Optional[BaseException] = None

    def close_writer(self) -> None:
        with self._lock:
            self._eof = True
            self._not_empty.notify_all()

    def fail(self, exc: BaseException) -> None:
        with self._lock:
            self._error = exc
            self._eof = True
            self._not_empty.notify_all()
            self._not_full.notify_all()

    def write(self, data: bytes) -> None:
        if not data:
            return
        mv = memoryview(data)
        while len(mv) > 0:
            with self._not_full:
                while (self._w - self._r) >= self.cap and self._error is None:
                    self._not_full.wait(timeout=1.0)
                if self._error is not None:
                    raise self._error
                space = self.cap - (self._w - self._r)
                n = min(len(mv), space)
                idx = self._w % self.cap
                first = min(n, self.cap - idx)
                self.buf[idx : idx + first] = mv[:first]
                if n > first:
                    self.buf[0 : n - first] = mv[first:n]
                self._w += n
                mv = mv[n:]
                self._not_empty.notify()

    def read(self, n: int) -> bytes:
        """Read exactly n bytes, or fewer if EOF and drained."""
        out = bytearray()
        while len(out) < n:
            with self._not_empty:
                while (self._w - self._r) == 0 and not self._eof and self._error is None:
                    self._not_empty.wait(timeout=1.0)
                if self._error is not None:
                    raise self._error
                avail = self._w - self._r
                if avail == 0:
                    break  # EOF
                take = min(n - len(out), avail)
                idx = self._r % self.cap
                first = min(take, self.cap - idx)
                out += self.buf[idx : idx + first]
                if take > first:
                    out += self.buf[0 : take - first]
                self._r += take
                self._not_full.notify()
        return bytes(out)

    @property
    def bytes_written(self) -> int:
        with self._lock:
            return self._w

    @property
    def bytes_read(self) -> int:
        with self._lock:
            return self._r


# ---------------------------------------------------------------------------
# Digest sinks: in-memory (capped) or external unique (full scan)
# ---------------------------------------------------------------------------

DEFAULT_UNIQUE_MEMORY_ITEMS = 4_000_000


class MemoryDigestSink:
    """In-RAM unique digests. Optional max_keep > 0 stops the carve early."""

    def __init__(self, max_keep: int = 0) -> None:
        self.accepted: Set[str] = set()
        self.max_keep = max_keep  # 0 = unlimited

    def offer_hex(self, h: str) -> bool:
        if self.max_keep and len(self.accepted) >= self.max_keep:
            return False
        self.accepted.add(h)
        if self.max_keep and len(self.accepted) >= self.max_keep:
            return False
        return True

    def offer_raw(self, raw: bytes) -> bool:
        n = len(raw)
        if n not in (16, 20, 32):
            return True
        return self.offer_hex(raw.hex())

    @property
    def stopped(self) -> bool:
        return bool(self.max_keep and len(self.accepted) >= self.max_keep)


class ExternalUniqueSink:
    """
    Exact online unique for full NSRL carve (no false drops).

    Flow:
      offer → per-algo in-memory set (drops dups in the current window)
           → when memory_items is hit, spill each non-empty set as a sorted
             unique run file
           → close() spills remainder
           → merge_sorted_raw_runs() k-way merges runs with exact unique

    Peak disk ≈ unique digest payload (+ brief merge output), not ~940M rows.
    """

    def __init__(
        self,
        directory: Path,
        memory_items: int = DEFAULT_UNIQUE_MEMORY_ITEMS,
    ) -> None:
        if memory_items < 10_000:
            raise ValueError("memory_items must be >= 10000")
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.memory_items = memory_items
        self.sets: Dict[int, Set[bytes]] = {16: set(), 20: set(), 32: set()}
        self.runs: Dict[int, List[Path]] = {16: [], 20: [], 32: []}
        self.offered: int = 0
        self.duplicates_dropped: int = 0
        self.unique_accepted: int = 0  # first-seen into memory (pre-cross-run dups)
        self.spilled_records: int = 0
        self._run_seq = 0
        self._closed = False

    def _mem_count(self) -> int:
        return sum(len(s) for s in self.sets.values())

    def offer_raw(self, raw: bytes) -> bool:
        if self._closed:
            raise RuntimeError("ExternalUniqueSink is closed")
        n = len(raw)
        bucket = self.sets.get(n)
        if bucket is None:
            return True
        self.offered += 1
        if raw in bucket:
            self.duplicates_dropped += 1
            return True
        bucket.add(raw)
        self.unique_accepted += 1
        if self._mem_count() >= self.memory_items:
            self._spill_all()
        return True

    def offer_hex(self, h: str) -> bool:
        if not looks_like_digest(h):
            return True
        return self.offer_raw(bytes.fromhex(h))

    @property
    def stopped(self) -> bool:
        return False

    def _spill_size(self, size: int) -> None:
        bucket = self.sets[size]
        if not bucket:
            return
        path = self.directory / f"run_{size}_{self._run_seq:04d}.raw"
        self._run_seq += 1
        with path.open("wb") as fh:
            for dig in sorted(bucket):
                fh.write(dig)
        n = len(bucket)
        self.spilled_records += n
        self.runs[size].append(path)
        bucket.clear()
        print(
            f"    [unique] spill size={size} records={n} "
            f"runs={len(self.runs[size])} offered={self.offered} "
            f"dropped_dup={self.duplicates_dropped}",
            file=sys.stderr,
        )

    def _spill_all(self) -> None:
        for size in (16, 20, 32):
            self._spill_size(size)

    def close(self) -> None:
        if self._closed:
            return
        self._spill_all()
        self._closed = True

    def __enter__(self) -> "ExternalUniqueSink":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def stats_line(self) -> str:
        return (
            f"offered={self.offered} mem_unique={self._mem_count()} "
            f"accepted={self.unique_accepted} dropped_dup={self.duplicates_dropped} "
            f"runs={sum(len(v) for v in self.runs.values())}"
        )


def merge_sorted_raw_runs(
    runs: List[Path], digest_size: int, dst: Path
) -> int:
    """K-way merge of sorted unique runs → sorted exact-unique raw file."""
    if not runs:
        dst.write_bytes(b"")
        return 0

    if len(runs) == 1:
        src = runs[0]
        if src.resolve() != dst.resolve():
            shutil.copyfile(src, dst)
            src.unlink(missing_ok=True)
        nbytes = dst.stat().st_size
        if nbytes % digest_size:
            raise RuntimeError(f"{dst}: bad size {nbytes}")
        return nbytes // digest_size

    handles = [p.open("rb") for p in runs]
    try:
        heap: List[Tuple[bytes, int]] = []
        for idx, fh in enumerate(handles):
            dig = fh.read(digest_size)
            if not dig:
                continue
            if len(dig) != digest_size:
                raise RuntimeError(f"{runs[idx]}: truncated digest")
            heapq.heappush(heap, (dig, idx))

        count = 0
        last: Optional[bytes] = None
        with dst.open("wb") as out:
            while heap:
                dig, idx = heapq.heappop(heap)
                if dig != last:
                    out.write(dig)
                    last = dig
                    count += 1
                nxt = handles[idx].read(digest_size)
                if not nxt:
                    continue
                if len(nxt) != digest_size:
                    raise RuntimeError(f"{runs[idx]}: truncated digest")
                heapq.heappush(heap, (nxt, idx))
        return count
    finally:
        for fh in handles:
            fh.close()
        for p in runs:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass


def write_cvt1_from_raw(
    raw_path: Path, out_path: Path, algo: int, updated_unix: int
) -> int:
    digest_size = DIGEST_SIZE_BY_ALGO[algo]
    nbytes = raw_path.stat().st_size if raw_path.is_file() else 0
    if nbytes % digest_size:
        raise RuntimeError(f"{raw_path}: bad raw size {nbytes}")
    count = nbytes // digest_size
    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = struct.pack(
        "<IIIQI", CVT1_MAGIC, CVT1_VERSION, algo, updated_unix, count
    )
    with out_path.open("wb") as out, raw_path.open("rb") as src:
        out.write(header)
        while True:
            block = src.read(1024 * 1024)
            if not block:
                break
            out.write(block)
    return count


def _write_raw_as_text(raw_path: Path, txt_path: Path, digest_size: int) -> None:
    with raw_path.open("rb") as src, txt_path.open(
        "w", encoding="ascii", newline="\n"
    ) as out:
        while True:
            block = src.read(digest_size * 8192)
            if not block:
                break
            if len(block) % digest_size:
                raise RuntimeError(f"{raw_path}: truncated while writing text")
            for i in range(0, len(block), digest_size):
                out.write(block[i : i + digest_size].hex())
                out.write("\n")


def finalize_external_unique_to_packs(
    sink: ExternalUniqueSink,
    out_dir: Path,
    *,
    updated_unix: Optional[int] = None,
    text: bool = False,
) -> Dict[str, int]:
    """Merge spilled runs to exact-unique raw → CVT1 .bin (+ optional .txt)."""
    sink.close()
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = int(updated_unix if updated_unix is not None else time.time())
    counts: Dict[str, int] = {}
    print(
        f"    [unique] finalize {sink.stats_line()}",
        file=sys.stderr,
    )
    for size in (16, 20, 32):
        algo = ALGO_BY_DIGEST_SIZE[size]
        pack_name = PACK_NAME_BY_ALGO[algo]
        unique_raw = sink.directory / f"unique_{size}.raw"
        runs = list(sink.runs[size])
        print(
            f"    [unique] merge size={size} runs={len(runs)} → {pack_name}",
            file=sys.stderr,
        )
        n = merge_sorted_raw_runs(runs, size, unique_raw)
        sink.runs[size] = []
        if text:
            txt_path = out_dir / pack_name.replace(".bin", ".txt")
            _write_raw_as_text(unique_raw, txt_path, size)
            counts[txt_path.name] = n
        bin_path = out_dir / pack_name
        write_cvt1_from_raw(unique_raw, bin_path, algo, ts)
        counts[pack_name] = n
        try:
            unique_raw.unlink(missing_ok=True)
        except OSError:
            pass
        print(f"    [unique] {pack_name}: {n} exact unique", file=sys.stderr)
    drop_pct = (
        (100.0 * sink.duplicates_dropped / sink.offered) if sink.offered else 0.0
    )
    print(
        f"    [unique] done offered={sink.offered} "
        f"dropped_dup={sink.duplicates_dropped} ({drop_pct:.1f}%)",
        file=sys.stderr,
    )
    return counts


# ---------------------------------------------------------------------------
# SQLite sequential page carve (file-order read, like scanning a local .db)
# ---------------------------------------------------------------------------

def _read_varint(data: bytes, i: int) -> Tuple[int, int]:
    val = 0
    for n in range(9):
        if i >= len(data):
            raise ValueError("truncated varint")
        b = data[i]
        i += 1
        if n < 8:
            val = (val << 7) | (b & 0x7F)
            if (b & 0x80) == 0:
                return val, i
        else:
            val = (val << 8) | b
            return val, i
    raise ValueError("bad varint")


def _serial_type_len(serial: int) -> Tuple[str, int]:
    """Return (kind, length) kind in null|int|float|blob|text|reserved."""
    if serial == 0:
        return "null", 0
    if serial == 1:
        return "int", 1
    if serial == 2:
        return "int", 2
    if serial == 3:
        return "int", 3
    if serial == 4:
        return "int", 4
    if serial == 5:
        return "int", 6
    if serial == 6:
        return "int", 8
    if serial == 7:
        return "float", 8
    if serial == 8 or serial == 9:
        return "int", 0
    if serial >= 12 and serial % 2 == 0:
        return "blob", (serial - 12) // 2
    if serial >= 13 and serial % 2 == 1:
        return "text", (serial - 13) // 2
    return "reserved", 0


def _digests_from_record_payload(payload: bytes, sink: object) -> None:
    if not payload or getattr(sink, "stopped", False):
        return
    try:
        header_size, i = _read_varint(payload, 0)
    except ValueError:
        return
    if header_size < 1 or header_size > len(payload):
        return
    header_end = header_size
    serials: List[int] = []
    while i < header_end:
        try:
            s, i = _read_varint(payload, i)
        except ValueError:
            return
        serials.append(s)
    body = payload[header_end:]
    off = 0
    offer_hex = sink.offer_hex  # type: ignore[attr-defined]
    offer_raw = sink.offer_raw  # type: ignore[attr-defined]
    for s in serials:
        kind, ln = _serial_type_len(s)
        if off + ln > len(body):
            return
        chunk = body[off : off + ln]
        off += ln
        if kind == "text" and ln in (32, 40, 64):
            try:
                t = chunk.decode("ascii", errors="strict").strip().lower()
            except UnicodeError:
                continue
            if looks_like_digest(t) and not offer_hex(t):
                return
        elif kind == "blob" and ln in (16, 20, 32):
            if not offer_raw(chunk):
                return
        elif kind == "text" and 32 <= ln <= 80:
            # quoted / prefixed forms inside longer text cells
            try:
                t = chunk.decode("utf-8", errors="ignore").strip().lower()
            except Exception:
                continue
            m = re.search(r"\b([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b", t)
            if m and looks_like_digest(m.group(1)) and not offer_hex(m.group(1)):
                return


def _carve_leaf_table_page(page: bytes, sink: object, page1_hdr: bool) -> None:
    if getattr(sink, "stopped", False):
        return
    base = 100 if page1_hdr else 0
    if len(page) <= base + 8:
        return
    ptype = page[base]
    if ptype != 0x0D:  # table leaf
        return
    ncells = struct.unpack_from(">H", page, base + 3)[0]
    if ncells == 0 or ncells > 10000:
        return
    ptr_base = base + 8
    for c in range(ncells):
        if getattr(sink, "stopped", False):
            return
        poff = ptr_base + c * 2
        if poff + 2 > len(page):
            return
        cell_off = struct.unpack_from(">H", page, poff)[0]
        if cell_off >= len(page):
            continue
        try:
            payload_len, j = _read_varint(page, cell_off)
            _rowid, j = _read_varint(page, j)
        except ValueError:
            continue
        # payload may start with overflow; local size is min(available, payload_len)
        local = page[j:]
        if payload_len <= len(local):
            payload = local[:payload_len]
        else:
            # overflow: take local portion only (short hashes usually fit)
            payload = local
        _digests_from_record_payload(payload, sink)


def carve_sqlite_stream_from_ring(
    ring: ByteRing,
    sink: object,
) -> None:
    """
    Read the .db byte stream in file order from the ring and carve hash cells.
    Digests go to sink (memory set or disk spool).
    """
    # Page 1 begins with 100-byte DB header.
    hdr = ring.read(100)
    if len(hdr) < 100 or hdr[0:16] != b"SQLite format 3\x00":
        raise RuntimeError(
            "not a SQLite 3 database header (unexpected member or corrupt stream)"
        )
    page_size = struct.unpack(">H", hdr[16:18])[0]
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536 or (page_size & (page_size - 1)) != 0:
        raise RuntimeError(f"invalid SQLite page_size={page_size}")

    print(f"    [carve] SQLite page_size={page_size}", file=sys.stderr)

    # Rest of page 1
    rest = ring.read(page_size - 100)
    if len(rest) < page_size - 100:
        raise RuntimeError("truncated first SQLite page")
    page1 = hdr + rest
    _carve_leaf_table_page(page1, sink, page1_hdr=True)

    pages = 1
    last_report = 0
    while not getattr(sink, "stopped", False):
        page = ring.read(page_size)
        if len(page) == 0:
            break
        if len(page) < page_size:
            # trailing incomplete page — ignore
            break
        pages += 1
        _carve_leaf_table_page(page, sink, page1_hdr=False)
        if pages - last_report >= 50000:
            last_report = pages
            if isinstance(sink, MemoryDigestSink):
                detail = f"unique={len(sink.accepted)}"
            elif isinstance(sink, ExternalUniqueSink):
                detail = sink.stats_line()
            else:
                detail = "digests=?"
            print(
                f"    [carve] pages={pages} {detail} "
                f"ring_r={ring.bytes_read / (1024 * 1024):.1f}MiB "
                f"ring_w={ring.bytes_written / (1024 * 1024):.1f}MiB",
                file=sys.stderr,
            )

    if isinstance(sink, MemoryDigestSink):
        detail = f"unique={len(sink.accepted)}"
    elif isinstance(sink, ExternalUniqueSink):
        detail = sink.stats_line()
    else:
        detail = "digests=?"
    print(f"    [carve] done pages={pages} {detail}", file=sys.stderr)


# ---------------------------------------------------------------------------
# HTTP + ZIP (sequential local-header) — inflate member into ring
# ---------------------------------------------------------------------------

class HttpByteStream:
    def __init__(self, url: str, chunk_size: int = CHUNK_SIZE, timeout: int = 600) -> None:
        self.url = url
        self.chunk_size = chunk_size
        self.timeout = timeout
        self._buf = bytearray()
        self._eof = False
        self._resp = None
        self._iter = None
        self._use_requests = False
        self._open()

    def _open(self) -> None:
        try:
            import requests  # type: ignore

            self._use_requests = True
            self._resp = requests.get(
                self.url,
                stream=True,
                timeout=self.timeout,
                headers={"User-Agent": HTTP_USER_AGENT},
            )
            self._resp.raise_for_status()
            self._iter = self._resp.iter_content(chunk_size=self.chunk_size)
        except ImportError:
            req = Request(self.url, headers={"User-Agent": HTTP_USER_AGENT})
            self._resp = urlopen(req, timeout=self.timeout)
            self._use_requests = False

    def _fill(self) -> None:
        if self._eof:
            return
        if self._use_requests:
            try:
                block = next(self._iter)  # type: ignore[arg-type]
            except StopIteration:
                self._eof = True
                return
            if block:
                self._buf.extend(block)
        else:
            block = self._resp.read(self.chunk_size)  # type: ignore[union-attr]
            if not block:
                self._eof = True
                return
            self._buf.extend(block)

    def read(self, n: int) -> bytes:
        while len(self._buf) < n and not self._eof:
            self._fill()
        if not self._buf:
            return b""
        take = min(n, len(self._buf))
        out = bytes(self._buf[:take])
        del self._buf[:take]
        return out

    def discard(self, n: int) -> None:
        left = n
        while left > 0:
            while len(self._buf) < min(left, self.chunk_size) and not self._eof:
                self._fill()
            if not self._buf:
                break
            take = min(left, len(self._buf))
            del self._buf[:take]
            left -= take

    def close(self) -> None:
        try:
            if self._resp is not None:
                self._resp.close()
        except Exception:
            pass

    def __enter__(self) -> "HttpByteStream":
        return self

    def __exit__(self, *args) -> None:
        self.close()


def _norm_zip_path(name: str) -> str:
    return name.replace("\\", "/").lstrip("./")


def _member_basename(name: str) -> str:
    return _norm_zip_path(name).rsplit("/", 1)[-1]


def _wildcard_match(pattern: str, value: str) -> bool:
    pat = pattern.replace("\\", "/").lower()
    val = value.replace("\\", "/").lower()
    if "*" not in pat:
        return pat == val or val.endswith("/" + pat) or _member_basename(val) == pat
    parts = re.split(r"(\*)", pat)
    rx = "".join("[^/]*" if p == "*" else re.escape(p) for p in parts)
    return re.fullmatch(rx, val) is not None or re.fullmatch(rx, _member_basename(val)) is not None


def _is_rds_modern_db(name: str) -> bool:
    base = _member_basename(name).lower()
    if not base.endswith(".db") or "minimal" in base:
        return False
    return base.endswith("_modern.db")


def _is_sqlite_member(name: str) -> bool:
    return _member_basename(name).lower().endswith((".db", ".sqlite", ".sqlite3"))


def _member_matches(name: str, want: Optional[str]) -> bool:
    path = _norm_zip_path(name)
    if want:
        want_n = _norm_zip_path(want)
        if "*" in want_n:
            return _wildcard_match(want_n, path) or _wildcard_match(
                _member_basename(want_n), _member_basename(path)
            )
        wl, pl = want_n.lower(), path.lower()
        return pl == wl or pl.endswith("/" + wl) or _member_basename(pl) == wl
    return _is_rds_modern_db(path)


def _skip_data_descriptor(stream: HttpByteStream) -> None:
    sig = stream.read(4)
    if sig == ZIP_DATA_DESC_SIG:
        stream.discard(12)
    else:
        stream.discard(8)


def _inflate_zip_entry(
    stream: HttpByteStream,
    method: int,
    comp_size: int,
    has_data_desc: bool,
    chunk_size: int,
) -> Iterator[bytes]:
    if method not in (0, 8):
        raise RuntimeError(f"ZIP: unsupported compression method {method}")
    if method == 0:
        left = comp_size
        while left > 0:
            block = stream.read(min(chunk_size, left))
            if not block:
                break
            left -= len(block)
            yield block
        if has_data_desc:
            _skip_data_descriptor(stream)
        return

    dec = zlib.decompressobj(-zlib.MAX_WBITS)
    if not has_data_desc and comp_size > 0:
        left = comp_size
        while left > 0:
            block = stream.read(min(chunk_size, left))
            if not block:
                break
            left -= len(block)
            out = dec.decompress(block)
            if out:
                yield out
        tail = dec.flush()
        if tail:
            yield tail
        if has_data_desc:
            _skip_data_descriptor(stream)
        return

    while True:
        block = stream.read(chunk_size)
        if not block:
            break
        out = dec.decompress(block)
        if out:
            yield out
        if dec.eof:
            unused = dec.unused_data or b""
            if unused:
                stream._buf[0:0] = unused
            break
    if not dec.eof:
        tail = dec.flush()
        if tail:
            yield tail
    if has_data_desc:
        peek = stream.read(4)
        if peek == ZIP_DATA_DESC_SIG:
            stream.discard(12)
        elif len(peek) == 4:
            stream._buf[0:0] = peek


def _skip_entry(stream: HttpByteStream, method: int, comp_size: int, has_data_desc: bool, chunk_size: int) -> None:
    if has_data_desc and comp_size == 0:
        for _ in _inflate_zip_entry(stream, method, 0, True, chunk_size):
            pass
        return
    stream.discard(comp_size)
    if has_data_desc:
        _skip_data_descriptor(stream)


def _walk_zip_to_member(
    stream: HttpByteStream, member: Optional[str], chunk_size: int
) -> Tuple[str, int, int, bool]:
    seen_db: List[str] = []
    while True:
        sig = stream.read(4)
        if len(sig) < 4 or sig in (ZIP_CENTRAL_SIG, ZIP_EOCD_SIG, ZIP_DATA_DESC_SIG):
            break
        if sig != ZIP_LOCAL_SIG:
            raise RuntimeError(f"ZIP stream: unexpected signature {sig!r}")

        header = stream.read(26)
        if len(header) < 26:
            raise RuntimeError("ZIP stream: truncated local header")
        (
            _ver, flags, method, _t, _d, _crc, comp_size, uncomp_size, name_len, extra_len,
        ) = struct.unpack("<HHHHHIIIHH", header)
        name_b = stream.read(name_len)
        extra_b = stream.read(extra_len)
        if len(name_b) < name_len or len(extra_b) < extra_len:
            raise RuntimeError("ZIP stream: truncated name/extra")
        name = name_b.decode("utf-8", errors="replace")
        has_data_desc = bool(flags & 0x08)

        if comp_size == 0xFFFFFFFF or uncomp_size == 0xFFFFFFFF:
            pos = 0
            while pos + 4 <= len(extra_b):
                xid, xsz = struct.unpack_from("<HH", extra_b, pos)
                pos += 4
                if pos + xsz > len(extra_b):
                    break
                payload = extra_b[pos : pos + xsz]
                pos += xsz
                if xid != 0x0001:
                    continue
                off = 0
                if uncomp_size == 0xFFFFFFFF and off + 8 <= len(payload):
                    uncomp_size = struct.unpack_from("<Q", payload, off)[0]
                    off += 8
                if comp_size == 0xFFFFFFFF and off + 8 <= len(payload):
                    comp_size = int(struct.unpack_from("<Q", payload, off)[0])
                break

        if _is_sqlite_member(name):
            seen_db.append(_norm_zip_path(name))

        take = (not name.endswith("/")) and _member_matches(name, member)
        if take:
            return name, method, int(comp_size), has_data_desc

        _skip_entry(stream, method, int(comp_size), has_data_desc, chunk_size)

    hint = (" Seen .db: " + ", ".join(seen_db[:8])) if seen_db else ""
    raise RuntimeError(f"ZIP member not found matching {member or DEFAULT_ZIP_MEMBER!r}.{hint}")


def writer_inflate_db_to_ring(
    url: str,
    ring: ByteRing,
    *,
    member: Optional[str],
    chunk_size: int,
    timeout: int,
) -> None:
    """Producer: zip HTTP → inflate target .db → ring.write (throttled)."""
    try:
        with HttpByteStream(url, chunk_size=chunk_size, timeout=timeout) as stream:
            name, method, comp_size, has_data_desc = _walk_zip_to_member(
                stream, member, chunk_size
            )
            print(
                f"    [writer] inflating {name} (method={method}) → ring "
                f"({ring.cap / (1024 * 1024):.0f} MiB)",
                file=sys.stderr,
            )
            last_mb = 0
            for block in _inflate_zip_entry(
                stream, method, comp_size, has_data_desc, chunk_size
            ):
                ring.write(block)
                mb = int(ring.bytes_written // (50 * 1024 * 1024))
                if mb > last_mb:
                    last_mb = mb
                    print(
                        f"    [writer] inflated {ring.bytes_written / (1024 * 1024):.1f} MiB "
                        f"(ring live={(ring.bytes_written - ring.bytes_read) / (1024 * 1024):.1f} MiB)",
                        file=sys.stderr,
                    )
        ring.close_writer()
        print(
            f"    [writer] EOF after {ring.bytes_written / (1024 * 1024):.1f} MiB inflated",
            file=sys.stderr,
        )
    except BaseException as exc:
        ring.fail(exc)
        raise


def _run_zip_carve_pipeline(
    url: str,
    sink: object,
    *,
    member: Optional[str],
    ring_mb: int,
    chunk_size: int,
    timeout: int,
) -> None:
    """Two-thread pipeline: writer → ring → SQLite page carve reader → sink."""
    mem = member if member is not None else DEFAULT_ZIP_MEMBER
    ring = ByteRing(ring_mb * 1024 * 1024)
    print(
        f"    [stream] ring={ring_mb} MiB  member={mem!r}  (no full .db on disk)",
        file=sys.stderr,
    )

    errors: List[BaseException] = []

    def run_writer() -> None:
        try:
            writer_inflate_db_to_ring(
                url, ring, member=mem, chunk_size=chunk_size, timeout=timeout
            )
        except BaseException as exc:
            errors.append(exc)

    t = threading.Thread(target=run_writer, name="zip-db-writer", daemon=True)
    t.start()
    try:
        carve_sqlite_stream_from_ring(ring, sink)
    finally:
        t.join(timeout=max(timeout + 120, 3600))
    if errors:
        raise errors[0]


def stream_rds_zip_carve(
    url: str,
    *,
    member: Optional[str] = None,
    ring_mb: int = DEFAULT_RING_MB,
    chunk_size: int = CHUNK_SIZE,
    max_keep: int = 0,
    timeout: int = 600,
) -> Set[str]:
    """Zip carve into an in-memory set (use max_keep>0 to cap; 0=unlimited RAM)."""
    sink = MemoryDigestSink(max_keep=max_keep)
    _run_zip_carve_pipeline(
        url,
        sink,
        member=member,
        ring_mb=ring_mb,
        chunk_size=chunk_size,
        timeout=timeout,
    )
    return sink.accepted


def stream_rds_zip_carve_full(
    url: str,
    out_dir: Path,
    *,
    member: Optional[str] = None,
    ring_mb: int = DEFAULT_RING_MB,
    chunk_size: int = CHUNK_SIZE,
    timeout: int = 600,
    text: bool = False,
    spool_dir: Optional[Path] = None,
    unique_memory_items: int = DEFAULT_UNIQUE_MEMORY_ITEMS,
) -> Dict[str, int]:
    """
    Full modern.db carve with exact online unique (memory set → spill runs → merge).
    Safe for free GitHub runners: peak disk ≈ unique digests, not duplicate rows.
    """
    out_dir = Path(out_dir)
    tmp_root = Path(spool_dir) if spool_dir else Path(tempfile.mkdtemp(prefix="cvt_unique_"))
    own_tmp = spool_dir is None
    try:
        print(
            f"    [full] external unique at {tmp_root} "
            f"(memory_items={unique_memory_items})",
            file=sys.stderr,
        )
        with ExternalUniqueSink(
            tmp_root / "runs", memory_items=unique_memory_items
        ) as sink:
            _run_zip_carve_pipeline(
                url,
                sink,
                member=member,
                ring_mb=ring_mb,
                chunk_size=chunk_size,
                timeout=timeout,
            )
            return finalize_external_unique_to_packs(sink, out_dir, text=text)
    finally:
        if own_tmp:
            shutil.rmtree(tmp_root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Optional: classic temp-file + SQL (small DBs / fat disks only)
# ---------------------------------------------------------------------------

def _resolve_hash_source(conn: sqlite3.Connection) -> Tuple[str, List[str]]:
    names = {
        r[0].lower(): r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
        )
    }
    source = None
    for cand in ("file", "metadata"):
        if cand in names:
            source = names[cand]
            break
    if not source:
        raise RuntimeError("RDS DB: no FILE/metadata")
    cols = [r[1].lower() for r in conn.execute(f'PRAGMA table_info("{source}")')]
    algos = [c for c in ("sha256", "sha1", "md5") if c in cols]
    if not algos:
        raise RuntimeError(f"no hash columns on {source}")
    return source, algos


def iter_hash_lines_from_rds_db(db_path: Path, batch_bytes: int = 1024 * 1024) -> Iterator[bytes]:
    uri = db_path.resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.execute("PRAGMA query_only=ON")
        source, algos = _resolve_hash_source(conn)
        buf: List[str] = []
        size = 0
        for algo in algos:
            q = (
                f'SELECT DISTINCT {algo} FROM "{source}" '
                f"WHERE {algo} IS NOT NULL AND TRIM({algo}) != ''"
            )
            for (val,) in conn.execute(q):
                if val is None:
                    continue
                h = str(val).strip().lower()
                if not looks_like_digest(h):
                    continue
                line = h + "\n"
                buf.append(line)
                size += len(line)
                if size >= batch_bytes:
                    yield "".join(buf).encode("ascii", errors="ignore")
                    buf.clear()
                    size = 0
        if buf:
            yield "".join(buf).encode("ascii", errors="ignore")
    finally:
        conn.close()


def filter_hashes_from_text_chunks(
    chunks: Iterable[bytes],
    *,
    line_filter: Callable[[str], Optional[str]] = digest_only_filter,
    max_keep: int = 2_000_000,
) -> Set[str]:
    pending = bytearray()
    accepted: Set[str] = set()
    # max_keep <= 0 means unlimited
    capped = max_keep > 0

    def consume(text_bytes: bytes, final: bool = False) -> bool:
        nonlocal pending
        if text_bytes:
            pending.extend(text_bytes)
        while True:
            nl = pending.find(b"\n")
            if nl < 0:
                break
            raw = bytes(pending[:nl])
            del pending[: nl + 1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            dig = line_filter(raw.decode("utf-8", errors="ignore"))
            if dig and dig not in accepted:
                accepted.add(dig)
                if capped and len(accepted) >= max_keep:
                    return True
        if final and pending:
            dig = line_filter(bytes(pending).decode("utf-8", errors="ignore"))
            pending.clear()
            if dig:
                accepted.add(dig)
        return bool(capped and len(accepted) >= max_keep)

    for chunk in chunks:
        if consume(chunk):
            break
    else:
        consume(b"", final=True)
    return accepted


class ZlibStreamDecoder:
    def __init__(self, mode: str = "gzip") -> None:
        wbits = {
            "gzip": 16 + zlib.MAX_WBITS,
            "zlib": zlib.MAX_WBITS,
            "raw": -zlib.MAX_WBITS,
            "auto": 16 + zlib.MAX_WBITS,
        }[mode]
        self._obj = zlib.decompressobj(wbits)
        self._mode = mode

    def feed(self, data: bytes) -> bytes:
        if not data:
            return b""
        try:
            return self._obj.decompress(data)
        except zlib.error:
            if self._mode != "auto":
                raise
            self._obj = zlib.decompressobj(zlib.MAX_WBITS)
            return self._obj.decompress(data)

    def flush(self) -> bytes:
        try:
            return self._obj.flush()
        except zlib.error:
            return b""


def guess_encoding(url: str, explicit: str) -> str:
    if explicit != "auto":
        return explicit
    u = url.lower().split("?", 1)[0]
    if u.endswith(".zip"):
        return "zip"
    if u.endswith(".gz") or u.endswith(".gzip"):
        return "gzip"
    return "none"


def stream_filter_hashes(
    url: str,
    *,
    encoding: str = "auto",
    zip_member: Optional[str] = None,
    mode: str = "carve",
    ring_mb: int = DEFAULT_RING_MB,
    chunk_size: int = CHUNK_SIZE,
    max_keep: int = 0,
    timeout: int = 600,
) -> Set[str]:
    enc = guess_encoding(url, encoding)
    # 0 = unlimited for memory paths; zip full-scan uses stream_rds_zip_carve_full.
    mem_cap = max_keep if max_keep > 0 else 0

    if enc == "zip":
        if mode == "sqlite-disk":
            return _stream_zip_sqlite_disk(
                url,
                member=zip_member,
                chunk_size=chunk_size,
                max_keep=mem_cap if mem_cap else 2_000_000,
                timeout=timeout,
            )
        return stream_rds_zip_carve(
            url,
            member=zip_member,
            ring_mb=ring_mb,
            chunk_size=chunk_size,
            max_keep=mem_cap,
            timeout=timeout,
        )

    decoder = None if enc == "none" else ZlibStreamDecoder(enc)

    def plain_chunks() -> Iterator[bytes]:
        with HttpByteStream(url, chunk_size=chunk_size, timeout=timeout) as stream:
            while True:
                block = stream.read(chunk_size)
                if not block:
                    break
                yield decoder.feed(block) if decoder else block
        if decoder is not None:
            tail = decoder.flush()
            if tail:
                yield tail

    return filter_hashes_from_text_chunks(
        plain_chunks(), line_filter=default_filter, max_keep=max_keep
    )


def _stream_zip_sqlite_disk(
    url: str,
    *,
    member: Optional[str],
    chunk_size: int,
    max_keep: int,
    timeout: int,
) -> Set[str]:
    """Legacy path: extract .db to temp (needs huge disk)."""
    mem = member if member is not None else DEFAULT_ZIP_MEMBER
    fd, tmp = tempfile.mkstemp(prefix="cvt_rds_", suffix=".db")
    os.close(fd)
    path = Path(tmp)
    try:
        with HttpByteStream(url, chunk_size=chunk_size, timeout=timeout) as stream:
            name, method, comp_size, has_data_desc = _walk_zip_to_member(
                stream, mem, chunk_size
            )
            print(f"    [sqlite-disk] extracting {name} → {path}", file=sys.stderr)
            with path.open("wb") as out:
                for block in _inflate_zip_entry(
                    stream, method, comp_size, has_data_desc, chunk_size
                ):
                    out.write(block)
        return filter_hashes_from_text_chunks(
            iter_hash_lines_from_rds_db(path),
            line_filter=digest_only_filter,
            max_keep=max_keep,
        )
    finally:
        try:
            path.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# CVT1 packs
# ---------------------------------------------------------------------------

def partition_by_algo(hex_digests: Set[str]) -> Dict[int, List[bytes]]:
    buckets: Dict[int, List[bytes]] = {ALGO_MD5: [], ALGO_SHA1: [], ALGO_SHA256: []}
    for h in hex_digests:
        raw = hex_to_raw(h)
        if len(raw) == 16:
            buckets[ALGO_MD5].append(raw)
        elif len(raw) == 20:
            buckets[ALGO_SHA1].append(raw)
        elif len(raw) == 32:
            buckets[ALGO_SHA256].append(raw)
    for algo in buckets:
        buckets[algo].sort()
    return buckets


def write_cvt1_pack(path: Path, algo: int, digests: List[bytes], updated_unix: int) -> None:
    header = struct.pack(
        "<IIIQI", CVT1_MAGIC, CVT1_VERSION, algo, updated_unix, len(digests)
    )
    with path.open("wb") as f:
        f.write(header)
        for d in digests:
            f.write(d)


def write_clean_packs(
    out_dir: Path, hex_digests: Set[str], updated_unix: Optional[int] = None
) -> Dict[str, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = int(updated_unix if updated_unix is not None else time.time())
    buckets = partition_by_algo(hex_digests)
    counts: Dict[str, int] = {}
    for algo, name in (
        (ALGO_MD5, "clean_md5.bin"),
        (ALGO_SHA1, "clean_sha1.bin"),
        (ALGO_SHA256, "clean_sha256.bin"),
    ):
        write_cvt1_pack(out_dir / name, algo, buckets[algo], ts)
        counts[name] = len(buckets[algo])
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "url",
        nargs="?",
        default=None,
        help="HTTP(S) URL (RDSv3 .zip / .gz / text)",
    )
    src.add_argument(
        "--latest-modern",
        action="store_true",
        help=(
            "Auto-discover the newest full RDS_*_modern.zip from NIST "
            "(skips *_minimal* and *_delta*)"
        ),
    )
    ap.add_argument(
        "--encoding",
        choices=("auto", "zip", "gzip", "zlib", "raw", "none"),
        default="auto",
    )
    ap.add_argument(
        "--mode",
        choices=("carve", "sqlite-disk"),
        default="carve",
        help="carve=ring+SQLite page scan (default, GHA-safe); "
        "sqlite-disk=extract full .db then SQL (needs huge disk)",
    )
    ap.add_argument(
        "--member",
        default=None,
        help=f"ZIP member pattern (default: {DEFAULT_ZIP_MEMBER})",
    )
    ap.add_argument(
        "--ring-mb",
        type=int,
        default=DEFAULT_RING_MB,
        help=f"ring buffer MiB (default {DEFAULT_RING_MB}; use 10240 only if RAM allows)",
    )
    ap.add_argument("--chunk-size", type=int, default=CHUNK_SIZE)
    ap.add_argument(
        "--max-keep",
        type=int,
        default=0,
        help="0=full zip carve via exact online unique (default); >0=in-memory cap",
    )
    ap.add_argument(
        "--unique-memory-items",
        type=int,
        default=DEFAULT_UNIQUE_MEMORY_ITEMS,
        help=(
            "full-scan: max digests held in RAM before spilling a sorted unique "
            f"run (default {DEFAULT_UNIQUE_MEMORY_ITEMS})"
        ),
    )
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("-o", "--output", default="clean_packs")
    ap.add_argument("--format", choices=("bin", "text"), default="bin")
    args = ap.parse_args()

    if args.latest_modern:
        try:
            url = discover_latest_rds_modern_zip(timeout=min(60, args.timeout))
        except Exception as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2
    else:
        url = args.url

    enc = guess_encoding(url, args.encoding)
    use_full_spool = (
        enc == "zip" and args.mode == "carve" and args.max_keep == 0
    )
    print(
        f"[*] {url}\n"
        f"    encoding={enc} mode={args.mode} ring_mb={args.ring_mb} "
        f"max_keep={args.max_keep}"
        f"{' full_unique=on' if use_full_spool else ''}"
        f"{f' unique_memory_items={args.unique_memory_items}' if use_full_spool else ''}",
        file=sys.stderr,
    )

    out = Path(args.output)
    try:
        if use_full_spool:
            counts = stream_rds_zip_carve_full(
                url,
                out,
                member=args.member,
                ring_mb=args.ring_mb,
                chunk_size=args.chunk_size,
                timeout=args.timeout,
                text=(args.format == "text"),
                unique_memory_items=args.unique_memory_items,
            )
            for name, n in counts.items():
                print(f"[+] {name}: {n}", file=sys.stderr)
            print(f"[+] CVT1 → {out.resolve()}", file=sys.stderr)
            return 0

        accepted = stream_filter_hashes(
            url,
            encoding=args.encoding,
            zip_member=args.member,
            mode=args.mode,
            ring_mb=args.ring_mb,
            chunk_size=args.chunk_size,
            max_keep=args.max_keep,
            timeout=args.timeout,
        )
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print(f"[+] Kept {len(accepted)} unique digest(s)", file=sys.stderr)
    if args.format == "text":
        out.mkdir(parents=True, exist_ok=True)
        path = out / "clean_hashes.txt" if out.suffix == "" else out
        if path.suffix == "":
            path = out / "clean_hashes.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(h + "\n" for h in sorted(accepted)), encoding="utf-8")
        print(f"[+] {path}", file=sys.stderr)
        return 0

    counts = write_clean_packs(out, accepted)
    for name, n in counts.items():
        print(f"[+] {name}: {n}", file=sys.stderr)
    print(f"[+] CVT1 → {out.resolve()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
