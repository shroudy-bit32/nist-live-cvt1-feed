# ⚡ NIST NSRL Live CVT1 & DFIR Hash Feed Pipeline

An automated, high-performance, **zero-disk footprint** threat intelligence pipeline that parses the massive (~120 GB) NIST NSRL Modern database entirely in-memory. It generates daily micro-sized native binary hash feeds (CVT1 format) for high-performance engines, alongside **DFIR-compatible plain-text lists** (for Magnet AXIOM, FTK, etc.), deploying them directly to GitHub Releases.

---

## 🧠 The Engineering Problem & Architecture

### The Constraint
The official NIST NSRL Modern SQLite database is a massive **~120 GB** monolith. Standard implementations require downloading the entire archive, extracting it to disk, and running heavy SQL queries. Doing this on cloud infrastructure or free-tier automation layers like GitHub Actions is impossible due to the strict **14 GB disk space limit** and performance bottlenecks.

### The Solution: Native Page Carving, Scatter-Gather Chunking & Compatibility Layers
This project completely bypasses the local storage layer and the SQLite engine itself:

1. **Dynamic Upstream Resolution:** The pipeline dynamically scrapes NIST directories to always target the latest `RDS_*_modern.zip` release without manual URL pinning.
2. **Pre-Flight Speed Probe:** Before committing to a multi-hour carve, a dedicated job measures this runner's *real* sustained throughput to the NIST host and projects whether the full download fits GitHub-hosted runners' 6-hour job ceiling — the expensive job is skipped (not wasted) on a bad-network night, rather than failing after hours of work.
3. **Network Stream to Inflation:** The remote `.zip` file is streamed via HTTP chunks (with automatic reconnect-and-resume on a dropped connection) and decompressed (inflated) on the fly.
4. **Ping-Pong Native Carver:** A pybind11 C++ engine (`native/`) fills one 256 MiB arena while a separate thread pool carves the previous one in parallel — sequential SQLite page-by-page scanning, no B-tree traversal, no full download-to-disk. Digest extraction is schema-positional (matches the exact trailing `crc32/md5/sha1/sha256` column layout of the NSRL `METADATA` table), not a blind "any hex-looking string" scan, so it can't be fooled by unrelated hash-shaped columns or cache-style filenames elsewhere in the row.
5. **Scatter-Gather Disk Safety:** Instead of accumulating one giant on-disk shard set for the whole ~400+ GiB decompressed database, the engine periodically compacts (sort + exact-unique) and uploads a `part_NNNNN_*.bin` checkpoint, then frees the local disk — bounding the runner's footprint regardless of total database size, and meaning a timeout loses at most one checkpoint window, not the whole run.
6. **Zero-Overhead Binary Packs (CVT1):** Extracted hashes are strictly packed as raw binary streams (16 bytes for MD5, 20 bytes for SHA-1, 32 bytes for SHA-256) instead of bulky ASCII text hex strings.
7. **Exact-Unique Merge:** A separate, lightweight job downloads every checkpoint and does one true cross-part deduplication pass via external k-way merge over already-sorted runs — never an in-memory set, so RAM stays flat regardless of total hash count.
8. **DFIR Compatibility Layer:** A lightweight secondary pipeline exports standard ASCII Hex text files (one hash per line) for traditional forensics tools — split into parts past 1.5 GiB the same way as `.bin`, no compression anywhere in the release pipeline.

A pure-Python fallback path (ring buffer + Python carve loop, no compiled extension) still exists for local experimentation without a C++ toolchain — see `CVT_FORCE_PYTHON=1` below — but the native engine is what production runs use.

---

## 📊 Live Feed Statistics

Element sizes are fixed by format; total population is the true exact-unique count from the latest run, not an estimate:

| Artifact | Format | Element Size |
| :--- | :--- | :--- |
| 📦 `clean_md5.*` | Raw Binary (CVT1) | 16 Bytes |
| 📦 `clean_sha1.*` | Raw Binary (CVT1) | 20 Bytes |
| 📦 `clean_sha256.*` | Raw Binary (CVT1) | 32 Bytes |
| 📄 `clean_md5.txt.*` | ASCII Hex | 32 Chars + `\n` |
| 📄 `clean_sha1.txt.*` | ASCII Hex | 40 Chars + `\n` |
| 📄 `clean_sha256.txt.*` | ASCII Hex | 64 Chars + `\n` |

The real digest count per algorithm (tens of millions at full NSRL modern scale — `clean_sha256` alone already clears GitHub's 2 GiB single-asset limit) is published in **every release's notes**, read live from that run's own CVT1 headers — check the [latest release](../../releases/latest) rather than trusting a number printed here, since it changes with every NIST update.

> *Feeds are completely refreshed and re-generated every 24 hours via automated pipelines.*

---

## 📦 Release Asset Structure (Multi-Part Files)

GitHub caps a single release asset at 2 GiB. `clean_sha256` clears that on its own — both `.bin` and `.txt` — and raw cryptographic digests don't compress (measured: gzip -9 / zip -9 on real SHA-256 output land at ~100.0% of original size, there's no redundancy for DEFLATE to exploit), so compression wouldn't rescue an oversized file anyway. This pipeline handles it the same way any large dataset distribution does: **split into numbered parts, no compression involved at all.**

- **`.bin` (CVT1 binary):** a file over 1.5 GiB becomes `clean_<algo>_part01.bin`, `clean_<algo>_part02.bin`, … (zero-padded so a plain glob sorts in the right order). Part 1 carries the original CVT1 header verbatim (the *total* count across all parts, not just part 1's), so:

  ```bash
  cat clean_sha256_part*.bin > clean_sha256_full.bin
  ```

  reconstructs a byte-exact copy of the original single `.bin` — same format as always, nothing to re-parse. (A lone part 1 is intentionally incomplete by itself, same as any split archive piece — its header describes the whole file, so a strict CVT1 reader will correctly refuse to treat it as complete until it's reassembled.)

- **`.txt` (DFIR hex lists):** plain hex-per-line text, split on line boundaries the same way and reassembled just as simply:

  ```bash
  cat clean_sha256_part*.txt > clean_sha256.txt
  ```

- **Files that never crossed 1.5 GiB** (currently `clean_md5`, `clean_sha1`, both `.bin` and `.txt`) ship as a single plain file — no `_partNN` suffix, no merge step needed.

Every release's notes are generated fresh from that release's actual asset list (not assumed from a previous run), with a per-algorithm table of files, sizes, and the exact merge command to use.

---

## 🚀 Integration Guide: How to Use the Feeds

Because the feeds are deployed as pure, un-padded binary structures, you don't need heavy JSON/CSV/SQL parsers. You can directly integrate them into your malware scanning engines, sandbox environments, or whitelist checkers.

### 1. DFIR Tools & Standard Software (Magnet AXIOM, FTK, SIEMs)
Simply download the `.txt` artifacts from the latest Release. These are standard, pre-cleaned, line-separated ASCII hex lists. You can ingest them directly into Magnet AXIOM, Autopsy, FTK, or any SIEM/Sandbox environment for instant whitelisting.

### 2. Integration in C/C++ (Zero-Copy Memory Mapping)
For custom engines, you can directly map the native `.bin` files into memory using `mmap` for instant, zero-allocation runtime space lookups. If the algorithm you want was split into multiple parts (see [Release Asset Structure](#-release-asset-structure-multi-part-files) above), run the `cat` merge command first — the reconstructed file is byte-identical to what a single-part release would have shipped, so nothing below changes:

```cpp
#include <iostream>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct SHA256Hash {
    uint8_t bytes[32];
};

int main() {
    int fd = open("clean_sha256.bin", O_RDONLY);
    if (fd < 0) return 1;

    struct stat sb;
    fstat(fd, &sb);

    // Memory-map the entire feed instantly (Skip 24-byte CVT1 header)
    size_t data_size = sb.st_size - 24;
    size_t total_hashes = data_size / sizeof(SHA256Hash);
    
    // Map the file
    uint8_t* map_ptr = (uint8_t*)mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    SHA256Hash* hash_feed = (SHA256Hash*)(map_ptr + 24);

    std::cout << "[+] Instantly mapped " << total_hashes << " hashes into runtime space." << std::endl;

    // Perform ultra-fast O(log N) binary search here since the array is pre-sorted
    // Example: std::binary_search(hash_feed, hash_feed + total_hashes, target_hash);

    munmap(map_ptr, sb.st_size);
    close(fd);
    return 0;
}
```

### 3. Integration in Python (Struct Unpacking)
If you want to read or query the generated binary files using Python, you can unpack the CVT1 headers like this:
```
import struct
from pathlib import Path

def parse_cvt1_pack(bin_path: str):
    path = Path(bin_path)
    if not path.exists():
        return []
        
    data = path.read_bytes()
    header_format = "<IIIQI"
    header_size = struct.calcsize(header_format)
    
    if len(data) < header_size:
        return []
        
    magic, version, algo, timestamp, count = struct.unpack_from(header_format, data, 0)
    algo_sizes = {1: 16, 2: 20, 3: 32}
    
    if algo not in algo_sizes:
        return []
        
    hash_size = algo_sizes[algo]
    hashes = []
    offset = header_size
    
    for _ in range(count):
        if offset + hash_size > len(data):
            break
        hashes.append(data[offset : offset + hash_size].hex())
        offset += hash_size
        
    return hashes
```

## 🛠️ Running the Infrastructure Locally
You can run the exact pipeline logic on your local machine without downloading the database to your hard drive.

### Prerequisites
```bash
pip install requests pybind11 scikit-build-core
pip install .          # builds the native C++ carve engine (native/) -- needs a C++17 compiler + CMake
```
Skip the native build and set `CVT_FORCE_PYTHON=1` to use the slower pure-Python fallback instead.

### Run the full local pipeline
```bash
# 1. Measure real throughput before committing to a multi-hour run (optional but recommended)
python tools/speed_probe.py

# 2. Fetch latest NIST zip, carve in-memory, checkpoint to scatter-gather parts
python tools/stream_http_hash_filter.py --latest-modern \
  --parts-dir chunks --checkpoint-mb 1536

# 3. Merge every checkpoint into exact-unique clean_*.bin (external k-way merge, no in-memory set)
python tools/merge_cvt1_parts.py -i chunks -o clean_packs

# 4. Split anything over 1.5 GiB into clean_<algo>_partNN.bin (raw -- compression doesn't help)
python tools/pack_release_assets.py --dir clean_packs --limit-mib 1500

# 5. Export CVT1 binaries to DFIR-compatible plain-text lists (per algorithm)
python tools/cvt1_to_text.py -i clean_packs -o clean_packs clean_md5.bin

# 6. Split any resulting .txt over 1.5 GiB too (same tool, same rule -- no compression)
python tools/pack_release_assets.py --dir clean_packs --files clean_md5.txt --limit-mib 1500
```

Note: native-engine memory stays close to `--ring-mb` × 2 (ping-pong arenas) plus a bounded per-worker TLS bucket budget (auto-sized from `--bucket-ram-budget-mb`, default 2048 MiB total) while processing 100+ GB over the network pipeline — see `tools/stream_http_hash_filter.py --help` for every tuning knob.

## 🛡️ Maintainer \& Author
Cemil Emre Bıyık - Computer Systems \& Low-Level Security Architecture Enthusiast.

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.



