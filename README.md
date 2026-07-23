# ⚡ NIST NSRL Live CVT1 & DFIR Hash Feed Pipeline

An automated, high-performance, **zero-disk footprint** threat intelligence pipeline that parses the massive (~120 GB) NIST NSRL Modern database entirely in-memory. It generates daily micro-sized native binary hash feeds (CVT1 format) for high-performance engines, alongside **DFIR-compatible plain-text lists** (for Magnet AXIOM, FTK, etc.), deploying them directly to GitHub Releases.

---

## 🧠 The Engineering Problem & Architecture

### The Constraint
The official NIST NSRL Modern SQLite database is a massive **~120 GB** monolith. Standard implementations require downloading the entire archive, extracting it to disk, and running heavy SQL queries. Doing this on cloud infrastructure or free-tier automation layers like GitHub Actions is impossible due to the strict **14 GB disk space limit** and performance bottlenecks.

### The Solution: SQLite Page Carving, Ring Buffers & Compatibility Layers
This project completely bypasses the local storage layer and the SQLite engine itself:

1. **Dynamic Upstream Resolution:** The pipeline dynamically scrapes NIST directories to always target the latest `RDS_*_modern.zip` release without manual URL pinning.
2. **Network Stream to Inflation:** The remote `.zip` file is streamed via HTTP chunks and decompressed (inflated) on the fly.
3. **Circular Ring Buffer:** Decompressed raw binary `.db` bytes are pushed into a highly optimized, custom multi-threaded **Circular Ring Buffer** (`ByteRing` class).
4. **Low-Level Page Carving:** Instead of initializing a traditional SQLite database connection, a custom **Binary Carver** sequentially scans the byte stream in file order. It parses the physical SQLite page/cell boundaries on the fly, extracting valid `MD5`, `SHA-1`, and `SHA-256` columns.
5. **Zero-Overhead Binary Packs (CVT1):** Extracted hashes are strictly packed as raw binary streams (16 bytes for MD5, 20 bytes for SHA-1, 32 bytes for SHA-256) instead of bulky ASCII text hex strings.
6. **DFIR Compatibility Layer:** A lightweight secondary pipeline automatically strips the CVT1 headers and exports standard ASCII Hex text files (one hash per line) for traditional forensics tools.

---

## 📊 Live Feed Statistics

Thanks to the elimination of SQLite B-Tree metadata fragmentation and index headers, the massive database overhead collapses into tightly packed files available in two flavors:

| Artifact Name | Format | Element Size | Total Packed Size | Target Population |
| :--- | :--- | :--- | :--- | :--- |
| 📦 `clean_md5.bin` | Raw Binary | 16 Bytes | ~10.2 MB | ~668,000 Hashes |
| 📦 `clean_sha1.bin` | Raw Binary | 20 Bytes | ~12.7 MB | ~665,000 Hashes |
| 📦 `clean_sha256.bin` | Raw Binary | 32 Bytes | ~20.4 MB | ~668,000 Hashes |
| 📄 `clean_md5.txt` | ASCII Hex | 32 Chars + \n | ~22.0 MB | ~668,000 Hashes |
| 📄 `clean_sha1.txt` | ASCII Hex | 40 Chars + \n | ~27.0 MB | ~665,000 Hashes |
| 📄 `clean_sha256.txt` | ASCII Hex | 64 Chars + \n | ~43.0 MB | ~668,000 Hashes |

> *Feeds are completely refreshed and re-generated every 24 hours via automated pipelines.*

---

## 🚀 Integration Guide: How to Use the Feeds

Because the feeds are deployed as pure, un-padded binary structures, you don't need heavy JSON/CSV/SQL parsers. You can directly integrate them into your malware scanning engines, sandbox environments, or whitelist checkers.

### 1. DFIR Tools & Standard Software (Magnet AXIOM, FTK, SIEMs)
Simply download the `.txt` artifacts from the latest Release. These are standard, pre-cleaned, line-separated ASCII hex lists. You can ingest them directly into Magnet AXIOM, Autopsy, FTK, or any SIEM/Sandbox environment for instant whitelisting.

### 2. Integration in C/C++ (Zero-Copy Memory Mapping)
For custom engines, you can directly map the native `.bin` files into memory using `mmap` for instant, zero-allocation runtime space lookups:

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

### 2. Integration in Python (Struct Unpacking)
If you want to read or query the generated binary files using Python, you can unpack the CVT1 headers like this:
```
import struct

from pathlib import Path



def parse\_cvt1\_pack(bin\_path: str):

&#x20;   path = Path(bin\_path)

&#x20;   if not path.exists():

&#x20;       return \[]

&#x20;   data = path.read\_bytes()

&#x20;   header\_format = "<IIIQI"

&#x20;   header\_size = struct.calcsize(header\_format)

&#x20;   if len(data) < header\_size:

&#x20;       return \[]

&#x20;   magic, version, algo, timestamp, count = struct.unpack\_from(header\_format, data, 0)

&#x20;   algo\_sizes = {1: 16, 2: 20, 3: 32}

&#x20;   if algo not in algo\_sizes:

&#x20;       return \[]

&#x20;   hash\_size = algo\_sizes\[algo]

&#x20;   hashes = \[]

&#x20;   offset = header\_size

&#x20;   for \_ in range(count):

&#x20;       if offset + hash\_size > len(data):

&#x20;           break

&#x20;       hashes.append(data\[offset : offset + hash\_size].hex())

&#x20;       offset += hash\_size

&#x20;   return hashes
```

## 🛠️ Running the Infrastructure Locally
You can run the exact pipeline logic on your local machine without downloading the database to your hard drive.

### Prerequisites
pip install requests

### Run the Carver Stream & Compatibility Layer

# 1. Fetch latest NIST zip, extract hashes in-memory, and pack to CVT1 binaries
python tools/stream_http_hash_filter.py --latest-modern -o clean_packs

# 2. Export CVT1 binaries to DFIR-compatible plain-text lists
python tools/cvt1_to_text.py -i clean_packs -o clean_packs

Note: Memory allocations will safely hover around the default --ring-mb 512 value while processing 120+ GB over the network pipeline.

## 🛡️ Maintainer \& Author
Cemil Emre Bıyık - Computer Systems \& Low-Level Security Architecture Enthusiast.

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.



