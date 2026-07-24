#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace cvt {

inline bool read_varint(const uint8_t* data, std::size_t len, std::size_t& i,
                        std::uint64_t& val) {
  val = 0;
  for (int n = 0; n < 9; ++n) {
    if (i >= len) return false;
    const uint8_t b = data[i++];
    if (n < 8) {
      val = (val << 7) | (b & 0x7f);
      if ((b & 0x80) == 0) return true;
    } else {
      val = (val << 8) | b;
      return true;
    }
  }
  return false;
}

inline void serial_type_len(std::uint64_t serial, char& kind, std::size_t& ln) {
  if (serial == 0) {
    kind = 'n';
    ln = 0;
    return;
  }
  if (serial >= 1 && serial <= 4) {
    kind = 'i';
    ln = serial;
    return;
  }
  if (serial == 5) {
    kind = 'i';
    ln = 6;
    return;
  }
  if (serial == 6) {
    kind = 'i';
    ln = 8;
    return;
  }
  if (serial == 7) {
    kind = 'f';
    ln = 8;
    return;
  }
  if (serial == 8 || serial == 9) {
    kind = 'i';
    ln = 0;
    return;
  }
  if (serial >= 12 && (serial % 2) == 0) {
    kind = 'b';
    ln = static_cast<std::size_t>((serial - 12) / 2);
    return;
  }
  if (serial >= 13 && (serial % 2) == 1) {
    kind = 't';
    ln = static_cast<std::size_t>((serial - 13) / 2);
    return;
  }
  kind = 'r';
  ln = 0;
}

inline int hex_nibble(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

inline bool hex_to_raw(const uint8_t* hex, std::size_t hex_len, uint8_t* out) {
  if (hex_len % 2) return false;
  const std::size_t n = hex_len / 2;
  for (std::size_t i = 0; i < n; ++i) {
    const int hi = hex_nibble(hex[2 * i]);
    const int lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

inline bool looks_like_ascii_hex(const uint8_t* p, std::size_t n) {
  for (std::size_t i = 0; i < n; ++i) {
    const uint8_t c = p[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F')))
      return false;
  }
  return true;
}

// NSRL RDSv3 modern.db METADATA row fingerprint (verified against the live
// schema: metadata_id, object_id, key_hash, image_hash, path, path_b64,
// path_coding, file_name, file_name_b64, file_name_coding, extension,
// extension_b64, extension_coding, bytes, mtime, used_in_rds, update_date,
// recursion_level, extractee_id, crc32, md5, sha1, sha256 -- 23 columns,
// all four trailing hash columns declared NOT NULL). A record only counts
// as a file-hash row if its LAST FOUR serial types are exactly
// text(8)/text(32)/text(40)/text(64) in that order. This is a positional
// match, not a length-only match: it rejects key_hash/image_hash (which sit
// earlier in the same row and would otherwise coincidentally look like a
// hash) and rejects hash-looking substrings inside path/file_name (e.g.
// content-addressable cache filenames), since neither can ever land in
// this exact trailing slot. No other table in the schema ends in this
// four-column sequence, so this stays robust without needing the table
// name (which isn't recoverable from a bare leaf page anyway).
inline bool is_metadata_row_tail(const std::vector<std::uint64_t>& serials) {
  const std::size_t n = serials.size();
  if (n < 4) return false;
  char k0, k1, k2, k3;
  std::size_t l0, l1, l2, l3;
  serial_type_len(serials[n - 4], k0, l0);
  serial_type_len(serials[n - 3], k1, l1);
  serial_type_len(serials[n - 2], k2, l2);
  serial_type_len(serials[n - 1], k3, l3);
  return k0 == 't' && l0 == 8 &&   // crc32 (unused, but anchors the match)
         k1 == 't' && l1 == 32 &&  // md5
         k2 == 't' && l2 == 40 &&  // sha1
         k3 == 't' && l3 == 64;    // sha256
}

// Sink must provide: void offer_raw(const uint8_t*, std::size_t n);
template <typename Sink>
inline void carve_record_payload(const uint8_t* payload, std::size_t len,
                                 Sink& sink) {
  if (!payload || len == 0) return;
  std::size_t i = 0;
  std::uint64_t header_size = 0;
  if (!read_varint(payload, len, i, header_size)) return;
  if (header_size < 1 || header_size > len) return;
  const std::size_t header_end = static_cast<std::size_t>(header_size);
  std::vector<std::uint64_t> serials;
  serials.reserve(24);
  while (i < header_end) {
    std::uint64_t s = 0;
    if (!read_varint(payload, len, i, s)) return;
    serials.push_back(s);
  }
  if (!is_metadata_row_tail(serials)) return;

  const uint8_t* body = payload + header_end;
  const std::size_t body_len = len - header_end;
  const std::size_t n = serials.size();
  std::size_t off = 0;
  for (std::size_t idx = 0; idx < n; ++idx) {
    char kind = 'r';
    std::size_t ln = 0;
    serial_type_len(serials[idx], kind, ln);
    if (off + ln > body_len) return;  // overflow-truncated locally; don't guess
    if (idx >= n - 3) {  // md5, sha1, sha256 in order -- crc32 (n-4) unused
      const uint8_t* chunk = body + off;
      if (looks_like_ascii_hex(chunk, ln)) {
        uint8_t raw[32];
        if (hex_to_raw(chunk, ln, raw)) {
          sink.offer_raw(raw, ln / 2);
        }
      }
    }
    off += ln;
  }
}

template <typename Sink>
inline void carve_leaf_table_page(const uint8_t* page, std::size_t page_size,
                                  bool page1_hdr, Sink& sink) {
  const std::size_t base = page1_hdr ? 100 : 0;
  if (page_size <= base + 8) return;
  if (page[base] != 0x0d) return;
  const std::uint16_t ncells =
      (static_cast<std::uint16_t>(page[base + 3]) << 8) |
      static_cast<std::uint16_t>(page[base + 4]);
  if (ncells == 0 || ncells > 10000) return;
  const std::size_t ptr_base = base + 8;
  for (std::uint16_t c = 0; c < ncells; ++c) {
    const std::size_t poff = ptr_base + static_cast<std::size_t>(c) * 2;
    if (poff + 2 > page_size) return;
    const std::uint16_t cell_off =
        (static_cast<std::uint16_t>(page[poff]) << 8) |
        static_cast<std::uint16_t>(page[poff + 1]);
    if (cell_off >= page_size) continue;
    std::size_t j = cell_off;
    std::uint64_t payload_len = 0;
    std::uint64_t rowid = 0;
    if (!read_varint(page, page_size, j, payload_len)) continue;
    if (!read_varint(page, page_size, j, rowid)) continue;
    (void)rowid;
    if (j > page_size) continue;
    const std::size_t take =
        std::min(page_size - j, static_cast<std::size_t>(payload_len));
    carve_record_payload(page + j, take, sink);
  }
}

}  // namespace cvt
