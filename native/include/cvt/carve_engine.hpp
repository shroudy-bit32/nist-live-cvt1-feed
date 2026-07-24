#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "cvt/shard_sink.hpp"
#include "cvt/sqlite_carve.hpp"

namespace cvt {

inline constexpr std::uint32_t CVT1_MAGIC = 0x31545643u;
inline constexpr std::uint32_t CVT1_VERSION = 1;
inline constexpr std::uint32_t ALGO_MD5 = 1;
inline constexpr std::uint32_t ALGO_SHA1 = 2;
inline constexpr std::uint32_t ALGO_SHA256 = 3;

inline constexpr std::size_t kDefaultArenaBytes = 256ull * 1024ull * 1024ull;
inline constexpr std::size_t kDefaultBucketCap = 50000;
// Scatter-gather checkpoint threshold: once this many resident bytes have
// piled up across the 768 shard files, compact them into a part_NNN.bin
// triple and empty the shards, instead of waiting for the whole run to
// finish. Keeps local disk footprint bounded regardless of total DB size.
inline constexpr std::uint64_t kDefaultCheckpointBytes =
    1536ull * 1024ull * 1024ull;

struct ThreadOffer {
  ShardSink* sink;
  ShardSink::ThreadBuckets* buckets;
  void offer_raw(const uint8_t* p, std::size_t n) {
    sink->offer_raw(*buckets, p, n);
  }
};

class CarveEngine {
public:
  CarveEngine(std::string spool_dir, std::size_t arena_bytes, unsigned workers,
              std::size_t bucket_cap, std::string parts_dir = std::string(),
              std::uint64_t checkpoint_bytes = kDefaultCheckpointBytes)
      : spool_dir_(std::move(spool_dir)),
        arena_bytes_(arena_bytes < (8ull * 1024ull * 1024ull)
                         ? (8ull * 1024ull * 1024ull)
                         : arena_bytes),
        workers_(workers == 0 ? std::max(1u, std::thread::hardware_concurrency())
                              : workers),
        sink_(spool_dir_, bucket_cap == 0 ? kDefaultBucketCap : bucket_cap),
        parts_dir_(std::move(parts_dir)),
        checkpoint_bytes_(checkpoint_bytes == 0 ? kDefaultCheckpointBytes
                                                : checkpoint_bytes) {
    arenas_[0].assign(arena_bytes_, 0);
    arenas_[1].assign(arena_bytes_, 0);
  }

  ~CarveEngine() {
    if (carve_thread_.joinable()) {
      try {
        carve_thread_.join();
      } catch (...) {
      }
    }
  }

  unsigned worker_count() const { return workers_; }
  std::size_t arena_bytes() const { return arena_bytes_; }
  std::size_t bucket_cap() const { return sink_.bucket_cap(); }
  std::uintptr_t arena_ptr(int idx) const {
    return reinterpret_cast<std::uintptr_t>(arenas_[idx & 1].data());
  }
  bool chunked() const { return !parts_dir_.empty(); }
  std::uint64_t checkpoint_bytes() const { return checkpoint_bytes_; }
  std::uint64_t parts_written() const { return part_seq_; }

  void write(const uint8_t* data, std::size_t n) {
    std::size_t off = 0;
    while (off < n) {
      if (error_) throw std::runtime_error(*error_);
      {
        std::unique_lock<std::mutex> lock(mu_);
        not_full_.wait(lock, [&] {
          return !carving_[fill_idx_] || error_.has_value();
        });
        if (error_) throw std::runtime_error(*error_);
      }
      const std::size_t space = arena_bytes_ - fill_used_;
      const std::size_t take = std::min(n - off, space);
      std::memcpy(arenas_[fill_idx_].data() + fill_used_, data + off, take);
      fill_used_ += take;
      off += take;
      if (fill_used_ == arena_bytes_) {
        submit_fill_arena_(false);
      }
    }
  }

  void close_writer() {
    if (error_) throw std::runtime_error(*error_);
    submit_fill_arena_(true);
    std::unique_lock<std::mutex> lock(mu_);
    not_full_.wait(lock, [&] { return !carving_[0] && !carving_[1]; });
    if (carve_thread_.joinable()) {
      lock.unlock();
      carve_thread_.join();
      lock.lock();
    }
    if (error_) throw std::runtime_error(*error_);
    writer_closed_ = true;
  }

  void fail(const std::string& msg) {
    {
      std::lock_guard<std::mutex> lock(mu_);
      error_ = msg;
    }
    not_full_.notify_all();
  }

  std::map<std::string, std::uint64_t> write_packs(const std::string& out_dir,
                                                   std::uint64_t updated_unix) {
    if (!writer_closed_) {
      throw std::runtime_error("close_writer() must be called before write_packs()");
    }
    const auto md5_n =
        finalize_algo<16>(out_dir + "/clean_md5.bin", ALGO_MD5, updated_unix);
    const auto sha1_n =
        finalize_algo<20>(out_dir + "/clean_sha1.bin", ALGO_SHA1, updated_unix);
    const auto sha256_n = finalize_algo<32>(out_dir + "/clean_sha256.bin",
                                            ALGO_SHA256, updated_unix);
    std::fprintf(stderr,
                 "    [cvt_carve] packs md5=%llu sha1=%llu sha256=%llu "
                 "offered=%llu window_flushed=%llu pages=%llu\n",
                 static_cast<unsigned long long>(md5_n),
                 static_cast<unsigned long long>(sha1_n),
                 static_cast<unsigned long long>(sha256_n),
                 static_cast<unsigned long long>(sink_.offered()),
                 static_cast<unsigned long long>(sink_.flushed_records()),
                 static_cast<unsigned long long>(pages_.load()));
    return {{"clean_md5.bin", md5_n},
            {"clean_sha1.bin", sha1_n},
            {"clean_sha256.bin", sha256_n},
            {"offered", sink_.offered()},
            {"pages", pages_.load()}};
  }

  // Scatter-gather finish: instead of one final read-everything merge into
  // clean_*.bin (write_packs), flush whatever's still resident as one last
  // part_NNNNN_*.bin -- symmetric with the periodic checkpoints taken during
  // the run. A separate, later job downloads every part and does the true
  // cross-part exact-unique merge (k-way merge over already-sorted runs, not
  // an in-memory set) to produce the final clean_*.bin release files.
  std::map<std::string, std::uint64_t> finalize_chunked() {
    if (!writer_closed_) {
      throw std::runtime_error("close_writer() must be called before finalize_chunked()");
    }
    if (parts_dir_.empty()) {
      throw std::runtime_error("finalize_chunked() requires a non-empty parts_dir");
    }
    return do_checkpoint_();
  }

private:
  // Reads+sorts+uniques+deletes all 768 shard files and writes one
  // part_NNNNN_{md5,sha1,sha256}.bin triple. Called both periodically (from
  // carve_arena_, once resident_bytes crosses checkpoint_bytes_) and once
  // more at the very end via finalize_chunked(). Each part is independently
  // exact-unique (no duplicates within itself) but not deduped against other
  // parts -- that happens in the separate merge step.
  std::map<std::string, std::uint64_t> do_checkpoint_() {
    const std::uint64_t seq = part_seq_++;
    const std::uint64_t ts = static_cast<std::uint64_t>(std::time(nullptr));
    char seqbuf[16];
    std::snprintf(seqbuf, sizeof(seqbuf), "%05llu",
                  static_cast<unsigned long long>(seq));
    const std::string prefix = parts_dir_ + "/part_" + seqbuf + "_";
    std::map<std::string, std::uint64_t> counts;
    counts["md5"] = finalize_algo<16>(prefix + "md5.bin", ALGO_MD5, ts);
    counts["sha1"] = finalize_algo<20>(prefix + "sha1.bin", ALGO_SHA1, ts);
    counts["sha256"] = finalize_algo<32>(prefix + "sha256.bin", ALGO_SHA256, ts);
    sink_.reset_resident_bytes();
    std::fprintf(stderr,
                 "    [cvt_carve] checkpoint #%llu -> %smd5/sha1/sha256.bin "
                 "(md5=%llu sha1=%llu sha256=%llu) resident cleared\n",
                 static_cast<unsigned long long>(seq), prefix.c_str(),
                 static_cast<unsigned long long>(counts["md5"]),
                 static_cast<unsigned long long>(counts["sha1"]),
                 static_cast<unsigned long long>(counts["sha256"]));
    return counts;
  }

  // Invoked after each arena's carve completes; only the single dedicated
  // carve_thread_ ever calls this (arenas are never carved concurrently with
  // each other -- see submit_fill_arena_), so no extra locking is needed
  // around the shard-file read/truncate/delete sequence in finalize_algo.
  void maybe_checkpoint_() {
    if (parts_dir_.empty()) return;
    if (sink_.resident_bytes() < checkpoint_bytes_) return;
    do_checkpoint_();
  }

  void submit_fill_arena_(bool eof) {
    const int idx = fill_idx_;
    const std::size_t used = fill_used_;
    {
      std::unique_lock<std::mutex> lock(mu_);
      not_full_.wait(lock, [&] { return !carving_[idx] || error_.has_value(); });
      if (error_) throw std::runtime_error(*error_);
      carving_[idx] = true;
    }

    // Wait previous carve to free the worker slot; ping-pong overlap happens
    // while THIS arena was being filled (previous idx was carving).
    if (carve_thread_.joinable()) {
      carve_thread_.join();
      if (error_) throw std::runtime_error(*error_);
    }

    carve_thread_ = std::thread([this, idx, used, eof] {
      try {
        carve_arena_(arenas_[idx].data(), used, eof);
      } catch (const std::exception& ex) {
        fail(ex.what());
      } catch (...) {
        fail("unknown carve error");
      }
      {
        std::lock_guard<std::mutex> lock(mu_);
        carving_[idx] = false;
      }
      not_full_.notify_all();
    });

    fill_idx_ = 1 - fill_idx_;
    fill_used_ = 0;

    if (eof && carve_thread_.joinable()) {
      carve_thread_.join();
      if (error_) throw std::runtime_error(*error_);
    }
  }

  void carve_arena_(const uint8_t* data, std::size_t len, bool eof) {
    std::vector<uint8_t> buf;
    const uint8_t* view = data;
    std::size_t view_len = len;
    if (!prefix_.empty()) {
      buf.resize(prefix_.size() + len);
      std::memcpy(buf.data(), prefix_.data(), prefix_.size());
      if (len) std::memcpy(buf.data() + prefix_.size(), data, len);
      prefix_.clear();
      view = buf.data();
      view_len = buf.size();
    }
    if (view_len == 0) {
      if (eof && !header_ok_) {
        throw std::runtime_error("empty DB stream");
      }
      return;
    }

    if (!header_ok_) {
      if (view_len < 100) {
        if (eof) throw std::runtime_error("truncated SQLite header");
        prefix_.assign(view, view + view_len);
        return;
      }
      if (std::memcmp(view, "SQLite format 3\0", 16) != 0) {
        throw std::runtime_error("not a SQLite 3 database header");
      }
      std::uint32_t ps =
          (static_cast<std::uint32_t>(view[16]) << 8) | view[17];
      if (ps == 1) ps = 65536;  // SQLite's encoding for the 64 KiB page size
      if (ps < 512 || ps > 65536 || (ps & (ps - 1)) != 0) {
        throw std::runtime_error("invalid SQLite page_size");
      }
      page_size_ = ps;
      header_ok_ = true;
      std::fprintf(stderr,
                   "    [cvt_carve] ping-pong arena=%zuMiB x2 workers=%u "
                   "bucket_cap=%zu page_size=%u (full scan, no caps)\n",
                   arena_bytes_ / (1024 * 1024), workers_, sink_.bucket_cap(),
                   static_cast<unsigned>(page_size_));
    }

    std::size_t offset = 0;
    std::vector<std::pair<const uint8_t*, bool>> pages;
    pages.reserve(view_len / page_size_ + 1);
    while (offset + page_size_ <= view_len) {
      const bool page1 = (db_offset_ == 0 && offset == 0);
      pages.emplace_back(view + offset, page1);
      offset += page_size_;
      db_offset_ += page_size_;
    }
    if (offset < view_len) {
      if (!eof) {
        prefix_.assign(view + offset, view + view_len);
      }
    }
    if (pages.empty()) return;

    const unsigned nthreads = std::min<unsigned>(
        workers_, std::max<unsigned>(1, static_cast<unsigned>(pages.size())));
    std::vector<std::thread> pool;
    pool.reserve(nthreads);
    std::atomic<std::size_t> next{0};
    for (unsigned t = 0; t < nthreads; ++t) {
      pool.emplace_back([&] {
        auto buckets = sink_.make_buckets();
        ThreadOffer offer{&sink_, &buckets};
        for (;;) {
          const std::size_t i = next.fetch_add(1);
          if (i >= pages.size()) break;
          carve_leaf_table_page(pages[i].first, page_size_, pages[i].second,
                                offer);
          ++pages_;
        }
        sink_.flush_all(buckets);
      });
    }
    for (auto& th : pool) th.join();

    const auto p = pages_.load();
    if (p - last_report_ >= 50000) {
      last_report_ = p;
      std::fprintf(stderr,
                   "    [cvt_carve] pages=%llu offered=%llu flushed=%llu "
                   "db_MiB=%.1f\n",
                   static_cast<unsigned long long>(p),
                   static_cast<unsigned long long>(sink_.offered()),
                   static_cast<unsigned long long>(sink_.flushed_records()),
                   db_offset_ / (1024.0 * 1024.0));
    }

    // No other carve is ever in flight concurrently with this one (see
    // submit_fill_arena_), so it's safe to compact+empty the shard files here.
    maybe_checkpoint_();
  }

  // Shard-by-shard exact unique → CVT1. Peak RAM ≈ one shard, not full set.
  // Shards partition by first byte ⇒ disjoint key spaces.
  template <std::size_t N>
  std::uint64_t finalize_algo(const std::string& out_path, std::uint32_t algo,
                              std::uint64_t updated_unix) {
    const std::string tmp = out_path + ".payload.tmp";
    std::ofstream payload(tmp, std::ios::binary | std::ios::trunc);
    if (!payload) throw std::runtime_error("cannot write " + tmp);

    std::uint64_t count = 0;
    for (std::size_t s = 0; s < kShards; ++s) {
      const std::string& path = (N == 16)   ? sink_.md5_path(s)
                               : (N == 20) ? sink_.sha1_path(s)
                                           : sink_.sha256_path(s);
      std::ifstream in(path, std::ios::binary);
      if (!in) continue;
      in.seekg(0, std::ios::end);
      const auto sz = static_cast<std::int64_t>(in.tellg());
      in.seekg(0, std::ios::beg);
      if (sz <= 0) {
        in.close();
        std::remove(path.c_str());
        continue;
      }
      if (static_cast<std::size_t>(sz) % N) {
        throw std::runtime_error("corrupt shard size " + path);
      }
      std::vector<std::array<uint8_t, N>> part(
          static_cast<std::size_t>(sz) / N);
      in.read(reinterpret_cast<char*>(part.data()),
              static_cast<std::streamsize>(sz));
      in.close();
      std::sort(part.begin(), part.end());
      part.erase(std::unique(part.begin(), part.end()), part.end());
      for (const auto& k : part) {
        payload.write(reinterpret_cast<const char*>(k.data()),
                      static_cast<std::streamsize>(N));
      }
      count += static_cast<std::uint64_t>(part.size());
      std::remove(path.c_str());
    }
    payload.close();

    // Write under a .tmp name and rename into place at the end so a
    // concurrently-polling uploader (the Python part watcher, in chunked
    // mode) never observes a partially-written part file.
    const std::string out_tmp = out_path + ".tmp";
    std::ofstream out(out_tmp, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot write " + out_tmp);
    auto put_u32 = [&](std::uint32_t v) {
      const uint8_t b[4] = {static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8),
                            static_cast<uint8_t>(v >> 16),
                            static_cast<uint8_t>(v >> 24)};
      out.write(reinterpret_cast<const char*>(b), 4);
    };
    auto put_u64 = [&](std::uint64_t v) {
      uint8_t b[8];
      for (int i = 0; i < 8; ++i) b[i] = static_cast<uint8_t>(v >> (8 * i));
      out.write(reinterpret_cast<const char*>(b), 8);
    };
    put_u32(CVT1_MAGIC);
    put_u32(CVT1_VERSION);
    put_u32(algo);
    put_u64(updated_unix);
    if (count > 0xffffffffull) {
      throw std::runtime_error("digest count exceeds uint32 CVT1 field");
    }
    put_u32(static_cast<std::uint32_t>(count));

    std::ifstream in_payload(tmp, std::ios::binary);
    if (!in_payload) throw std::runtime_error("missing payload tmp");
    std::vector<char> buf(1 << 20);
    while (in_payload) {
      in_payload.read(buf.data(), static_cast<std::streamsize>(buf.size()));
      const auto g = in_payload.gcount();
      if (g > 0) out.write(buf.data(), g);
    }
    in_payload.close();
    std::remove(tmp.c_str());
    out.close();
    if (std::rename(out_tmp.c_str(), out_path.c_str()) != 0) {
      throw std::runtime_error("cannot rename " + out_tmp + " -> " + out_path);
    }
    return count;
  }

  std::string spool_dir_;
  std::size_t arena_bytes_;
  unsigned workers_;
  ShardSink sink_;
  std::string parts_dir_;
  std::uint64_t checkpoint_bytes_;
  std::uint64_t part_seq_ = 0;

  std::array<std::vector<uint8_t>, 2> arenas_{};
  int fill_idx_ = 0;
  std::size_t fill_used_ = 0;
  bool carving_[2] = {false, false};
  std::mutex mu_;
  std::condition_variable not_full_;
  std::thread carve_thread_;
  std::optional<std::string> error_;
  bool writer_closed_ = false;

  bool header_ok_ = false;
  std::uint32_t page_size_ = 0;
  std::vector<uint8_t> prefix_;
  std::uint64_t db_offset_ = 0;
  std::atomic<std::uint64_t> pages_{0};
  std::uint64_t last_report_ = 0;
};

}  // namespace cvt
