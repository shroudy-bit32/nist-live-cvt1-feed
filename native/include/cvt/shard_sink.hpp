#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace cvt {

inline constexpr std::size_t kShards = 256;

// Per-thread lock-free L1 buckets; flush to disk shards under short per-file lock.
class ShardSink {
public:
  ShardSink(std::string spool_dir, std::size_t bucket_cap)
      : spool_dir_(std::move(spool_dir)), bucket_cap_(bucket_cap) {
    for (std::size_t i = 0; i < kShards; ++i) {
      md5_path_[i] = spool_dir_ + "/md5_" + hex2(i) + ".raw";
      sha1_path_[i] = spool_dir_ + "/sha1_" + hex2(i) + ".raw";
      sha256_path_[i] = spool_dir_ + "/sha256_" + hex2(i) + ".raw";
    }
  }

  std::size_t bucket_cap() const { return bucket_cap_; }

  struct ThreadBuckets {
    std::array<std::vector<std::array<uint8_t, 16>>, kShards> md5{};
    std::array<std::vector<std::array<uint8_t, 20>>, kShards> sha1{};
    std::array<std::vector<std::array<uint8_t, 32>>, kShards> sha256{};
  };

  ThreadBuckets make_buckets() const {
    ThreadBuckets b;
    for (std::size_t i = 0; i < kShards; ++i) {
      b.md5[i].reserve(std::min<std::size_t>(bucket_cap_, 4096));
      b.sha1[i].reserve(std::min<std::size_t>(bucket_cap_, 4096));
      b.sha256[i].reserve(std::min<std::size_t>(bucket_cap_, 4096));
    }
    return b;
  }

  void offer_raw(ThreadBuckets& tb, const uint8_t* p, std::size_t n) {
    ++offered_;
    if (n == 16) {
      const std::size_t s = p[0];
      std::array<uint8_t, 16> key{};
      std::memcpy(key.data(), p, 16);
      auto& v = tb.md5[s];
      v.push_back(key);
      if (v.size() >= bucket_cap_) flush_md5(s, v);
    } else if (n == 20) {
      const std::size_t s = p[0];
      std::array<uint8_t, 20> key{};
      std::memcpy(key.data(), p, 20);
      auto& v = tb.sha1[s];
      v.push_back(key);
      if (v.size() >= bucket_cap_) flush_sha1(s, v);
    } else if (n == 32) {
      const std::size_t s = p[0];
      std::array<uint8_t, 32> key{};
      std::memcpy(key.data(), p, 32);
      auto& v = tb.sha256[s];
      v.push_back(key);
      if (v.size() >= bucket_cap_) flush_sha256(s, v);
    }
  }

  void flush_all(ThreadBuckets& tb) {
    for (std::size_t s = 0; s < kShards; ++s) {
      if (!tb.md5[s].empty()) flush_md5(s, tb.md5[s]);
      if (!tb.sha1[s].empty()) flush_sha1(s, tb.sha1[s]);
      if (!tb.sha256[s].empty()) flush_sha256(s, tb.sha256[s]);
    }
  }

  std::uint64_t offered() const { return offered_.load(); }
  std::uint64_t flushed_records() const { return flushed_records_.load(); }

  // Bytes currently resident across all 768 shard files on disk (i.e. written
  // since the last checkpoint compaction). Drives CarveEngine's periodic
  // "flush a part_NNN.bin and empty the shards" decision so intermediate
  // disk usage never has to approach the full offered volume.
  std::uint64_t resident_bytes() const { return resident_bytes_.load(); }
  void reset_resident_bytes() { resident_bytes_.store(0); }

  const std::string& md5_path(std::size_t s) const { return md5_path_[s]; }
  const std::string& sha1_path(std::size_t s) const { return sha1_path_[s]; }
  const std::string& sha256_path(std::size_t s) const { return sha256_path_[s]; }

private:
  static std::string hex2(std::size_t v) {
    static const char* d = "0123456789abcdef";
    std::string s(2, '0');
    s[0] = d[(v >> 4) & 0xf];
    s[1] = d[v & 0xf];
    return s;
  }

  template <std::size_t N>
  void flush_sorted_unique(std::vector<std::array<uint8_t, N>>& v,
                           const std::string& path, std::mutex& mu) {
    if (v.empty()) return;
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    {
      std::lock_guard<std::mutex> lock(mu);
      std::ofstream out(path, std::ios::binary | std::ios::app);
      if (!out) throw std::runtime_error("cannot append shard " + path);
      for (const auto& k : v) {
        out.write(reinterpret_cast<const char*>(k.data()),
                  static_cast<std::streamsize>(N));
      }
    }
    flushed_records_ += static_cast<std::uint64_t>(v.size());
    resident_bytes_ += static_cast<std::uint64_t>(v.size()) * N;
    v.clear();
  }

  void flush_md5(std::size_t s, std::vector<std::array<uint8_t, 16>>& v) {
    flush_sorted_unique<16>(v, md5_path_[s], md5_mu_[s]);
  }
  void flush_sha1(std::size_t s, std::vector<std::array<uint8_t, 20>>& v) {
    flush_sorted_unique<20>(v, sha1_path_[s], sha1_mu_[s]);
  }
  void flush_sha256(std::size_t s, std::vector<std::array<uint8_t, 32>>& v) {
    flush_sorted_unique<32>(v, sha256_path_[s], sha256_mu_[s]);
  }

  std::string spool_dir_;
  std::size_t bucket_cap_;
  std::array<std::string, kShards> md5_path_{};
  std::array<std::string, kShards> sha1_path_{};
  std::array<std::string, kShards> sha256_path_{};
  std::array<std::mutex, kShards> md5_mu_{};
  std::array<std::mutex, kShards> sha1_mu_{};
  std::array<std::mutex, kShards> sha256_mu_{};
  std::atomic<std::uint64_t> offered_{0};
  std::atomic<std::uint64_t> flushed_records_{0};
  std::atomic<std::uint64_t> resident_bytes_{0};
};

}  // namespace cvt
