#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <thread>

#include "cvt/carve_engine.hpp"

namespace py = pybind11;

PYBIND11_MODULE(cvt_carve, m) {
  m.doc() =
      "Native NSRL carver: ping-pong arenas, TLS shard buckets, disk unique";

  m.def(
      "hardware_concurrency",
      []() {
        const unsigned n = std::thread::hardware_concurrency();
        return n == 0 ? 1u : n;
      },
      "CPU cores available to this process");

  py::class_<cvt::CarveEngine>(m, "CarveEngine")
      .def(py::init<std::string, std::size_t, unsigned, std::size_t,
                     std::string, std::uint64_t>(),
           py::arg("spool_dir"),
           py::arg("arena_bytes") = cvt::kDefaultArenaBytes,
           py::arg("workers") = 0,
           py::arg("bucket_cap") = cvt::kDefaultBucketCap,
           py::arg("parts_dir") = std::string(),
           py::arg("checkpoint_bytes") = cvt::kDefaultCheckpointBytes,
           "workers=0 → hardware_concurrency(); ping-pong arena pair. "
           "parts_dir!='' enables scatter-gather chunking: once "
           "checkpoint_bytes accumulate on disk, shards are compacted into "
           "a part_NNNNN_{md5,sha1,sha256}.bin triple and emptied.")
      .def_property_readonly("worker_count", &cvt::CarveEngine::worker_count)
      .def_property_readonly("arena_bytes", &cvt::CarveEngine::arena_bytes)
      .def_property_readonly("bucket_cap", &cvt::CarveEngine::bucket_cap)
      .def_property_readonly("chunked", &cvt::CarveEngine::chunked)
      .def_property_readonly("checkpoint_bytes",
                             &cvt::CarveEngine::checkpoint_bytes)
      .def_property_readonly("parts_written", &cvt::CarveEngine::parts_written)
      .def("arena_ptr", &cvt::CarveEngine::arena_ptr, py::arg("idx"),
           "uint8_t* address of ping-pong arena 0 or 1")
      .def(
          "write",
          [](cvt::CarveEngine& self, py::buffer buf) {
            py::buffer_info info = buf.request();
            if (info.ndim != 1) {
              throw std::runtime_error("write() expects a 1-D buffer");
            }
            const auto* ptr = static_cast<const uint8_t*>(info.ptr);
            const auto n = static_cast<std::size_t>(info.size * info.itemsize);
            py::gil_scoped_release release;
            self.write(ptr, n);
          },
          py::arg("data"))
      .def(
          "close_writer",
          [](cvt::CarveEngine& self) {
            py::gil_scoped_release release;
            self.close_writer();
          })
      .def("fail", &cvt::CarveEngine::fail, py::arg("message"))
      .def(
          "write_packs",
          [](cvt::CarveEngine& self, const std::string& out_dir,
             std::uint64_t updated_unix) {
            py::gil_scoped_release release;
            return self.write_packs(out_dir, updated_unix);
          },
          py::arg("out_dir"), py::arg("updated_unix") = 0,
          "Non-chunked mode only: single final merge -> clean_*.bin")
      .def(
          "finalize_chunked",
          [](cvt::CarveEngine& self) {
            py::gil_scoped_release release;
            return self.finalize_chunked();
          },
          "Chunked mode only: flush whatever's left as one last part_*.bin "
          "triple. Call after close_writer(); a separate job merges all "
          "parts into the final clean_*.bin release files.");
}
