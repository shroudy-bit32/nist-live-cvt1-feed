#!/usr/bin/env python3
"""
Network speed probe: measure real sustained throughput from this runner to
the actual NIST modern.zip host, then project whether a full download fits
inside a fixed job time budget (GitHub-hosted runners hard-cap a job at 6h)
-- BEFORE spending hours finding out the hard way.

This is not a simulation: it resolves the same URL the real carve job uses
(discover_latest_rds_modern_zip), HEADs the real Content-Length, and streams
real bytes for --duration seconds (discarding them -- only throughput
matters here). It reuses HttpByteStream's Range-resume-on-drop logic so one
transient blip during the sample doesn't understate the number.

Why a probe instead of just trusting the math: the "does 132 GiB fit in 6h"
question depends entirely on this runner's actual egress bandwidth to S3,
which varies by GitHub Actions fleet/region/day and isn't published anywhere
-- the only way to know is to actually measure it, on the actual runner,
against the actual host, right before the actual job would run.

Exit code is always 0 on a successful measurement (a slow network is a
result, not a probe failure) -- the go/no-go decision is exposed via
GITHUB_OUTPUT (will_fit=true/false) for the workflow's `if:` gate to act on,
plus a GITHUB_STEP_SUMMARY report for a human to read.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stream_http_hash_filter import (  # noqa: E402  (reuse the tested retry/resume stream)
    HTTP_USER_AGENT,
    HttpByteStream,
    discover_latest_rds_modern_zip,
)

DEFAULT_DURATION_S = 120.0
DEFAULT_SAMPLE_CHUNK = 1024 * 1024

# Fixed, NON-network cost per run: apt-get/pip installs + compiling the
# pybind11 module + the final arena's trailing carve/checkpoint after the
# download completes. Doesn't scale with file size, so it's a flat minute
# count, not a rate. Deliberately generous (measured builds are usually
# faster than this) since underestimating overhead is the dangerous
# direction here.
DEFAULT_FIXED_OVERHEAD_MINUTES = 20.0

# A 1-2 minute sample is a point estimate, not a 6-hour average -- shared
# runner network noise, S3-side throttling, or just bad luck can all make a
# short sample optimistic. Only trust a fraction of the measured rate when
# projecting the full multi-hour transfer.
DEFAULT_SAFETY_MARGIN = 0.80

DEFAULT_BUDGET_MINUTES = 360.0  # GitHub-hosted runner hard ceiling


def head_content_length(url: str, timeout: int = 30) -> int:
    req = Request(url, method="HEAD", headers={"User-Agent": HTTP_USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        length = resp.headers.get("Content-Length")
        if length is None:
            raise RuntimeError(f"{url}: response has no Content-Length header")
        return int(length)


def measure_throughput(url: str, duration_s: float, chunk_size: int) -> dict:
    start = time.monotonic()
    total = 0
    with HttpByteStream(url, chunk_size=chunk_size, timeout=60) as stream:
        while True:
            if time.monotonic() - start >= duration_s:
                break
            block = stream.read(chunk_size)
            if not block:
                break  # object smaller than duration_s worth of data (not this file)
            total += len(block)
    elapsed = time.monotonic() - start
    mib_s = (total / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0
    return {"bytes": total, "elapsed_s": elapsed, "mib_s": mib_s}


def write_github_output(path: str, values: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        for k, v in values.items():
            f.write(f"{k}={v}\n")


def write_github_summary(path: str, report: dict, url: str, duration_s: float) -> None:
    verdict = (
        "✅ projected to finish comfortably within budget"
        if report["will_fit"]
        else "❌ projected NOT to finish within budget at this measured speed"
    )
    lines = [
        "## Network speed probe\n",
        f"- Target: `{url}`\n",
        f"- Total object size: **{report['total_gib']} GiB**\n",
        f"- Measured throughput ({duration_s:.0f}s sample): **{report['measured_mib_s']} MiB/s**\n",
        f"- After {int(report['safety_margin'] * 100)}% safety margin: "
        f"{report['reliable_mib_s']} MiB/s\n",
        f"- Projected download time: {report['projected_download_minutes']} min\n",
        f"- Fixed overhead (install/build/final checkpoint): "
        f"{report['fixed_overhead_minutes']} min\n",
        f"- **Projected total: {report['projected_total_minutes']} min** "
        f"(budget: {report['budget_minutes']} min)\n",
        f"- Verdict: {verdict}\n",
    ]
    with open(path, "a", encoding="utf-8") as f:
        f.writelines(lines)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--url", default=None, help="explicit zip URL (default: auto-discover latest modern.zip)"
    )
    ap.add_argument("--duration", type=float, default=DEFAULT_DURATION_S, help="measurement window, seconds")
    ap.add_argument("--chunk-size", type=int, default=DEFAULT_SAMPLE_CHUNK)
    ap.add_argument("--fixed-overhead-min", type=float, default=DEFAULT_FIXED_OVERHEAD_MINUTES)
    ap.add_argument("--safety-margin", type=float, default=DEFAULT_SAFETY_MARGIN)
    ap.add_argument("--budget-min", type=float, default=DEFAULT_BUDGET_MINUTES)
    ap.add_argument(
        "--github-output",
        default=os.environ.get("GITHUB_OUTPUT"),
        help="path to $GITHUB_OUTPUT (auto-detected from env inside Actions)",
    )
    ap.add_argument(
        "--github-summary",
        default=os.environ.get("GITHUB_STEP_SUMMARY"),
        help="path to $GITHUB_STEP_SUMMARY (auto-detected from env inside Actions)",
    )
    args = ap.parse_args()

    url = args.url or discover_latest_rds_modern_zip()
    print(f"[*] probing {url}", file=sys.stderr)

    total_bytes = head_content_length(url)
    print(
        f"[*] full object size: {total_bytes} bytes ({total_bytes / 1024**3:.2f} GiB)",
        file=sys.stderr,
    )

    print(f"[*] measuring sustained throughput for {args.duration:.0f}s ...", file=sys.stderr)
    sample = measure_throughput(url, args.duration, args.chunk_size)
    print(
        f"[*] measured: {sample['bytes'] / 1024**2:.1f} MiB in {sample['elapsed_s']:.1f}s "
        f"= {sample['mib_s']:.2f} MiB/s",
        file=sys.stderr,
    )

    reliable_mib_s = sample["mib_s"] * args.safety_margin
    download_minutes = (
        (total_bytes / 1024**2) / reliable_mib_s / 60 if reliable_mib_s > 0 else float("inf")
    )
    projected_total_minutes = download_minutes + args.fixed_overhead_min
    will_fit = projected_total_minutes <= args.budget_min

    report = {
        "total_gib": round(total_bytes / 1024**3, 2),
        "measured_mib_s": round(sample["mib_s"], 2),
        "safety_margin": args.safety_margin,
        "reliable_mib_s": round(reliable_mib_s, 2),
        "projected_download_minutes": round(download_minutes, 1)
        if download_minutes != float("inf")
        else "inf",
        "fixed_overhead_minutes": args.fixed_overhead_min,
        "projected_total_minutes": round(projected_total_minutes, 1)
        if projected_total_minutes != float("inf")
        else "inf",
        "budget_minutes": args.budget_min,
        "will_fit": will_fit,
    }
    print(json.dumps({"url": url, **report}, indent=2), file=sys.stderr)

    if args.github_output:
        write_github_output(
            args.github_output,
            {
                "will_fit": "true" if will_fit else "false",
                "measured_mib_s": report["measured_mib_s"],
                "projected_total_minutes": report["projected_total_minutes"],
                "total_gib": report["total_gib"],
                "zip_url": url,
            },
        )
    if args.github_summary:
        write_github_summary(args.github_summary, report, url, args.duration)

    print("WILL_FIT" if will_fit else "WONT_FIT", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
