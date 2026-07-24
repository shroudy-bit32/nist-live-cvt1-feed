#!/usr/bin/env python3
"""
Render the GitHub Release body for the CVT1 feed: a table of contents plus
one section per algorithm (MD5 / SHA-1 / SHA-256), separated by `---`, each
listing every actual uploaded asset for that algorithm with its size and a
one-line shell command to reconstruct the full file.

Ground truth only -- never assumes how many parts exist:
  - The asset list comes from `gh release view --json assets` against the
    real release, after every producing job has finished.
  - Each algorithm's true digest count comes from a 24-byte HTTP Range
    request against that algorithm's first .bin part's CVT1 header (no
    need to download gigabytes just to report a count).

Usage:
    python tools/render_release_notes.py --tag latest-feed --repo owner/name
"""

from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
import urllib.request
from typing import Dict, List, Optional, Tuple

HEADER_FMT = "<IIIQI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
CVT1_MAGIC = 0x31545643

ALGO_ORDER = ["md5", "sha1", "sha256"]
ALGO_LABEL = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
ALGO_DIGEST_SIZE = {"md5": 16, "sha1": 20, "sha256": 32}

NAME_RE = re.compile(r"^clean_(md5|sha1|sha256)(?:_part(\d+))?\.(bin|txt)$")


def gh_asset_list(tag: str) -> List[Tuple[str, int]]:
    """Returns [(name, size_bytes), ...] for every asset on the release."""
    out = subprocess.run(
        ["gh", "release", "view", tag, "--json", "assets"],
        check=True, capture_output=True, text=True,
    )
    import json

    data = json.loads(out.stdout)
    return [(a["name"], int(a.get("size") or 0)) for a in data.get("assets", [])]


def human_size(n: int) -> str:
    v = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if v < 1024 or unit == "GiB":
            return f"{v:.1f} {unit}" if unit != "B" else f"{int(v)} {unit}"
        v /= 1024
    return f"{v:.1f} GiB"


def read_remote_cvt1_count(url: str) -> Optional[int]:
    req = urllib.request.Request(
        url,
        headers={"Range": f"bytes=0-{HEADER_SIZE - 1}", "User-Agent": "release-notes-gen"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read(HEADER_SIZE)
    except Exception as exc:  # noqa: BLE001 -- a missing count is cosmetic, never fatal
        print(f"[!] could not read header from {url}: {exc}", file=sys.stderr)
        return None
    if len(data) < HEADER_SIZE:
        return None
    magic, _version, _algo, _ts, count = struct.unpack(HEADER_FMT, data)
    if magic != CVT1_MAGIC:
        return None
    return count


def classify(assets: List[Tuple[str, int]]) -> Dict[str, Dict]:
    """Buckets assets per algo into bin parts and txt parts, each sorted."""
    buckets: Dict[str, Dict] = {a: {"bin": [], "txt": []} for a in ALGO_ORDER}
    for name, size in assets:
        m = NAME_RE.match(name)
        if not m:
            continue
        algo, part, ext = m.group(1), m.group(2), m.group(3)
        entry = {"name": name, "size": size, "part": int(part) if part else 1}
        buckets[algo][ext].append(entry)
    for algo in buckets:
        buckets[algo]["bin"].sort(key=lambda e: e["name"])
        buckets[algo]["txt"].sort(key=lambda e: e["name"])
    return buckets


def render(repo: str, tag: str, buckets: Dict[str, Dict]) -> str:
    lines: List[str] = []
    lines.append("# NIST NSRL Modern -- Clean Hash Feed (CVT1)")
    lines.append("")
    lines.append(
        "Automated, zero-disk-footprint feed carved directly from the NIST NSRL "
        "RDSv3 *modern* SQLite database. Every asset below is exact-unique across "
        "the full dataset -- nothing sampled, nothing capped."
    )
    lines.append("")
    lines.append(
        "Files over GitHub's 2 GiB per-asset limit are split into numbered, "
        "uncompressed parts (`_partNN`) -- no `.gz`/`.zip`. Raw digest binaries "
        "don't benefit from compression (they're cryptographic hash output, "
        "effectively random bytes), and splitting alone already solves the size "
        "limit for both `.bin` and `.txt`, so there's nothing compression would add."
    )
    lines.append("")
    lines.append("## Contents")
    lines.append("")
    for algo in ALGO_ORDER:
        if buckets[algo]["bin"] or buckets[algo]["txt"]:
            lines.append(f"- [{ALGO_LABEL[algo]}](#{algo})")
    lines.append("")

    for algo in ALGO_ORDER:
        b = buckets[algo]
        if not b["bin"] and not b["txt"]:
            continue
        lines.append("---")
        lines.append("")
        lines.append(f'<a name="{algo}"></a>')
        lines.append(f"## {ALGO_LABEL[algo]}")
        lines.append("")

        count = None
        if b["bin"]:
            first = repo and f"https://github.com/{repo}/releases/download/{tag}/{b['bin'][0]['name']}"
            if first:
                count = read_remote_cvt1_count(first)
        if count is not None:
            lines.append(f"**{count:,} unique {ALGO_LABEL[algo]} digests.**")
            lines.append("")

        if b["bin"]:
            lines.append("**Binary (CVT1, `<IIIQI>` header + raw digests):**")
            lines.append("")
            lines.append("| File | Size |")
            lines.append("|---|---|")
            for e in b["bin"]:
                lines.append(f"| `{e['name']}` | {human_size(e['size'])} |")
            lines.append("")
            if len(b["bin"]) > 1:
                lines.append("Reconstruct the full file:")
                lines.append("```bash")
                lines.append(
                    f"cat clean_{algo}_part*.bin > clean_{algo}_full.bin"
                )
                lines.append("```")
            else:
                lines.append(
                    f"Single file, already complete -- no merge needed: `{b['bin'][0]['name']}`."
                )
            lines.append("")

        if b["txt"]:
            lines.append("**DFIR text list (one hex digest per line, Magnet AXIOM / FTK):**")
            lines.append("")
            lines.append("| File | Size |")
            lines.append("|---|---|")
            for e in b["txt"]:
                lines.append(f"| `{e['name']}` | {human_size(e['size'])} |")
            lines.append("")
            if len(b["txt"]) > 1:
                lines.append("Reconstruct the full text list:")
                lines.append("```bash")
                lines.append(f"cat clean_{algo}_part*.txt > clean_{algo}.txt")
                lines.append("```")
            else:
                lines.append(
                    f"Single file, already complete -- no merge needed: `{b['txt'][0]['name']}`."
                )
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_Regenerated automatically on every successful pipeline run. "
        "See the repository README for the full pipeline architecture._"
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--repo", required=True, help="owner/name, e.g. from ${{ github.repository }}")
    ap.add_argument("--out", default=None, help="write markdown here instead of publishing directly")
    args = ap.parse_args()

    assets = gh_asset_list(args.tag)
    if not assets:
        print(f"[!] release {args.tag} has no assets yet", file=sys.stderr)
        return 2

    buckets = classify(assets)
    body = render(args.repo, args.tag, buckets)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(body)
        print(f"[+] wrote {args.out}", file=sys.stderr)
    else:
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
            f.write(body)
            tmp_path = f.name
        subprocess.run(["gh", "release", "edit", args.tag, "--notes-file", tmp_path], check=True)
        print(f"[+] published release notes to {args.tag}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
