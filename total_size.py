"""Calculate total disk space needed to download all videos.

Importable function:
    summarize_sizes(sizes) - return dict with total, smallest, largest, average, failed
"""

import argparse
import time
from typing import Any, TypedDict

from check_clashes import (
    fmt_size,
    fetch_sizes,
    load_video_map,
    save_video_map,
    build_url_referers,
    VIDEO_MAP_FILE,
)
from config import SITES, SIZE_CACHE_TTL


class SizeStats(TypedDict):
    sized: int
    total: int
    total_bytes: int
    smallest: int
    largest: int
    average: int
    failed: list[str]


def summarize_sizes(sizes: dict[str, int | None]) -> SizeStats:
    """Given {url: size_or_None}, return a stats dict."""
    known = {u: s for u, s in sizes.items() if s is not None}
    failed = [u for u, s in sizes.items() if s is None]
    if not known:
        return {
            "sized": 0,
            "total": len(sizes),
            "total_bytes": 0,
            "smallest": 0,
            "largest": 0,
            "average": 0,
            "failed": failed,
        }
    total_bytes = sum(known.values())
    return {
        "sized": len(known),
        "total": len(sizes),
        "total_bytes": total_bytes,
        "smallest": min(known.values()),
        "largest": max(known.values()),
        "average": total_bytes // len(known),
        "failed": failed,
    }


def _is_stale(vid: dict[str, Any], now: int) -> bool:
    """True if the cached size is absent or older than SIZE_CACHE_TTL seconds."""
    if vid.get("size") is None:
        return True
    return (now - vid.get("size_checked_at", 0)) >= SIZE_CACHE_TTL


# --------------- CLI ---------------


def _progress(done: int, total: int) -> None:
    if done % 200 == 0 or done == total:
        print(f"    {done}/{total}")


def _print_stats(stats: SizeStats) -> None:
    print(f"\n{'=' * 45}")
    print(f"  Sized:    {stats['sized']}/{stats['total']} files")
    print(f"  Total:    {fmt_size(stats['total_bytes'])}")
    print(f"  Smallest: {fmt_size(stats['smallest'])}")
    print(f"  Largest:  {fmt_size(stats['largest'])}")
    print(f"  Average:  {fmt_size(stats['average'])}")
    print(f"{'=' * 45}")
    if stats["failed"]:
        print(f"\n[!] {len(stats['failed'])} URL(s) could not be sized:")
        for u in stats["failed"]:
            print(f"    {u}")


def _cache_hint(fresh: int, stale: int, missing: int) -> str:
    parts = [label for count, label in [(fresh, f"{fresh} fresh"), (stale, f"{stale} stale"), (missing, f"{missing} missing")] if count]
    if stale or missing:
        suffix = " — run --write to refresh" if stale else " — run --write to probe missing"
    else:
        suffix = " — all current"
    return f"Cache: {', '.join(parts)}{suffix}"


def _run_stats() -> None:
    vm = load_video_map()
    now = int(time.time())
    sizes: dict[str, int | None] = {}
    fresh = stale = missing = 0
    for entry in vm.values():
        for vid in entry.get("videos", []):
            url = vid["url"]
            if url in sizes:
                continue
            sizes[url] = vid.get("size")
            if vid.get("size") is None:
                missing += 1
            elif _is_stale(vid, now):
                stale += 1
            else:
                fresh += 1

    print(f"[+] {len(sizes)} URLs in {VIDEO_MAP_FILE}")
    print(f"    {_cache_hint(fresh, stale, missing)}")
    _print_stats(summarize_sizes(sizes))


def _apply_fetched(vm: dict[str, Any], fetched: dict[str, int | None], now: int) -> None:
    for entry in vm.values():
        for vid in entry.get("videos", []):
            if vid["url"] in fetched:
                vid["size"] = fetched[vid["url"]]
                vid["size_checked_at"] = now


def _run_write() -> None:
    """Probe uncached sizes and write them into video_map.json."""
    now = int(time.time())
    all_fetched: dict[str, int | None] = {}

    for site_key in SITES:
        vm = load_video_map(site_key)
        if not vm:
            continue

        url_referers = build_url_referers(vm)

        to_probe: list[str] = [
            vid["url"]
            for entry in vm.values()
            for vid in entry.get("videos", [])
            if _is_stale(vid, now)
        ]
        cached_count = sum(
            1
            for entry in vm.values()
            for vid in entry.get("videos", [])
            if not _is_stale(vid, now)
        )
        print(f"[{site_key}] {cached_count} cached, {len(to_probe)} to probe…")

        fetched: dict[str, int | None] = {}
        if to_probe:
            fetched = fetch_sizes(
                to_probe, workers=20, on_progress=_progress, url_referers=url_referers
            )

        _apply_fetched(vm, fetched, now)
        save_video_map(vm, site_key)
        all_fetched.update(fetched)
        print(f"[{site_key}] Written.")

    if all_fetched:
        _print_stats(summarize_sizes(all_fetched))


def main() -> None:
    parser = argparse.ArgumentParser(description="Calculate total video download size")
    parser.add_argument(
        "--write",
        "-w",
        action="store_true",
        help="Probe uncached sizes and write them into video_map.json",
    )
    args = parser.parse_args()

    if args.write:
        _run_write()
    else:
        _run_stats()


if __name__ == "__main__":
    main()
