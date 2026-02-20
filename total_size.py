"""Calculate total disk space needed to download all videos.

Importable function:
    summarize_sizes(sizes) - return dict with total, smallest, largest, average, failed
"""

from check_clashes import fmt_size, fetch_sizes, load_video_map, VIDEO_MAP_FILE


def summarize_sizes(sizes):
    """Given {url: size_or_None}, return a stats dict."""
    known = {u: s for u, s in sizes.items() if s is not None}
    failed = [u for u, s in sizes.items() if s is None]
    if not known:
        return {"sized": 0, "total": len(sizes), "total_bytes": 0,
                "smallest": 0, "largest": 0, "average": 0, "failed": failed}
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


# --------------- CLI ---------------

def _progress(done, total):
    if done % 200 == 0 or done == total:
        print(f"    {done}/{total}")


def main():
    vm = load_video_map()
    urls = [u for entry in vm.values() for u in entry.get("videos", []) if u.startswith("http")]

    print(f"[+] {len(urls)} URLs in {VIDEO_MAP_FILE}")
    print("[+] Fetching file sizes (20 threads)…\n")

    sizes = fetch_sizes(urls, workers=20, on_progress=_progress)
    stats = summarize_sizes(sizes)

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


if __name__ == "__main__":
    main()
