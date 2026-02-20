"""Filename clash detection and shared URL utilities.

Importable functions:
    url_to_filename(url)       - extract clean filename from a URL
    find_clashes(urls)         - {filename: [urls]} for filenames with >1 source
    build_download_paths(urls, output_dir) - {url: local_path} with clash resolution
    fmt_size(bytes)            - human-readable size string
    get_remote_size(session, url) - file size via HEAD without downloading
    fetch_sizes(urls, workers, on_progress) - bulk size lookup
    make_session()             - requests.Session with required headers
    load_video_map()           - load video_map.json, returns {} on missing/corrupt
"""

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse, unquote
import json
import requests
from config import BASE_URL

REFERER = f"{BASE_URL}/"
VIDEO_MAP_FILE = "video_map.json"
VIDEO_EXTS = {".mp4", ".mov", ".m4v", ".webm", ".avi"}


def load_video_map():
    if Path(VIDEO_MAP_FILE).exists():
        try:
            with open(VIDEO_MAP_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def make_session():
    s = requests.Session()
    s.headers.update({"Referer": REFERER})
    return s


def fmt_size(b):
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def url_to_filename(url):
    return unquote(PurePosixPath(urlparse(url).path).name)


def find_clashes(urls):
    # Case-insensitive grouping so that e.g. "DaisyArrest.mp4" and
    # "daisyarrest.mp4" are treated as a clash.  This is required for
    # correctness on case-insensitive filesystems (NTFS, exFAT, macOS HFS+)
    # and harmless on case-sensitive ones (ext4) — the actual filenames on
    # disk keep their original casing; only the clash *detection* is folded.
    by_lower = defaultdict(list)
    for url in urls:
        by_lower[url_to_filename(url).lower()].append(url)
    return {url_to_filename(srcs[0]): srcs
            for srcs in by_lower.values() if len(srcs) > 1}


def _clash_subfolder(url):
    """Parent path segment used as disambiguator for clashing filenames."""
    parts = urlparse(url).path.rstrip("/").split("/")
    return unquote(parts[-2]) if len(parts) >= 2 else "unknown"


def build_download_paths(urls, output_dir):
    """Map each URL to a local file path. Flat layout; clashing names get a subfolder."""
    clashes = find_clashes(urls)
    clash_lower = {name.lower() for name in clashes}

    paths = {}
    for url in urls:
        filename = url_to_filename(url)
        if filename.lower() in clash_lower:
            paths[url] = Path(output_dir) / _clash_subfolder(url) / filename
        else:
            paths[url] = Path(output_dir) / filename
    return paths


def get_remote_size(session, url):
    try:
        r = session.head(url, allow_redirects=True, timeout=15)
        if r.status_code < 400 and "Content-Length" in r.headers:
            return int(r.headers["Content-Length"])
    except Exception:
        pass
    try:
        r = session.get(
            url, headers={"Range": "bytes=0-0"}, stream=True, timeout=15)
        r.close()
        cr = r.headers.get("Content-Range", "")
        if "/" in cr:
            return int(cr.split("/")[-1])
    except Exception:
        pass
    return None


def fetch_sizes(urls, workers=20, on_progress=None):
    """Return {url: size_or_None}. on_progress(done, total) called after each URL."""
    session = make_session()
    sizes = {}
    total = len(urls)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(get_remote_size, session, u): u for u in urls}
        done = 0
        for fut in as_completed(futures):
            sizes[futures[fut]] = fut.result()
            done += 1
            if on_progress:
                on_progress(done, total)

    return sizes


# --------------- CLI ---------------

def main():
    vm = load_video_map()
    urls = [u for entry in vm.values() for u in entry.get("videos", []) if u.startswith("http")]

    clashes = find_clashes(urls)

    print(f"Total URLs: {len(urls)}")
    by_name = defaultdict(list)
    for url in urls:
        by_name[url_to_filename(url)].append(url)
    print(f"Unique filenames: {len(by_name)}")

    if not clashes:
        print("\nNo filename clashes — every filename is unique.")
        return

    clash_urls = [u for srcs in clashes.values() for u in srcs]
    print(f"\n[+] Fetching file sizes for {len(clash_urls)} clashing URLs…")
    sizes = fetch_sizes(clash_urls)

    print(f"\n{len(clashes)} filename clash(es):\n")
    for name, srcs in sorted(clashes.items()):
        print(f"  {name}  ({len(srcs)} sources)")
        for s in srcs:
            sz = sizes.get(s)
            tag = fmt_size(sz) if sz is not None else "unknown"
            print(f"    [{tag}] {s}")
        print()


if __name__ == "__main__":
    main()
