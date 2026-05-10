"""Filename clash detection and shared URL utilities.

Importable functions:
    url_to_filename(url)       - extract clean filename from a URL
    find_clashes(urls)         - {filename: [urls]} for filenames with >1 source
    build_download_paths(urls, output_dir) - {url: local_path} with clash resolution
    fmt_size(bytes)            - human-readable size string
    get_remote_size(session, url, referer) - file size via HEAD without downloading
    fetch_sizes(urls, workers, on_progress, url_referers, session) - bulk size lookup
    make_session()             - requests.Session with required headers
    load_video_map(site, path) - load video_map.json; auto-migrates old flat format
    save_video_map(video_map, site_key, path) - atomic write of one site's entries
    build_url_referers(video_map) - {cdn_url: referer} derived from page URL keys
    is_valid_url(url)          - True if url is a plain http(s) URL with no HTML artefacts
    expects_video(url)         - True if url is a members-only video page
"""

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath
from typing import Any, cast

from collections.abc import Callable
from urllib.parse import urlparse, unquote
import json
import os
import tempfile
import requests

VIDEO_MAP_FILE: str = "video_map.json"
VIDEO_EXTS: set[str] = {".mp4", ".mov", ".m4v", ".webm", ".avi"}


def is_valid_url(url: str) -> bool:
    """True if url is a plain http(s) URL with no HTML artefacts (<, >, href= etc.)."""
    return (
        url.startswith("http")
        and "<" not in url
        and ">" not in url
        and " href=" not in url
    )


def expects_video(url: str) -> bool:
    """True if url is a members-only video page that should contain a video."""
    return "/pinkcuffs-videos/" in url


def _write_video_map_atomic(data: dict[str, Any], path: Path) -> None:
    """Write the full nested video_map dict to disk atomically via a temp file."""
    fd, tmp = tempfile.mkstemp(dir=path.resolve().parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        Path(tmp).replace(path)
    except Exception:
        try:
            Path(tmp).unlink()
        except OSError:
            pass
        raise


def load_video_map(
    site: str | None = None,
    path: str | Path = VIDEO_MAP_FILE,
) -> dict[str, Any]:
    """Load video_map.json.

    Args:
        site: If given, return only that site's inner dict {url: entry}.
              If None, return a flat-merged dict across all sites.
        path: Path to the JSON file (injectable for tests).
    """
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            raw: Any = json.load(f)
        data = cast(dict[str, Any], raw)
    except (json.JSONDecodeError, OSError):
        return {}

    if site is not None:
        return cast(dict[str, Any], data.get(site, {}))

    # Merge all sites into a flat dict for backward-compat callers
    merged: dict[str, Any] = {}
    for site_entries in data.values():
        if isinstance(site_entries, dict):
            merged.update(cast(dict[str, Any], site_entries))
    return merged


def save_video_map(
    video_map: dict[str, Any],
    site_key: str,
    path: str | Path = VIDEO_MAP_FILE,
) -> None:
    """Atomically update one site's entries in the nested video_map.json.

    Args:
        video_map: The inner {url: entry} dict for site_key.
        site_key:  Which top-level key to update (e.g. "jailbirdz").
        path:      Path to the JSON file (injectable for tests).
    """
    p = Path(path)
    if p.exists():
        try:
            with open(p, encoding="utf-8") as f:
                raw: Any = json.load(f)
            full = cast(dict[str, Any], raw)
        except (json.JSONDecodeError, OSError):
            full = {}
    else:
        full = {}

    full[site_key] = video_map
    _write_video_map_atomic(full, p)


def build_url_referers(video_map: dict[str, Any]) -> dict[str, str]:
    """Pure function: return {cdn_video_url: referer} from a flat video map.

    Bunny.net CDN URLs require https://player.mediadelivery.net/ as referer.
    All other URLs use the scheme+netloc of the page they were found on.
    """
    result: dict[str, str] = {}
    for page_url, entry in video_map.items():
        parsed = urlparse(page_url)
        site_referer = f"{parsed.scheme}://{parsed.netloc}/"
        for vid in cast(dict[str, Any], entry).get("videos", []):
            vid_url = vid["url"]
            if urlparse(vid_url).netloc.endswith(".b-cdn.net"):
                result.setdefault(vid_url, "https://player.mediadelivery.net/")
            else:
                result.setdefault(vid_url, site_referer)
    return result


def make_session() -> requests.Session:
    return requests.Session()


def fmt_size(b: float | int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def is_hls_url(url: str) -> bool:
    """True if url is an HLS master playlist (.m3u8)."""
    return urlparse(url).path.endswith(".m3u8")


def url_to_filename(url: str) -> str:
    path = PurePosixPath(urlparse(url).path)
    # Bunny.net HLS: .../guid/playlist.m3u8 → guid.mp4
    if path.name == "playlist.m3u8":
        return unquote(path.parent.name) + ".mp4"
    return unquote(path.name)


def find_clashes(urls: list[str]) -> dict[str, list[str]]:
    # Case-insensitive grouping so that e.g. "DaisyArrest.mp4" and
    # "daisyarrest.mp4" are treated as a clash.  This is required for
    # correctness on case-insensitive filesystems (NTFS, exFAT, macOS HFS+)
    # and harmless on case-sensitive ones (ext4) — the actual filenames on
    # disk keep their original casing; only the clash *detection* is folded.
    by_lower: defaultdict[str, list[str]] = defaultdict(list)
    for url in urls:
        by_lower[url_to_filename(url).lower()].append(url)
    return {
        url_to_filename(srcs[0]): srcs for srcs in by_lower.values() if len(srcs) > 1
    }


def _path_folders(url: str) -> list[str]:
    """Decoded URL path segments above the filename (filename excluded)."""
    parts = [unquote(p) for p in urlparse(url).path.split("/") if p]
    return parts[:-1]


def _disambiguate_group(group: list[str]) -> dict[str, tuple[str, ...]]:
    """Find the smallest depth of trailing folder segments that gives every URL in the group
    a unique subfolder path. Returns {url: subfolder_segments}.

    Comparison is case-insensitive so the result is safe on NTFS/APFS as well as ext4.
    """
    folders = {u: _path_folders(u) for u in group}
    max_depth = max((len(f) for f in folders.values()), default=0)

    for depth in range(1, max_depth + 1):
        keys = {u: tuple(p.lower() for p in folders[u][-depth:]) for u in group}
        if len(set(keys.values())) == len(group):
            return {u: tuple(folders[u][-depth:]) for u in group}

    raise RuntimeError(
        f"Cannot disambiguate URL group sharing filename and full parent path: {group}"
    )


def build_download_paths(
    urls: list[str],
    output_dir: str | Path,
) -> dict[str, Path]:
    """Map each URL to a unique local file path.

    Unique filenames go directly under output_dir. Filenames that clash
    (case-insensitively) get the smallest tail of their URL path prepended
    that makes every URL in the clashing group unique — e.g. /2018/Daisy/foo.mp4
    and /2023/Daisy/foo.mp4 land at 2018/Daisy/foo.mp4 and 2023/Daisy/foo.mp4
    rather than colliding at Daisy/foo.mp4.
    """
    by_lower: defaultdict[str, list[str]] = defaultdict(list)
    for url in urls:
        by_lower[url_to_filename(url).lower()].append(url)

    base = Path(output_dir)
    paths: dict[str, Path] = {}

    for group in by_lower.values():
        if len(group) == 1:
            url = group[0]
            paths[url] = base / url_to_filename(url)
            continue
        subfolders = _disambiguate_group(group)
        for url in group:
            paths[url] = base.joinpath(*subfolders[url]) / url_to_filename(url)

    # Defensive: every URL must map to a distinct destination path.
    # Case-fold the comparison since callers commonly run on NTFS/APFS where
    # "Daisy/foo" and "daisy/foo" are the same file on disk.
    seen: dict[str, str] = {}
    for url, p in paths.items():
        key = str(p).lower()
        if key in seen:
            raise RuntimeError(
                f"Path collision after disambiguation: {url!r} and {seen[key]!r} "
                f"both map to {p}"
            )
        seen[key] = url

    return paths


def get_remote_size(
    session: requests.Session,
    url: str,
    referer: str = "",
) -> int | None:
    extra = {"Referer": referer} if referer else {}
    try:
        r = session.head(url, headers=extra, allow_redirects=True, timeout=15)
        if r.status_code < 400 and "Content-Length" in r.headers:
            return int(r.headers["Content-Length"])
    except Exception:
        pass
    try:
        r = session.get(
            url,
            headers={"Range": "bytes=0-0", **extra},
            stream=True,
            timeout=15,
        )
        r.close()
        cr = r.headers.get("Content-Range", "")
        if "/" in cr:
            return int(cr.split("/")[-1])
    except Exception:
        pass
    return None


def fetch_sizes(
    urls: list[str],
    workers: int = 20,
    on_progress: Callable[[int, int], None] | None = None,
    url_referers: dict[str, str] | None = None,
    session: requests.Session | None = None,
) -> dict[str, int | None]:
    """Return {url: size_or_None}. on_progress(done, total) called after each URL."""
    if session is None:
        session = make_session()
    referers = url_referers or {}
    sizes: dict[str, int | None] = {}
    total = len(urls)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(get_remote_size, session, u, referers.get(u, "")): u
            for u in urls
        }
        done = 0
        for fut in as_completed(futures):
            sizes[futures[fut]] = fut.result()
            done += 1
            if on_progress is not None:
                on_progress(done, total)

    return sizes


# --------------- CLI ---------------


def main() -> None:
    vm = load_video_map()
    urls = [vid["url"] for entry in vm.values() for vid in entry.get("videos", [])]

    clashes = find_clashes(urls)

    print(f"Total URLs: {len(urls)}")
    by_name: defaultdict[str, list[str]] = defaultdict(list)
    for url in urls:
        by_name[url_to_filename(url)].append(url)
    print(f"Unique filenames: {len(by_name)}")

    if not clashes:
        print("\nNo filename clashes — every filename is unique.")
        return

    clash_urls = [u for srcs in clashes.values() for u in srcs]
    url_referers = build_url_referers(vm)
    print(f"\n[+] Fetching file sizes for {len(clash_urls)} clashing URLs…")
    sizes = fetch_sizes(clash_urls, url_referers=url_referers)

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
