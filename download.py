"""Download videos from video_map.json with resume, integrity checks, and naming modes.

Usage:
    python download.py                        # downloads with remembered (or default original) naming
    python download.py --output /mnt/nas      # custom directory
    python download.py --titles               # switch to title-based filenames (remembers choice)
    python download.py --original             # switch back to original filenames (remembers choice)
    python download.py --reorganize           # rename existing files to match current mode
    python download.py --dry-run              # preview what would happen
    python download.py --workers 6            # override concurrency (default 4)
"""

import argparse
from pathlib import Path
import re
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
import requests

from check_clashes import (
    make_session,
    fmt_size,
    url_to_filename,
    find_clashes,
    build_download_paths,
    build_url_referers,
    fetch_sizes,
    load_video_map,
    is_valid_url,
    VIDEO_MAP_FILE,
)
from config import SITES

CHUNK_SIZE = 8 * 1024 * 1024
DEFAULT_OUTPUT: str = "downloads"
DEFAULT_WORKERS: int = 4
MODE_FILE: str = ".naming_mode"
MODE_ORIGINAL: str = "original"
MODE_TITLE: str = "title"


# ── Naming mode persistence ──────────────────────────────────────────


def read_mode(output_dir: str | Path) -> str | None:
    p = Path(output_dir) / MODE_FILE
    if p.exists():
        return p.read_text().strip()
    return None


def write_mode(output_dir: str | Path, mode: str) -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    (Path(output_dir) / MODE_FILE).write_text(mode)


def resolve_mode(args: argparse.Namespace) -> str:
    """Determine naming mode from CLI flags + saved marker. Returns mode string."""
    saved = read_mode(args.output)

    if args.titles and args.original:
        print("[!] Cannot use --titles and --original together.")
        raise SystemExit(1)

    if args.titles:
        return MODE_TITLE
    if args.original:
        return MODE_ORIGINAL
    if saved:
        return saved
    return MODE_ORIGINAL


# ── Filename helpers ─────────────────────────────────────────────────


def sanitize_filename(title: str, max_len: int = 180) -> str:
    name = re.sub(r'[<>:"/\\|?*]', "", title)
    name = re.sub(r"\s+", " ", name).strip().rstrip(".")
    return name[:max_len].rstrip() if len(name) > max_len else name


def build_title_paths(
    urls: list[str],
    url_to_title: dict[str, str],
    output_dir: str | Path,
) -> dict[str, Path]:
    name_to_urls = defaultdict(list)
    url_to_base = {}

    for url in urls:
        title = url_to_title.get(url)
        ext = Path(url_to_filename(url)).suffix or ".mp4"
        base = sanitize_filename(title) if title else Path(url_to_filename(url)).stem
        url_to_base[url] = (base, ext)
        name_to_urls[base + ext].append(url)

    paths = {}
    for url in urls:
        base, ext = url_to_base[url]
        full = base + ext
        if len(name_to_urls[full]) > 1:
            slug = url_to_filename(url).rsplit(".", 1)[0]
            paths[url] = Path(output_dir) / f"{base} [{slug}]{ext}"
        else:
            paths[url] = Path(output_dir) / full
    return paths


def get_paths_for_mode(
    mode: str,
    urls: list[str],
    video_map: dict[str, Any],
    output_dir: str | Path,
    url_to_site: dict[str, str] | None = None,
) -> dict[str, Path]:
    if url_to_site:
        by_site: dict[str, list[str]] = defaultdict(list)
        for u in urls:
            by_site[url_to_site.get(u, "")].append(u)
        paths: dict[str, Path] = {}
        url_title = build_url_title_map(video_map) if mode == MODE_TITLE else {}
        for site, site_urls in by_site.items():
            base = Path(output_dir) / site if site else Path(output_dir)
            if mode == MODE_TITLE:
                paths.update(build_title_paths(site_urls, url_title, base))
            else:
                paths.update(build_download_paths(site_urls, base))
        return paths
    if mode == MODE_TITLE:
        url_title = build_url_title_map(video_map)
        return build_title_paths(urls, url_title, output_dir)
    return build_download_paths(urls, output_dir)


# ── Reorganize ───────────────────────────────────────────────────────


def reorganize(
    urls: list[str],
    video_map: dict[str, Any],
    output_dir: str | Path,
    target_mode: str,
    dry_run: bool = False,
    url_to_site: dict[str, str] | None = None,
) -> None:
    """Rename existing files from one naming scheme to another."""
    other_mode = MODE_TITLE if target_mode == MODE_ORIGINAL else MODE_ORIGINAL
    old_paths = get_paths_for_mode(other_mode, urls, video_map, output_dir, url_to_site)
    new_paths = get_paths_for_mode(
        target_mode, urls, video_map, output_dir, url_to_site
    )

    moves = []
    for url in urls:
        old = old_paths[url]
        new = new_paths[url]
        if old == new:
            continue
        if old.exists() and not new.exists():
            moves.append((old, new))
        # also handle .part files
        old_part = old.parent / (old.name + ".part")
        new_part = new.parent / (new.name + ".part")
        if old_part.exists() and not new_part.exists():
            moves.append((old_part, new_part))

    if not moves:
        print("[✓] Nothing to reorganize — files already match the target mode.")
        return

    print(f"[+] {len(moves)} file(s) to rename ({other_mode} → {target_mode}):\n")

    for old, new in moves:
        old_rel = old.relative_to(output_dir)
        new_rel = new.relative_to(output_dir)
        if dry_run:
            print(f"  [dry-run] {old_rel}  →  {new_rel}")
        else:
            new.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(old, new)
            print(f"  ✓ {old_rel}  →  {new_rel}")

    if not dry_run:
        # Clean up empty directories left behind
        output_path = Path(output_dir)
        for old, _ in moves:
            d = old.parent
            while d != output_path:
                try:
                    d.rmdir()
                except OSError:
                    break
                d = d.parent

        write_mode(output_dir, target_mode)
        print(f"\n[✓] Reorganized. Mode saved: {target_mode}")
    else:
        print(f"\n[dry-run] Would rename {len(moves)} files. No changes made.")


# ── Download ─────────────────────────────────────────────────────────


def download_one(
    session: requests.Session,
    url: str,
    dest: str | Path,
    expected_size: int | None,
    referer: str = "",
) -> tuple[str, int]:
    dest = Path(dest)
    part = dest.parent / (dest.name + ".part")
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        local = dest.stat().st_size
        if expected_size is not None and local == expected_size:
            return "ok", 0
        if expected_size is not None and local != expected_size:
            dest.unlink()

    existing = part.stat().st_size if part.exists() else 0
    headers: dict[str, str] = {}
    if referer:
        headers["Referer"] = referer
    if existing and expected_size is not None and existing < expected_size:
        headers["Range"] = f"bytes={existing}-"

    try:
        r = session.get(url, headers=headers, stream=True, timeout=60)

        if r.status_code == 416:
            part.rename(dest)
            return "ok", 0

        r.raise_for_status()
    except Exception as e:
        return f"error: {e}", 0

    mode = "ab" if headers.get("Range") else "wb"
    if mode == "wb":
        existing = 0

    written = 0
    try:
        with open(part, mode) as f:
            for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                f.write(chunk)
                written += len(chunk)
    except Exception as e:
        return f"error: {e}", written

    final_size = existing + written
    if expected_size is not None and final_size != expected_size:
        return "size_mismatch", written

    part.rename(dest)
    return "ok", written


def collect_urls(video_map: dict[str, Any]) -> list[str]:
    urls, seen, skipped = [], set(), 0
    for entry in video_map.values():
        for vid in entry.get("videos", []):
            u = vid["url"]
            if u in seen:
                continue
            seen.add(u)
            if is_valid_url(u):
                urls.append(u)
            else:
                skipped += 1
    if skipped:
        print(f"[!] Skipped {skipped} malformed URL(s)")
    return urls


def build_url_title_map(video_map: dict[str, Any]) -> dict[str, str]:
    url_title = {}
    for entry in video_map.values():
        title = entry.get("title", "")
        for vid in entry.get("videos", []):
            if vid["url"] not in url_title:
                url_title[vid["url"]] = title
    return url_title


def build_url_to_site() -> dict[str, str]:
    """Return {cdn_video_url: site_key} by loading each site's map in turn."""
    result: dict[str, str] = {}
    for site_key in SITES:
        for entry in load_video_map(site_key).values():
            for vid in entry.get("videos", []):
                result[vid["url"]] = site_key
    return result


# ── Main ─────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Download videos from video_map.json")
    parser.add_argument(
        "--output",
        "-o",
        default=DEFAULT_OUTPUT,
        help=f"Download directory (default: {DEFAULT_OUTPUT})",
    )

    naming = parser.add_mutually_exclusive_group()
    naming.add_argument(
        "--titles",
        "-t",
        action="store_true",
        help="Use title-based filenames (saved as default for this directory)",
    )
    naming.add_argument(
        "--original",
        action="store_true",
        help="Use original CloudFront filenames (saved as default for this directory)",
    )

    parser.add_argument(
        "--reorganize",
        action="store_true",
        help="Rename existing files to match the current naming mode",
    )
    parser.add_argument(
        "--dry-run", "-n", action="store_true", help="Preview without making changes"
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Concurrent downloads (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--site",
        action="append",
        choices=list(SITES.keys()),
        dest="sites",
        metavar="SITE",
        help=f"Site(s) to download (default: all). Can be repeated. Choices: {', '.join(SITES)}",
    )
    args = parser.parse_args()

    video_map = load_video_map()
    url_referers = build_url_referers(video_map)
    urls = collect_urls(video_map)

    url_to_site = build_url_to_site()

    if args.sites:
        selected = set(args.sites)
        urls = [u for u in urls if url_to_site.get(u) in selected]

    mode = resolve_mode(args)

    saved = read_mode(args.output)
    mode_changed = saved is not None and saved != mode

    print(f"[+] {len(urls)} MP4 URLs from {VIDEO_MAP_FILE}")
    print(f"[+] Naming mode: {mode}" + (" (changed!)" if mode_changed else ""))

    # Handle reorganize
    if args.reorganize or mode_changed:
        if mode_changed and not args.reorganize:
            print(f"\n[!] Mode changed from '{saved}' to '{mode}'.")
            print(
                "    Use --reorganize to rename existing files, or --dry-run to preview."
            )
            print("    Refusing to download until existing files are reorganized.")
            return
        reorganize(
            urls,
            video_map,
            args.output,
            mode,
            dry_run=args.dry_run,
            url_to_site=url_to_site,
        )
        if args.dry_run or args.reorganize:
            return

    # Save mode
    if not args.dry_run:
        write_mode(args.output, mode)

    paths = get_paths_for_mode(mode, urls, video_map, args.output, url_to_site)

    clashes = find_clashes(urls)
    if clashes:
        print(
            f"[+] {len(clashes)} filename clash(es) resolved with subfolders/suffixes"
        )

    already = [u for u in urls if paths[u].exists()]
    pending = [u for u in urls if not paths[u].exists()]

    print(f"[+] Already downloaded: {len(already)}")
    print(f"[+] To download: {len(pending)}")

    if not pending:
        print("\n[✓] Everything is already downloaded.")
        return

    if args.dry_run:
        print(f"\n[dry-run] Would download {len(pending)} files to {args.output}/")
        for url in pending[:20]:
            print(f"  → {paths[url].name}")
        if len(pending) > 20:
            print(f"  … and {len(pending) - 20} more")
        return

    cached_sizes: dict[str, int] = {
        vid["url"]: vid["size"]
        for entry in video_map.values()
        for vid in entry.get("videos", [])
        if vid.get("size") is not None
    }

    uncached_pending = [u for u in pending if u not in cached_sizes]
    session = make_session()
    if uncached_pending:
        print(
            f"\n[+] Fetching remote file sizes ({len(uncached_pending)} uncached, {len(pending) - len(uncached_pending)} cached)…"
        )
        remote_sizes: dict[str, int | None] = {
            **cached_sizes,
            **fetch_sizes(uncached_pending, workers=20, url_referers=url_referers),
        }
    else:
        print(f"\n[+] All {len(pending)} pending sizes cached — skipping probe.")
        remote_sizes = dict(cached_sizes)

    sized = {u: s for u, s in remote_sizes.items() if s is not None}
    total_bytes = sum(sized.values())
    print(f"[+] Download size: {fmt_size(total_bytes)} across {len(pending)} files")

    if already:
        uncached_already = [u for u in already if u not in cached_sizes]
        if uncached_already:
            print(
                f"[+] Verifying {len(already)} existing files ({len(uncached_already)} uncached)…"
            )
            already_sizes: dict[str, int | None] = {
                **cached_sizes,
                **fetch_sizes(uncached_already, workers=20, url_referers=url_referers),
            }
        else:
            print(f"[+] Verifying {len(already)} existing files (all sizes cached)…")
            already_sizes = dict(cached_sizes)

    mismatched = 0
    for url in already:
        dest = paths[url]
        local = dest.stat().st_size
        remote = already_sizes.get(url)
        if remote and local != remote:
            mismatched += 1
            print(
                f"[!] Size mismatch: {dest.name} "
                f"(local {fmt_size(local)} vs remote {fmt_size(remote)})"
            )
            pending.append(url)
            remote_sizes[url] = remote

    if mismatched:
        print(f"[!] {mismatched} file(s) will be re-downloaded due to size mismatch")

    print(f"\n[⚡] Downloading with {args.workers} threads…\n")

    completed = 0
    failed = []
    total_written = 0
    total = len(pending)
    interrupted = False

    def do_download(url: str) -> tuple[str, tuple[str, int]]:
        dest = paths[url]
        expected = remote_sizes.get(url)
        return url, download_one(
            session, url, dest, expected, url_referers.get(url, "")
        )

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(do_download, u): u for u in pending}
            for fut in as_completed(futures):
                url, (status, written) = fut.result()
                total_written += written
                completed += 1
                name = paths[url].name

                if status == "ok" and written > 0:
                    print(f"  [{completed}/{total}] ✓ {name} ({fmt_size(written)})")
                elif status == "ok":
                    print(f"  [{completed}/{total}] ✓ {name} (already complete)")
                elif status == "size_mismatch":
                    print(f"  [{completed}/{total}] ⚠ {name} (size mismatch)")
                    failed.append(url)
                else:
                    print(f"  [{completed}/{total}] ✗ {name} ({status})")
                    failed.append(url)
    except KeyboardInterrupt:
        interrupted = True
        pool.shutdown(wait=False, cancel_futures=True)
        print("\n\n[⏸] Interrupted! Partial downloads saved as .part files.")

    print(f"\n{'=' * 50}")
    print(f"  Downloaded: {fmt_size(total_written)}")
    print(f"  Completed:  {completed}/{total}")
    if failed:
        print(f"  Failed:     {len(failed)} (re-run to retry)")
    if interrupted:
        print("  Paused — re-run to resume.")
    elif not failed:
        print("  All done!")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    main()
