"""Upload videos to PeerTube with transcoding-aware flow control.

Uploads videos one batch at a time, waits for each batch to be fully transcoded
and moved to object storage before uploading the next — preventing disk
exhaustion on the PeerTube server.

Usage:
    python upload.py                      # upload from ./downloads
    python upload.py -i /mnt/vol/dl      # custom input dir
    python upload.py --batch-size 2      # upload 2, wait, repeat
    python upload.py --dry-run           # preview without uploading
    python upload.py --skip-wait         # upload without waiting

Required (CLI flag or env var):
    --url / PEERTUBE_URL
    --username / PEERTUBE_USER
    --channel / PEERTUBE_CHANNEL
    --password / PEERTUBE_PASSWORD
"""

import argparse
from collections import Counter
import html
import os
from pathlib import Path
import re
import sys
import time

import requests
from dotenv import load_dotenv

from check_clashes import fmt_size, url_to_filename, VIDEO_EXTS
from download import (
    load_video_map,
    collect_urls,
    get_paths_for_mode,
    read_mode,
    MODE_ORIGINAL,
    DEFAULT_OUTPUT,
)

load_dotenv()

# ── Defaults ─────────────────────────────────────────────────────────

DEFAULT_BATCH_SIZE = 1
DEFAULT_POLL = 30
UPLOADED_FILE = ".uploaded"
PT_NAME_MAX = 120


# ── Text helpers ─────────────────────────────────────────────────────

def clean_description(raw):
    """Strip WordPress shortcodes and HTML from a description."""
    if not raw:
        return ""
    text = re.sub(r'\[/?[^\]]+\]', '', raw)
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    text = re.sub(r'\n{3,}', '\n\n', text).strip()
    return text[:10000]


def make_pt_name(title, fallback_filename):
    """Build a PeerTube-safe video name (3-120 chars)."""
    name = html.unescape(title).strip(
    ) if title else Path(fallback_filename).stem
    if len(name) > PT_NAME_MAX:
        name = name[: PT_NAME_MAX - 1].rstrip() + "\u2026"
    while len(name) < 3:
        name += "_"
    return name


# ── PeerTube API ─────────────────────────────────────────────────────

def get_oauth_token(base, username, password):
    r = requests.get(f"{base}/api/v1/oauth-clients/local", timeout=15)
    r.raise_for_status()
    client = r.json()

    r = requests.post(
        f"{base}/api/v1/users/token",
        data={
            "client_id": client["client_id"],
            "client_secret": client["client_secret"],
            "grant_type": "password",
            "username": username,
            "password": password,
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def api_headers(token):
    return {"Authorization": f"Bearer {token}"}


def get_channel_id(base, token, channel_name):
    r = requests.get(
        f"{base}/api/v1/video-channels/{channel_name}",
        headers=api_headers(token),
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["id"]


def get_channel_video_names(base, token, channel_name):
    """Paginate through the channel and return a Counter of video names."""
    counts = Counter()
    start = 0
    while True:
        r = requests.get(
            f"{base}/api/v1/video-channels/{channel_name}/videos",
            params={"start": start, "count": 100},
            headers=api_headers(token),
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        for v in data.get("data", []):
            counts[v["name"]] += 1
        start += 100
        if start >= data.get("total", 0):
            break
    return counts


CHUNK_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_RETRIES = 5


def _init_resumable(base, token, channel_id, filepath, filename, name,
                    description="", nsfw=False):
    """POST to create a resumable upload session.  Returns upload URL."""
    file_size = Path(filepath).stat().st_size
    metadata = {
        "name": name,
        "channelId": channel_id,
        "filename": filename,
        "nsfw": nsfw,
        "waitTranscoding": True,
        "privacy": 1,
    }
    if description:
        metadata["description"] = description

    r = requests.post(
        f"{base}/api/v1/videos/upload-resumable",
        headers={
            **api_headers(token),
            "Content-Type": "application/json",
            "X-Upload-Content-Length": str(file_size),
            "X-Upload-Content-Type": "video/mp4",
        },
        json=metadata,
        timeout=30,
    )
    r.raise_for_status()

    location = r.headers["Location"]
    if location.startswith("//"):
        location = "https:" + location
    elif location.startswith("/"):
        location = base + location
    return location, file_size


def _query_offset(upload_url, token, file_size):
    """Ask the server how many bytes it has received so far."""
    r = requests.put(
        upload_url,
        headers={
            **api_headers(token),
            "Content-Range": f"bytes */{file_size}",
            "Content-Length": "0",
        },
        timeout=15,
    )
    if r.status_code == 308:
        range_hdr = r.headers.get("Range", "")
        if range_hdr:
            return int(range_hdr.split("-")[1]) + 1
        return 0
    if r.status_code == 200:
        return file_size
    r.raise_for_status()
    return 0


def upload_video(base, token, channel_id, filepath, name,
                 description="", nsfw=False):
    """Resumable chunked upload.  Returns (ok, uuid)."""
    filepath = Path(filepath)
    filename = filepath.name
    file_size = filepath.stat().st_size

    try:
        upload_url, _ = _init_resumable(
            base, token, channel_id, filepath, filename,
            name, description, nsfw,
        )
    except Exception as e:
        print(f"    Init failed: {e}")
        return False, None

    offset = 0
    retries = 0

    with open(filepath, "rb") as f:
        while offset < file_size:
            end = min(offset + CHUNK_SIZE, file_size) - 1
            chunk_len = end - offset + 1

            f.seek(offset)
            chunk = f.read(chunk_len)

            pct = int(100 * (end + 1) / file_size)
            print(f"    {fmt_size(offset)}/{fmt_size(file_size)}  ({pct}%)",
                  end="\r", flush=True)

            try:
                r = requests.put(
                    upload_url,
                    headers={
                        **api_headers(token),
                        "Content-Type": "application/octet-stream",
                        "Content-Range": f"bytes {offset}-{end}/{file_size}",
                        "Content-Length": str(chunk_len),
                    },
                    data=chunk,
                    timeout=120,
                )
            except (requests.ConnectionError, requests.Timeout) as e:
                retries += 1
                if retries > MAX_RETRIES:
                    print(
                        f"\n    Upload failed after {MAX_RETRIES} retries: {e}")
                    return False, None
                wait = min(2 ** retries, 60)
                print(f"\n    Connection error, retry {retries}/{MAX_RETRIES} "
                      f"in {wait}s ...")
                time.sleep(wait)
                try:
                    offset = _query_offset(upload_url, token, file_size)
                except Exception:
                    pass
                continue

            if r.status_code == 308:
                range_hdr = r.headers.get("Range", "")
                if range_hdr:
                    offset = int(range_hdr.split("-")[1]) + 1
                else:
                    offset = end + 1
                retries = 0

            elif r.status_code == 200:
                print(
                    f"    {fmt_size(file_size)}/{fmt_size(file_size)}  (100%)")
                uuid = r.json().get("video", {}).get("uuid")
                return True, uuid

            elif r.status_code in (502, 503, 429):
                retry_after = int(r.headers.get("Retry-After", 10))
                retries += 1
                if retries > MAX_RETRIES:
                    print(
                        f"\n    Upload failed: server returned {r.status_code}")
                    return False, None
                print(
                    f"\n    Server {r.status_code}, retry in {retry_after}s ...")
                time.sleep(retry_after)
                try:
                    offset = _query_offset(upload_url, token, file_size)
                except Exception:
                    pass

            else:
                detail = r.text[:300] if r.text else str(r.status_code)
                print(f"\n    Upload failed ({r.status_code}): {detail}")
                return False, None

    print("\n    Unexpected: sent all bytes but no 200 response")
    return False, None


_STATE = {
    1: "Published",
    2: "To transcode",
    3: "To import",
    6: "Moving to object storage",
    7: "Transcoding failed",
    8: "Storage move failed",
    9: "To edit",
}


def get_video_state(base, token, uuid):
    r = requests.get(
        f"{base}/api/v1/videos/{uuid}",
        headers=api_headers(token),
        timeout=15,
    )
    r.raise_for_status()
    state = r.json()["state"]
    return state["id"], state.get("label", "")


def wait_for_published(base, token, uuid, poll_interval):
    """Block until the video reaches state 1 (Published) or a failure state."""
    started = time.monotonic()
    while True:
        elapsed = int(time.monotonic() - started)
        hours, rem = divmod(elapsed, 3600)
        mins, secs = divmod(rem, 60)
        if hours:
            elapsed_str = f"{hours}h {mins:02d}m {secs:02d}s"
        elif mins:
            elapsed_str = f"{mins}m {secs:02d}s"
        else:
            elapsed_str = f"{secs}s"

        try:
            sid, label = get_video_state(base, token, uuid)
        except requests.exceptions.RequestException as e:
            print(f"    -> Poll error ({e.__class__.__name__}) "
                  f"after {elapsed_str}, retrying in {poll_interval}s …")
            time.sleep(poll_interval)
            continue

        display = _STATE.get(sid, label or f"state {sid}")

        if sid == 1:
            print(f"    -> {display}")
            return sid
        if sid in (7, 8):
            print(f"    -> FAILED: {display}")
            return sid

        print(f"    -> {display} … {elapsed_str} elapsed (next check in {poll_interval}s)")
        time.sleep(poll_interval)


# ── State tracker ────────────────────────────────────────────────────

def load_uploaded(input_dir):
    path = Path(input_dir) / UPLOADED_FILE
    if not path.exists():
        return set()
    with open(path) as f:
        return {Path(line.strip()) for line in f if line.strip()}


def mark_uploaded(input_dir, rel_path):
    with open(Path(input_dir) / UPLOADED_FILE, "a") as f:
        f.write(f"{rel_path}\n")


# ── File / metadata helpers ─────────────────────────────────────────

def build_path_to_meta(video_map, input_dir):
    """Map each expected download path (relative) to {title, description}."""
    urls = collect_urls(video_map)
    mode = read_mode(input_dir) or MODE_ORIGINAL
    paths = get_paths_for_mode(mode, urls, video_map, input_dir)

    url_meta = {}
    for entry in video_map.values():
        t = entry.get("title", "")
        d = entry.get("description", "")
        for video_url in entry.get("videos", []):
            if video_url not in url_meta:
                url_meta[video_url] = {"title": t, "description": d}

    result = {}
    for url, abs_path in paths.items():
        rel = Path(abs_path).relative_to(input_dir)
        meta = url_meta.get(url, {"title": "", "description": ""})
        result[rel] = {**meta, "original_filename": url_to_filename(url)}
    return result


def find_videos(input_dir):
    """Walk input_dir and return a set of relative paths for all video files."""
    found = set()
    for root, dirs, files in os.walk(input_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            if Path(f).suffix.lower() in VIDEO_EXTS:
                found.add((Path(root) / f).relative_to(input_dir))
    return found


# ── Channel match helpers ─────────────────────────────────────────────

def _channel_match(rel, path_meta, existing):
    """Return (matched, name) for a local file against the channel name set.

    Checks both the title-derived name and the original-filename-derived name
    so that videos uploaded under either form are recognised.  Extracted to
    avoid duplicating the logic between the pre-reconcile sweep and the per-
    file check inside the upload loop.
    """
    meta = path_meta.get(rel, {})
    name = make_pt_name(meta.get("title", ""), rel.name)
    orig_fn = meta.get("original_filename", "")
    raw_name = make_pt_name("", orig_fn) if orig_fn else None
    matched = name in existing or (raw_name and raw_name != name and raw_name in existing)
    return matched, name


# ── CLI ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Upload videos to PeerTube with transcoding-aware batching",
    )
    ap.add_argument("--input", "-i", default=DEFAULT_OUTPUT,
                    help=f"Directory with downloaded videos (default: {DEFAULT_OUTPUT})")
    ap.add_argument("--url",
                    help="PeerTube instance URL (or set PEERTUBE_URL env var)")
    ap.add_argument("--username", "-U",
                    help="PeerTube username (or set PEERTUBE_USER env var)")
    ap.add_argument("--password", "-p",
                    help="PeerTube password (or set PEERTUBE_PASSWORD env var)")
    ap.add_argument("--channel", "-C",
                    help="Channel to upload to (or set PEERTUBE_CHANNEL env var)")
    ap.add_argument("--batch-size", "-b", type=int, default=DEFAULT_BATCH_SIZE,
                    help="Videos to upload before waiting for transcoding (default: 1)")
    ap.add_argument("--poll-interval", type=int, default=DEFAULT_POLL,
                    help=f"Seconds between state polls (default: {DEFAULT_POLL})")
    ap.add_argument("--skip-wait", action="store_true",
                    help="Upload everything without waiting for transcoding")
    ap.add_argument("--nsfw", action="store_true",
                    help="Mark videos as NSFW")
    ap.add_argument("--dry-run", "-n", action="store_true",
                    help="Preview what would be uploaded")
    args = ap.parse_args()

    url      = args.url      or os.environ.get("PEERTUBE_URL")
    username = args.username or os.environ.get("PEERTUBE_USER")
    channel  = args.channel  or os.environ.get("PEERTUBE_CHANNEL")
    password = args.password or os.environ.get("PEERTUBE_PASSWORD")

    if not args.dry_run:
        missing = [label for label, val in [
            ("--url / PEERTUBE_URL", url),
            ("--username / PEERTUBE_USER", username),
            ("--channel / PEERTUBE_CHANNEL", channel),
            ("--password / PEERTUBE_PASSWORD", password),
        ] if not val]
        if missing:
            for label in missing:
                print(f"[!] Required: {label}")
            sys.exit(1)

    # ── load metadata & scan disk ──
    video_map = load_video_map()
    path_meta = build_path_to_meta(video_map, args.input)
    on_disk = find_videos(args.input)

    unmatched = on_disk - set(path_meta.keys())
    if unmatched:
        print(
            f"[!] {len(unmatched)} file(s) on disk not in video_map (will use filename as title)")
        for rel in unmatched:
            path_meta[rel] = {"title": "", "description": ""}

    uploaded = load_uploaded(args.input)
    pending = sorted(rel for rel in on_disk if rel not in uploaded)

    print(f"[+] {len(on_disk)} video files in {args.input}/")
    print(f"[+] {len(uploaded)} already uploaded")
    print(f"[+] {len(pending)} pending")
    print(f"[+] Batch size: {args.batch_size}")

    if not pending:
        print("\nAll videos already uploaded.")
        return

    # ── dry run ──
    if args.dry_run:
        total_bytes = 0
        for rel in pending:
            meta = path_meta.get(rel, {})
            name = make_pt_name(meta.get("title", ""), rel.name)
            sz = (Path(args.input) / rel).stat().st_size
            total_bytes += sz
            print(f"  [{fmt_size(sz):>10}]  {name}")
        print(
            f"\n  Total: {fmt_size(total_bytes)} across {len(pending)} videos")
        return

    # ── authenticate ──
    base = url.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"\n[+] Authenticating with {base} ...")
    token = get_oauth_token(base, username, password)
    print(f"[+] Authenticated as {username}")

    channel_id = get_channel_id(base, token, channel)
    print(f"[+] Channel: {channel} (id {channel_id})")

    name_counts = get_channel_video_names(base, token, channel)
    existing = set(name_counts)
    total = sum(name_counts.values())
    print(f"[+] Found {total} video(s) on channel ({len(name_counts)} unique name(s))")

    dupes = {name: count for name, count in name_counts.items() if count > 1}
    if dupes:
        print(f"[!] {len(dupes)} duplicate name(s) detected on channel:")
        for name, count in sorted(dupes.items()):
            print(f"    x{count}  {name}")

    # ── pre-reconcile: sweep all pending against channel names ────────
    # The main upload loop discovers already-uploaded videos lazily as it
    # walks the sorted pending list — meaning on a fresh run (no .uploaded
    # file) you won't know how many files are genuinely new until the loop
    # has processed everything.  Doing a full sweep here, before any
    # upload starts, gives an accurate count up-front and pre-populates
    # .uploaded so that interrupted/re-run sessions skip them instantly
    # without re-checking each time.
    pre_matched = []
    for rel in pending:
        if _channel_match(rel, path_meta, existing)[0]:
            pre_matched.append(rel)
    if pre_matched:
        print(f"\n[+] Pre-sweep: {len(pre_matched)} local file(s) already on channel — marking uploaded")
        for rel in pre_matched:
            mark_uploaded(args.input, rel)
        pending = [rel for rel in pending if rel not in set(pre_matched)]
        print(f"[+] {len(pending)} left to upload\n")

    nsfw = args.nsfw
    total_up = 0
    batch: list[tuple[str, str]] = []   # [(uuid, name), ...]

    try:
        for rel in pending:
            # ── flush batch if full ──
            if not args.skip_wait and len(batch) >= args.batch_size:
                print(
                    f"\n[+] Waiting for {len(batch)} video(s) to finish processing ...")
                for uuid, bname in batch:
                    print(f"\n  [{bname}]")
                    wait_for_published(base, token, uuid, args.poll_interval)
                batch.clear()

            filepath = Path(args.input) / rel
            meta = path_meta.get(rel, {})
            name = make_pt_name(meta.get("title", ""), rel.name)
            desc = clean_description(meta.get("description", ""))
            sz = filepath.stat().st_size

            if _channel_match(rel, path_meta, existing)[0]:
                print(f"\n[skip] already on channel: {name}")
                mark_uploaded(args.input, rel)
                continue

            print(f"\n[{total_up + 1}/{len(pending)}] {name}")
            print(f"    File: {rel}  ({fmt_size(sz)})")

            ok, uuid = upload_video(
                base, token, channel_id, filepath, name, desc, nsfw)
            if not ok:
                continue

            print(f"    Uploaded  uuid={uuid}")
            mark_uploaded(args.input, rel)
            total_up += 1
            existing.add(name)

            if uuid:
                batch.append((uuid, name))

        # ── wait for final batch ──
        if batch and not args.skip_wait:
            print(f"\n[+] Waiting for final {len(batch)} video(s) ...")
            for uuid, bname in batch:
                print(f"\n  [{bname}]")
                wait_for_published(base, token, uuid, args.poll_interval)

    except KeyboardInterrupt:
        print(
            f"\n\n[!] Interrupted after {total_up} uploads. Re-run to continue.")
        sys.exit(130)

    print(f"\n{'=' * 50}")
    print(f"  Uploaded: {total_up} video(s)")
    print("  Done!")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    main()
