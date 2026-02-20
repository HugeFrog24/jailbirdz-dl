import re
import json
import os
import time
import signal
import asyncio
import tempfile
import requests
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse
from dotenv import load_dotenv
from playwright.async_api import async_playwright
from check_clashes import VIDEO_EXTS
from config import BASE_URL

load_dotenv()


def _is_video_url(url):
    """True if `url` ends with a recognised video extension (case-insensitive, path only)."""
    return PurePosixPath(urlparse(url).path).suffix.lower() in VIDEO_EXTS
WP_API = f"{BASE_URL}/wp-json/wp/v2"

SKIP_TYPES = {
    "attachment", "nav_menu_item", "wp_block", "wp_template",
    "wp_template_part", "wp_global_styles", "wp_navigation",
    "wp_font_family", "wp_font_face",
}

VIDEO_MAP_FILE = "video_map.json"
MAX_WORKERS = 4

API_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
    "Accept": "application/json",
    "Referer": f"{BASE_URL}/",
}


def _get_login_cookie():
    raw = os.environ.get("WP_LOGIN_COOKIE", "").strip()  # strip accidental whitespace
    if not raw:
        raise RuntimeError(
            "WP_LOGIN_COOKIE not set. Copy it from your browser into .env — see .env.example.")
    name, _, value = raw.partition("=")
    if not value:
        raise RuntimeError(
            "WP_LOGIN_COOKIE looks malformed (no '=' found). Expected: name=value")
    if not name.startswith("wordpress_logged_in_"):
        raise RuntimeError(
            "WP_LOGIN_COOKIE doesn't look right — expected a wordpress_logged_in_... cookie.")
    return name, value


def discover_content_types(session):
    """Query /wp-json/wp/v2/types and return a list of (name, rest_base, type_slug) for content types worth scraping."""
    r = session.get(f"{WP_API}/types", timeout=30)
    r.raise_for_status()
    types = r.json()

    targets = []
    for type_slug, info in types.items():
        if type_slug in SKIP_TYPES:
            continue
        rest_base = info.get("rest_base")
        name = info.get("name", type_slug)
        if rest_base:
            targets.append((name, rest_base, type_slug))
    return targets


def fetch_all_posts_for_type(session, type_name, rest_base, type_slug):
    """Paginate one content type and return (url, title, description) tuples.
    Uses the `link` field when available; falls back to building from slug."""
    url_prefix = type_slug.replace("_", "-")
    results = []
    page = 1

    while True:
        r = session.get(
            f"{WP_API}/{rest_base}",
            params={"per_page": 100, "page": page},
            timeout=30,
        )
        if r.status_code == 400 or not r.ok:
            break
        data = r.json()
        if not data:
            break
        for post in data:
            link = post.get("link", "")
            if not link.startswith("http"):
                slug = post.get("slug")
                if slug:
                    link = f"{BASE_URL}/{url_prefix}/{slug}/"
                else:
                    continue
            title_obj = post.get("title", {})
            title = title_obj.get("rendered", "") if isinstance(
                title_obj, dict) else str(title_obj)
            content_obj = post.get("content", {})
            content_html = content_obj.get(
                "rendered", "") if isinstance(content_obj, dict) else ""
            description = html_to_text(content_html) if content_html else ""
            results.append((link, title, description))
        print(f"    {type_name} page {page}: {len(data)} items")
        page += 1

    return results


def fetch_post_urls_from_api(headers):
    """Auto-discover all content types via the WP REST API and collect every post URL.
    Also builds video_map.json with titles pre-populated."""
    print("[+] video_map.json empty or missing — discovering content types from REST API…")
    session = requests.Session()
    session.headers.update(headers)

    targets = discover_content_types(session)
    print(
        f"[+] Found {len(targets)} content types: {', '.join(name for name, _, _ in targets)}\n")

    all_results = []
    for type_name, rest_base, type_slug in targets:
        type_results = fetch_all_posts_for_type(
            session, type_name, rest_base, type_slug)
        all_results.extend(type_results)

    seen = set()
    deduped_urls = []
    video_map = load_video_map()

    for url, title, description in all_results:
        if url not in seen and url.startswith("http"):
            seen.add(url)
            deduped_urls.append(url)
            if url not in video_map:
                video_map[url] = {"title": title,
                                  "description": description, "videos": []}
            else:
                if not video_map[url].get("title"):
                    video_map[url]["title"] = title
                if not video_map[url].get("description"):
                    video_map[url]["description"] = description

    save_video_map(video_map)
    print(
        f"\n[+] Discovered {len(deduped_urls)} unique URLs → saved to {VIDEO_MAP_FILE}")
    print(
        f"[+] Pre-populated {len(video_map)} entries in {VIDEO_MAP_FILE}")
    return deduped_urls


def fetch_metadata_from_api(video_map, urls, headers):
    """Populate missing titles and descriptions in video_map from the REST API."""
    missing = [u for u in urls
               if u not in video_map
               or not video_map[u].get("title")
               or not video_map[u].get("description")]
    if not missing:
        return

    print(f"[+] Fetching metadata from REST API for {len(missing)} posts…")
    session = requests.Session()
    session.headers.update(headers)

    targets = discover_content_types(session)

    for type_name, rest_base, type_slug in targets:
        type_results = fetch_all_posts_for_type(
            session, type_name, rest_base, type_slug)
        for url, title, description in type_results:
            if url in video_map:
                if not video_map[url].get("title"):
                    video_map[url]["title"] = title
                if not video_map[url].get("description"):
                    video_map[url]["description"] = description
            else:
                video_map[url] = {"title": title,
                                  "description": description, "videos": []}

    save_video_map(video_map)
    populated_t = sum(1 for u in urls if video_map.get(u, {}).get("title"))
    populated_d = sum(1 for u in urls if video_map.get(
        u, {}).get("description"))
    print(f"[+] Titles populated: {populated_t}/{len(urls)}")
    print(f"[+] Descriptions populated: {populated_d}/{len(urls)}")


def load_post_urls(headers):
    vm = load_video_map()
    if vm:
        print(f"[+] {VIDEO_MAP_FILE} found — loading {len(vm)} post URLs.")
        return list(vm.keys())
    return fetch_post_urls_from_api(headers)


def html_to_text(html_str):
    """Strip HTML tags, decode entities, and collapse whitespace into clean plain text."""
    import html
    text = re.sub(r'<br\s*/?>', '\n', html_str)
    text = text.replace('</p>', '\n\n')
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    lines = [line.strip() for line in text.splitlines()]
    text = '\n'.join(lines)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def extract_mp4_from_html(html):
    candidates = re.findall(r'https?://[^\s"\'<>]+', html)
    return [u for u in candidates if _is_video_url(u)]


def extract_title_from_html(html):
    m = re.search(
        r'<h1[^>]*class="entry-title"[^>]*>(.*?)</h1>', html, re.DOTALL)
    if m:
        title = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        return title
    m = re.search(r'<title>(.*?)(?:\s*[-–|].*)?</title>', html, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None


def load_video_map():
    if Path(VIDEO_MAP_FILE).exists():
        try:
            with open(VIDEO_MAP_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_video_map(video_map):
    fd, tmp_path = tempfile.mkstemp(dir=Path(VIDEO_MAP_FILE).resolve().parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(video_map, f, indent=2, ensure_ascii=False)
        Path(tmp_path).replace(VIDEO_MAP_FILE)
    except Exception:
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass
        raise



def _expects_video(url):
    return "/pinkcuffs-videos/" in url


MAX_RETRIES = 2


async def worker(worker_id, queue, context, known,
                 total, retry_counts, video_map, map_lock, shutdown_event):
    page = await context.new_page()
    video_hits = set()

    page.on("response", lambda resp: video_hits.add(resp.url) if _is_video_url(resp.url) else None)

    try:
        while not shutdown_event.is_set():
            try:
                idx, url = queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            attempt = retry_counts.get(idx, 0)
            label = f" (retry {attempt}/{MAX_RETRIES})" if attempt else ""
            print(f"[W{worker_id}] ({idx + 1}/{total}) {url}{label}")

            try:
                await page.goto(url, wait_until="networkidle", timeout=60000)
            except Exception as e:
                print(f"[W{worker_id}] Navigation error: {e}")
                if _expects_video(url) and attempt < MAX_RETRIES:
                    retry_counts[idx] = attempt + 1
                    queue.put_nowait((idx, url))
                    print(f"[W{worker_id}] Re-queued for retry.")
                elif not _expects_video(url):
                    async with map_lock:
                        entry = video_map.get(url, {})
                        entry["scraped_at"] = int(time.time())
                        video_map[url] = entry
                        save_video_map(video_map)
                else:
                    print(
                        f"[W{worker_id}] Still failing after {MAX_RETRIES} retries — will retry next run.")
                continue

            await asyncio.sleep(1.5)
            html = await page.content()
            title = extract_title_from_html(html)
            html_videos = extract_mp4_from_html(html)
            found = set(html_videos) | set(video_hits)
            video_hits.clear()

            all_videos = [m for m in found if m not in (
                f"{BASE_URL}/wp-content/plugins/easy-video-player/lib/blank.mp4",
            )]

            async with map_lock:
                new_found = found - known
                if new_found:
                    print(f"[W{worker_id}] Found {len(new_found)} new video URLs")
                    known.update(new_found)
                elif all_videos:
                    print(
                        f"[W{worker_id}] {len(all_videos)} video(s) already known — skipping write.")
                else:
                    print(f"[W{worker_id}] No video found on page.")

                entry = video_map.get(url, {})
                if title:
                    entry["title"] = title
                existing_videos = set(entry.get("videos", []))
                existing_videos.update(all_videos)
                entry["videos"] = sorted(existing_videos)
                mark_done = bool(all_videos) or not _expects_video(url)
                if mark_done:
                    entry["scraped_at"] = int(time.time())
                video_map[url] = entry
                save_video_map(video_map)

            if not mark_done:
                if attempt < MAX_RETRIES:
                    retry_counts[idx] = attempt + 1
                    queue.put_nowait((idx, url))
                    print(
                        f"[W{worker_id}] Re-queued for retry ({attempt + 1}/{MAX_RETRIES}).")
                else:
                    print(
                        f"[W{worker_id}] No video after {MAX_RETRIES} retries — will retry next run.")
    finally:
        await page.close()


async def run():
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _handle_shutdown(signum, _frame):
        print(f"\n[!] Signal {signum} received — finishing active pages then exiting…")
        loop.call_soon_threadsafe(shutdown_event.set)

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    try:
        cookie_name, cookie_value = _get_login_cookie()
        req_headers = {
            **API_HEADERS,
            "Cookie": f"{cookie_name}={cookie_value}; eav-age-verified=1",
        }

        urls = load_post_urls(req_headers)

        video_map = load_video_map()
        if any(u not in video_map
               or not video_map[u].get("title")
               or not video_map[u].get("description")
               for u in urls if _expects_video(u)):
            fetch_metadata_from_api(video_map, urls, req_headers)

        known = {u for entry in video_map.values() for u in entry.get("videos", [])}

        total = len(urls)
        pending = []
        needs_map = 0
        for i, u in enumerate(urls):
            entry = video_map.get(u, {})
            if not entry.get("scraped_at"):
                pending.append((i, u))
            elif _expects_video(u) and not entry.get("videos"):
                pending.append((i, u))
                needs_map += 1

        done_count = sum(1 for v in video_map.values() if v.get("scraped_at"))
        print(f"[+] Loaded {total} post URLs.")
        print(f"[+] Already have {len(known)} video URLs mapped.")
        print(f"[+] Video map: {len(video_map)} entries in {VIDEO_MAP_FILE}")
        if done_count:
            remaining_new = len(pending) - needs_map
            print(
                f"[↻] Resuming: {done_count} done, {remaining_new} new + {needs_map} needing map data.")
        if not pending:
            print("[✓] All URLs already processed and mapped.")
            return

        print(
            f"[⚡] Running with {min(MAX_WORKERS, len(pending))} concurrent workers.\n")

        queue = asyncio.Queue()
        for item in pending:
            queue.put_nowait(item)

        map_lock = asyncio.Lock()
        retry_counts = {}

        async with async_playwright() as p:
            browser = await p.firefox.launch(headless=True)
            context = await browser.new_context()

            _cookie_domain = urlparse(BASE_URL).netloc
            site_cookies = [
                {
                    "name": cookie_name,
                    "value": cookie_value,
                    "domain": _cookie_domain,
                    "path": "/",
                    "httpOnly": True,
                    "secure": True,
                    "sameSite": "None"
                },
                {
                    "name": "eav-age-verified",
                    "value": "1",
                    "domain": _cookie_domain,
                    "path": "/"
                }
            ]

            await context.add_cookies(site_cookies)

            num_workers = min(MAX_WORKERS, len(pending))
            workers = [
                asyncio.create_task(
                    worker(i, queue, context, known,
                           total, retry_counts, video_map, map_lock, shutdown_event)
                )
                for i in range(num_workers)
            ]

            await asyncio.gather(*workers)
            await browser.close()

        mapped = sum(1 for v in video_map.values() if v.get("videos"))
        print(
            f"\n[+] Video map: {mapped} posts with videos, {len(video_map)} total entries.")

        if not shutdown_event.is_set():
            print(f"[✓] Completed. Full map in {VIDEO_MAP_FILE}")
        else:
            done = sum(1 for v in video_map.values() if v.get("scraped_at"))
            print(f"[⏸] Paused — {done}/{total} done. Run again to resume.")
    finally:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)


def main():
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Run again to resume.")
    except RuntimeError as e:
        raise SystemExit(f"[!] {e}")


if __name__ == "__main__":
    main()
