import argparse
import re
import os
import time
import signal
import asyncio
import requests
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse
from dotenv import load_dotenv
from playwright.async_api import async_playwright, BrowserContext
from check_clashes import (
    VIDEO_EXTS,
    load_video_map,
    save_video_map,
    is_valid_url,
    expects_video,
)
from config import SITES
from grab_cookie import login_and_get_cookie, update_env

load_dotenv()


def _is_video_url(url: str) -> bool:
    """True if `url` ends with a recognised video extension (case-insensitive, path only)."""
    return PurePosixPath(urlparse(url).path).suffix.lower() in VIDEO_EXTS


SKIP_TYPES = {
    "attachment",
    "nav_menu_item",
    "wp_block",
    "wp_template",
    "wp_template_part",
    "wp_global_styles",
    "wp_navigation",
    "wp_font_family",
    "wp_font_face",
}

MAX_WORKERS = 4

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0"
)


def _api_headers(base_url: str, cookie_name: str, cookie_value: str) -> dict[str, str]:
    return {
        "User-Agent": _USER_AGENT,
        "Accept": "application/json",
        "Referer": f"{base_url}/",
        "Cookie": f"{cookie_name}={cookie_value}; eav-age-verified=1",
    }


def _select_probe_url(video_map: dict[str, Any]) -> str | None:
    """Pure function: return the first URL in video_map where expects_video() is True."""
    return next((url for url in video_map if expects_video(url)), None)


def _probe_cookie(name: str, value: str, site_key: str) -> bool:
    """HEAD request to a members-only video page. Returns True if the cookie is still valid."""
    video_map = load_video_map(site_key)
    probe_url = _select_probe_url(video_map)
    if probe_url is None:
        return False  # no video URLs yet — can't validate, fall through to re-auth
    r = requests.head(
        probe_url,
        headers={"Cookie": f"{name}={value}", "User-Agent": _USER_AGENT},
        allow_redirects=False,
        timeout=10,
    )
    return r.status_code == 200


def _get_login_cookie(site_key: str, site_cfg: dict[str, str]) -> tuple[str, str]:
    env_prefix = site_cfg["env_prefix"]
    base_url = site_cfg["base_url"]
    env_key = f"{env_prefix}_LOGIN_COOKIE"

    username = os.environ.get(f"{env_prefix}_USERNAME", "").strip()
    password = os.environ.get(f"{env_prefix}_PASSWORD", "").strip()
    has_credentials = bool(username and password)

    raw = os.environ.get(env_key, "").strip()
    if raw:
        name, _, value = raw.partition("=")
        if value and name.startswith("wordpress_logged_in_"):
            if not has_credentials:
                return name, value  # cookie-only mode — trust it
            print(f"[{site_key}] Cookie found — validating…")
            if _probe_cookie(name, value, site_key):
                print(f"[{site_key}] Cookie still valid — skipping login.")
                return name, value
            print(f"[{site_key}] Cookie expired — re-authenticating…")

    if has_credentials:
        cookie_name, cookie_value = login_and_get_cookie(username, password, base_url)
        action = update_env(cookie_name, cookie_value, env_key=env_key)
        print(f"[{site_key}] Logged in: {cookie_name} ({action} in .env)")
        return cookie_name, cookie_value

    raise RuntimeError(
        f"No credentials or cookie found for {site_key}. Set either:\n"
        f"  • {env_prefix}_USERNAME + {env_prefix}_PASSWORD  (recommended)\n"
        f"  • {env_prefix}_LOGIN_COOKIE                      (fallback — may expire)\n"
        "See .env.example."
    )


def _has_credentials(site_cfg: dict[str, str]) -> bool:
    env_prefix = site_cfg["env_prefix"]
    has_cookie = bool(os.environ.get(f"{env_prefix}_LOGIN_COOKIE", "").strip())
    has_creds = bool(
        os.environ.get(f"{env_prefix}_USERNAME", "").strip()
        and os.environ.get(f"{env_prefix}_PASSWORD", "").strip()
    )
    return has_cookie or has_creds


def discover_content_types(
    session: requests.Session, wp_api: str
) -> list[tuple[str, str, str]]:
    """Query /wp-json/wp/v2/types and return a list of (name, rest_base, type_slug)."""
    r = session.get(f"{wp_api}/types", timeout=30)
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


def fetch_all_posts_for_type(
    session: requests.Session,
    wp_api: str,
    base_url: str,
    type_name: str,
    rest_base: str,
    type_slug: str,
) -> list[tuple[str, str, str]]:
    """Paginate one content type and return (url, title, description) tuples."""
    url_prefix = type_slug.replace("_", "-")
    results = []
    page = 1

    while True:
        r = session.get(
            f"{wp_api}/{rest_base}",
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
                    link = f"{base_url}/{url_prefix}/{slug}/"
                else:
                    continue
            title_obj = post.get("title", {})
            title = (
                title_obj.get("rendered", "")
                if isinstance(title_obj, dict)
                else str(title_obj)
            )
            content_obj = post.get("content", {})
            content_html = (
                content_obj.get("rendered", "") if isinstance(content_obj, dict) else ""
            )
            description = html_to_text(content_html) if content_html else ""
            results.append((link, title, description))
        print(f"    {type_name} page {page}: {len(data)} items")
        page += 1

    return results


def fetch_post_urls_from_api(
    site_key: str,
    base_url: str,
    wp_api: str,
    headers: dict[str, str],
) -> list[str]:
    """Auto-discover all content types via the WP REST API and collect every post URL.
    Also pre-populates video_map.json with titles."""
    print(f"[{site_key}] video_map empty — discovering content types from REST API…")
    session = requests.Session()
    session.headers.update(headers)

    targets = discover_content_types(session, wp_api)
    print(
        f"[{site_key}] Found {len(targets)} content types: "
        f"{', '.join(name for name, _, _ in targets)}\n"
    )

    all_results = []
    for type_name, rest_base, type_slug in targets:
        type_results = fetch_all_posts_for_type(
            session, wp_api, base_url, type_name, rest_base, type_slug
        )
        all_results.extend(type_results)

    seen: set[str] = set()
    deduped_urls = []
    video_map = load_video_map(site_key)

    for url, title, description in all_results:
        if url not in seen and url.startswith("http"):
            seen.add(url)
            deduped_urls.append(url)
            if url not in video_map:
                video_map[url] = {
                    "title": title,
                    "description": description,
                    "videos": [],
                }
            else:
                if not video_map[url].get("title"):
                    video_map[url]["title"] = title
                if not video_map[url].get("description"):
                    video_map[url]["description"] = description

    save_video_map(video_map, site_key)
    print(
        f"\n[{site_key}] Discovered {len(deduped_urls)} unique URLs → saved to video_map.json"
    )
    print(f"[{site_key}] Pre-populated {len(video_map)} entries")
    return deduped_urls


def fetch_metadata_from_api(
    site_key: str,
    base_url: str,
    wp_api: str,
    video_map: dict[str, Any],
    urls: list[str],
    headers: dict[str, str],
) -> None:
    """Populate missing titles and descriptions in video_map from the REST API."""
    missing = [
        u
        for u in urls
        if u not in video_map
        or not video_map[u].get("title")
        or not video_map[u].get("description")
    ]
    if not missing:
        return

    print(f"[{site_key}] Fetching metadata from REST API for {len(missing)} posts…")
    session = requests.Session()
    session.headers.update(headers)

    targets = discover_content_types(session, wp_api)

    for type_name, rest_base, type_slug in targets:
        type_results = fetch_all_posts_for_type(
            session, wp_api, base_url, type_name, rest_base, type_slug
        )
        for url, title, description in type_results:
            if url in video_map:
                if not video_map[url].get("title"):
                    video_map[url]["title"] = title
                if not video_map[url].get("description"):
                    video_map[url]["description"] = description
            else:
                video_map[url] = {
                    "title": title,
                    "description": description,
                    "videos": [],
                }

    save_video_map(video_map, site_key)
    populated_t = sum(1 for u in urls if video_map.get(u, {}).get("title"))
    populated_d = sum(1 for u in urls if video_map.get(u, {}).get("description"))
    print(f"[{site_key}] Titles populated: {populated_t}/{len(urls)}")
    print(f"[{site_key}] Descriptions populated: {populated_d}/{len(urls)}")


def load_post_urls(
    site_key: str,
    base_url: str,
    wp_api: str,
    headers: dict[str, str],
) -> list[str]:
    vm = load_video_map(site_key)
    if vm:
        print(f"[{site_key}] video_map found — loading {len(vm)} post URLs.")
        return list(vm.keys())
    return fetch_post_urls_from_api(site_key, base_url, wp_api, headers)


def html_to_text(html_str: str) -> str:
    """Strip HTML tags, decode entities, and collapse whitespace into clean plain text."""
    import html

    text = re.sub(r"<br\s*/?>", "\n", html_str)
    text = text.replace("</p>", "\n\n")
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    lines = [line.strip() for line in text.splitlines()]
    text = "\n".join(lines)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_mp4_from_html(html: str) -> list[str]:
    candidates = re.findall(r'https?://[^\s"\'<>]+', html)
    return [u for u in candidates if _is_video_url(u)]


def extract_title_from_html(html: str) -> str | None:
    m = re.search(r'<h1[^>]*class="entry-title"[^>]*>(.*?)</h1>', html, re.DOTALL)
    if m:
        title = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        return title
    m = re.search(r"<title>(.*?)(?:\s*[-–|].*)?</title>", html, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None


MAX_RETRIES = 2


async def worker(
    worker_id: int,
    queue: asyncio.Queue[tuple[int, str]],
    context: BrowserContext,
    known: set[str],
    total: int,
    retry_counts: dict[int, int],
    video_map: dict[str, Any],
    map_lock: asyncio.Lock,
    shutdown_event: asyncio.Event,
    reauth_lock: asyncio.Lock,
    reauth_done: list[bool],
    site_key: str,
    site_cfg: dict[str, str],
) -> None:
    base_url = site_cfg["base_url"]
    cookie_domain = urlparse(base_url).hostname or site_cfg["cookie_domain"]
    env_prefix = site_cfg["env_prefix"]
    page = await context.new_page()
    video_hits: set[str] = set()

    page.on(
        "response",
        lambda resp: video_hits.add(resp.url) if _is_video_url(resp.url) else None,
    )

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
                if expects_video(url) and attempt < MAX_RETRIES:
                    retry_counts[idx] = attempt + 1
                    queue.put_nowait((idx, url))
                    print(f"[W{worker_id}] Re-queued for retry.")
                elif not expects_video(url):
                    async with map_lock:
                        entry = video_map.get(url, {})
                        entry["scraped_at"] = int(time.time())
                        video_map[url] = entry
                        save_video_map(video_map, site_key)
                else:
                    print(
                        f"[W{worker_id}] Still failing after {MAX_RETRIES} retries — will retry next run."
                    )
                continue

            if "NoDirectAccessAllowed" in page.url:
                recovered = False
                async with reauth_lock:
                    if not reauth_done[0]:
                        username = os.environ.get(f"{env_prefix}_USERNAME", "").strip()
                        password = os.environ.get(f"{env_prefix}_PASSWORD", "").strip()
                        if username and password:
                            print(f"[W{worker_id}] Cookie expired — re-authenticating…")
                            try:
                                new_name, new_value = await asyncio.to_thread(
                                    login_and_get_cookie, username, password, base_url
                                )
                                update_env(
                                    new_name,
                                    new_value,
                                    env_key=f"{env_prefix}_LOGIN_COOKIE",
                                )
                                await context.add_cookies(
                                    [
                                        {
                                            "name": new_name,
                                            "value": new_value,
                                            "domain": cookie_domain,
                                            "path": "/",
                                            "httpOnly": True,
                                            "secure": True,
                                            "sameSite": "None",
                                        }
                                    ]
                                )
                                reauth_done[0] = True
                                recovered = True
                                print(f"[W{worker_id}] Re-auth succeeded — re-queuing.")
                            except Exception as e:
                                print(f"[W{worker_id}] Re-auth failed: {e}")
                                shutdown_event.set()
                        else:
                            print(
                                f"[W{worker_id}] Cookie expired. "
                                f"Set {env_prefix}_USERNAME + {env_prefix}_PASSWORD "
                                "in .env for auto re-auth."
                            )
                            shutdown_event.set()
                    else:
                        recovered = True  # another worker already re-authed
                if recovered:
                    queue.put_nowait((idx, url))
                continue

            await asyncio.sleep(1.5)
            html = await page.content()
            title = extract_title_from_html(html)
            html_videos = extract_mp4_from_html(html)
            found = set(html_videos) | set(video_hits)
            video_hits.clear()

            all_videos = [
                m
                for m in found
                if is_valid_url(m)
                and m
                not in (
                    f"{base_url}/wp-content/plugins/easy-video-player/lib/blank.mp4",
                )
            ]

            async with map_lock:
                new_found = found - known
                if new_found:
                    print(f"[W{worker_id}] Found {len(new_found)} new video URLs")
                    known.update(new_found)
                elif all_videos:
                    print(
                        f"[W{worker_id}] {len(all_videos)} video(s) already known — skipping write."
                    )
                else:
                    print(f"[W{worker_id}] No video found on page.")

                entry = video_map.get(url, {})
                if title:
                    entry["title"] = title
                existing_dict: dict[str, Any] = {
                    vid["url"]: vid for vid in entry.get("videos", [])
                }
                for vid_url in all_videos:
                    if vid_url not in existing_dict:
                        existing_dict[vid_url] = {"url": vid_url}
                entry["videos"] = sorted(existing_dict.values(), key=lambda v: v["url"])
                mark_done = bool(all_videos) or not expects_video(url)
                if mark_done:
                    entry["scraped_at"] = int(time.time())
                video_map[url] = entry
                save_video_map(video_map, site_key)

            if not mark_done:
                if attempt < MAX_RETRIES:
                    retry_counts[idx] = attempt + 1
                    queue.put_nowait((idx, url))
                    print(
                        f"[W{worker_id}] Re-queued for retry ({attempt + 1}/{MAX_RETRIES})."
                    )
                else:
                    print(
                        f"[W{worker_id}] No video after {MAX_RETRIES} retries — will retry next run."
                    )
    finally:
        await page.close()


async def run_for_site(
    site_key: str,
    site_cfg: dict[str, str],
    shutdown_event: asyncio.Event,
) -> None:
    base_url = site_cfg["base_url"]
    cookie_domain = urlparse(base_url).hostname or site_cfg["cookie_domain"]
    wp_api = f"{base_url}/wp-json/wp/v2"

    cookie_name, cookie_value = _get_login_cookie(site_key, site_cfg)
    req_headers = _api_headers(base_url, cookie_name, cookie_value)

    urls = load_post_urls(site_key, base_url, wp_api, req_headers)

    video_map = load_video_map(site_key)
    if any(
        u not in video_map
        or not video_map[u].get("title")
        or not video_map[u].get("description")
        for u in urls
        if expects_video(u)
    ):
        fetch_metadata_from_api(
            site_key, base_url, wp_api, video_map, urls, req_headers
        )

    known = {
        vid["url"] for entry in video_map.values() for vid in entry.get("videos", [])
    }

    total = len(urls)
    pending = []
    needs_map = 0
    for i, u in enumerate(urls):
        entry = video_map.get(u, {})
        if not entry.get("scraped_at"):
            pending.append((i, u))
        elif expects_video(u) and not entry.get("videos"):
            pending.append((i, u))
            needs_map += 1

    done_count = sum(1 for v in video_map.values() if v.get("scraped_at"))
    print(f"[{site_key}] Loaded {total} post URLs.")
    print(f"[{site_key}] Already have {len(known)} video URLs mapped.")
    print(f"[{site_key}] Video map: {len(video_map)} entries in video_map.json")
    if done_count:
        remaining_new = len(pending) - needs_map
        print(
            f"[{site_key}] Resuming: {done_count} done, "
            f"{remaining_new} new + {needs_map} needing map data."
        )
    if not pending:
        print(f"[{site_key}] All URLs already processed and mapped.")
        return

    print(
        f"[{site_key}] Running with {min(MAX_WORKERS, len(pending))} concurrent workers.\n"
    )

    queue: asyncio.Queue[tuple[int, str]] = asyncio.Queue()
    for item in pending:
        queue.put_nowait(item)

    map_lock = asyncio.Lock()
    reauth_lock = asyncio.Lock()
    reauth_done: list[bool] = [False]
    retry_counts: dict[int, int] = {}

    async with async_playwright() as p:
        browser = await p.firefox.launch(headless=True)
        context = await browser.new_context()

        site_cookies = [
            {
                "name": cookie_name,
                "value": cookie_value,
                "domain": cookie_domain,
                "path": "/",
                "httpOnly": True,
                "secure": True,
                "sameSite": "None",
            },
            {
                "name": "eav-age-verified",
                "value": "1",
                "domain": cookie_domain,
                "path": "/",
            },
        ]

        await context.add_cookies(site_cookies)  # type: ignore[arg-type]

        num_workers = min(MAX_WORKERS, len(pending))
        workers = [
            asyncio.create_task(
                worker(
                    i,
                    queue,
                    context,
                    known,
                    total,
                    retry_counts,
                    video_map,
                    map_lock,
                    shutdown_event,
                    reauth_lock,
                    reauth_done,
                    site_key,
                    site_cfg,
                )
            )
            for i in range(num_workers)
        ]

        await asyncio.gather(*workers)
        await browser.close()

    mapped = sum(1 for v in video_map.values() if v.get("videos"))
    print(
        f"\n[{site_key}] Video map: {mapped} posts with videos, {len(video_map)} total entries."
    )

    if not shutdown_event.is_set():
        print(f"[{site_key}] Completed. Full map in video_map.json")
    else:
        done = sum(1 for v in video_map.values() if v.get("scraped_at"))
        print(f"[{site_key}] Paused — {done}/{total} done. Run again to resume.")


async def run(selected_sites: list[str], explicit: bool) -> None:
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _handle_shutdown(signum: int, _: object) -> None:
        print(f"\n[!] Signal {signum} received — finishing active pages then exiting…")
        loop.call_soon_threadsafe(shutdown_event.set)

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    try:
        for site_key in selected_sites:
            if shutdown_event.is_set():
                break
            site_cfg = SITES[site_key]
            if not _has_credentials(site_cfg):
                if explicit:
                    raise RuntimeError(
                        f"No credentials or cookie found for {site_key}. See .env.example."
                    )
                print(f"[{site_key}] No credentials found — skipping.")
                continue
            print(f"\n{'=' * 60}")
            print(f"  Site: {site_key}  ({site_cfg['base_url']})")
            print(f"{'=' * 60}\n")
            await run_for_site(site_key, site_cfg, shutdown_event)
    finally:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scrape video URLs from member sites")
    parser.add_argument(
        "--site",
        action="append",
        choices=list(SITES.keys()),
        dest="sites",
        metavar="SITE",
        help=f"Site(s) to scrape (default: all). Can be repeated. Choices: {', '.join(SITES)}",
    )
    args = parser.parse_args()
    explicit = bool(args.sites)
    selected = args.sites or list(SITES.keys())

    try:
        asyncio.run(run(selected, explicit))
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Run again to resume.")
    except RuntimeError as e:
        raise SystemExit(f"[!] {e}")


if __name__ == "__main__":
    main()
