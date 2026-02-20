#!/usr/bin/env python3
"""
grab_cookie.py — read the WordPress login cookie from an
installed browser and write it to .env as WP_LOGIN_COOKIE=name=value.

Usage:
    python grab_cookie.py                        # tries Firefox, Chrome, Edge, Brave
    python grab_cookie.py --browser firefox      # explicit browser
"""

import argparse
from pathlib import Path
from config import COOKIE_DOMAIN

ENV_FILE = Path(".env")
ENV_KEY = "WP_LOGIN_COOKIE"
COOKIE_PREFIX = "wordpress_logged_in_"

BROWSER_NAMES = ["firefox", "chrome", "edge", "brave"]


def find_cookie(browser_name):
    """Return (name, value) for the wordpress_logged_in_* cookie, or (None, None)."""
    try:
        import rookiepy
    except ImportError:
        raise ImportError("rookiepy not installed — run: pip install rookiepy")

    fn = getattr(rookiepy, browser_name, None)
    if fn is None:
        raise ValueError(f"rookiepy does not support '{browser_name}'.")

    try:
        cookies = fn([COOKIE_DOMAIN])
    except PermissionError:
        raise PermissionError(
            f"Permission denied reading {browser_name} cookies.\n"
            "    Close the browser, or on Windows run as Administrator for Chrome/Edge."
        )
    except Exception as e:
        raise RuntimeError(f"Could not read {browser_name} cookies: {e}")

    for c in cookies:
        if c.get("name", "").startswith(COOKIE_PREFIX):
            return c["name"], c["value"]

    return None, None


def update_env(name, value):
    """Write WP_LOGIN_COOKIE=name=value into .env, replacing any existing line."""
    new_line = f"{ENV_KEY}={name}={value}\n"

    if ENV_FILE.exists():
        text = ENV_FILE.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        for i, line in enumerate(lines):
            if line.startswith(f"{ENV_KEY}=") or line.strip() == ENV_KEY:
                lines[i] = new_line
                ENV_FILE.write_text("".join(lines), encoding="utf-8")
                return "updated"
        # Key not present — append
        if text and not text.endswith("\n"):
            text += "\n"
        ENV_FILE.write_text(text + new_line, encoding="utf-8")
        return "appended"
    else:
        ENV_FILE.write_text(new_line, encoding="utf-8")
        return "created"


def main():
    parser = argparse.ArgumentParser(
        description=f"Copy the {COOKIE_DOMAIN} login cookie from your browser into .env."
    )
    parser.add_argument(
        "--browser", "-b",
        choices=BROWSER_NAMES,
        metavar="BROWSER",
        help=f"Browser to read from: {', '.join(BROWSER_NAMES)} (default: try all in order)",
    )
    args = parser.parse_args()

    order = [args.browser] if args.browser else BROWSER_NAMES

    cookie_name = cookie_value = None
    for browser in order:
        print(f"[…] Trying {browser}…")
        try:
            cookie_name, cookie_value = find_cookie(browser)
        except ImportError as e:
            raise SystemExit(f"[!] {e}")
        except (ValueError, PermissionError, RuntimeError) as e:
            print(f"[!] {e}")
            continue

        if cookie_name:
            print(f"[+] Found in {browser}: {cookie_name}")
            break
        print(f"    No {COOKIE_PREFIX}* cookie found in {browser}.")

    if not cookie_name:
        raise SystemExit(
            f"\n[!] No {COOKIE_PREFIX}* cookie found in any browser.\n"
            f"    Make sure you are logged into {COOKIE_DOMAIN}, then re-run.\n"
            "    Or set WP_LOGIN_COOKIE manually in .env — see .env.example."
        )

    action = update_env(cookie_name, cookie_value)
    print(f"[✓] {ENV_KEY} {action} in {ENV_FILE}.")


if __name__ == "__main__":
    main()
