#!/usr/bin/env python3
"""
grab_cookie.py — log in to a site and write the session cookie to .env.

Requires {SITE}_USERNAME and {SITE}_PASSWORD to be set in the environment or .env.

Usage:
    python grab_cookie.py --site jailbirdz
    python grab_cookie.py --site pinkcuffs
"""

import argparse
import os
from pathlib import Path
from typing import Literal
import requests
from config import SITES

ENV_FILE = Path(".env")
COOKIE_PREFIX = "wordpress_logged_in_"


def update_env(
    name: str,
    value: str,
    env_key: str = "WP_LOGIN_COOKIE",
    path: Path = ENV_FILE,
) -> Literal["updated", "appended", "created"]:
    """Write env_key=name=value into the env file, replacing any existing line."""
    new_line = f"{env_key}={name}={value}\n"

    if path.exists():
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        for i, line in enumerate(lines):
            key, sep, _ = line.partition("=")
            if key.strip() == env_key and sep:
                lines[i] = new_line
                path.write_text("".join(lines), encoding="utf-8")
                return "updated"
        # Key not present — append
        if text and not text.endswith("\n"):
            text += "\n"
        path.write_text(text + new_line, encoding="utf-8")
        return "appended"
    else:
        path.write_text(new_line, encoding="utf-8")
        return "created"


def login_and_get_cookie(
    username: str, password: str, base_url: str
) -> tuple[str, str]:
    """POST to wp-admin/admin-ajax.php (xootix action) and return (cookie_name, cookie_value).

    No browser needed — the xootix login endpoint takes plain form fields and returns
    the wordpress_logged_in_* cookie directly in the response Set-Cookie headers.
    """
    session = requests.Session()
    r = session.post(
        f"{base_url}/wp-admin/admin-ajax.php",
        data={
            "xoo-el-username": username,
            "xoo-el-password": password,
            "xoo-el-rememberme": "forever",
            "_xoo_el_form": "login",
            "xoo_el_redirect": "/",
            "action": "xoo_el_form_action",
            "display": "popup",
        },
        headers={
            "Referer": f"{base_url}/",
            "Origin": base_url,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
        },
        timeout=30,
    )
    r.raise_for_status()
    result = r.json()
    if result.get("error"):
        raise RuntimeError(f"Login rejected by server: {result.get('notice', result)}")

    for name, value in session.cookies.items():
        if name.startswith(COOKIE_PREFIX):
            return name, value

    raise RuntimeError(
        "Server accepted login but no wordpress_logged_in_* cookie was set.\n"
        "    Check that username and password are correct."
    )


def _auto_login() -> None:
    parser = argparse.ArgumentParser(
        description="Log in and save session cookie to .env"
    )
    parser.add_argument(
        "--site",
        required=True,
        choices=list(SITES.keys()),
        help="Which site to authenticate with",
    )
    args = parser.parse_args()

    site_cfg = SITES[args.site]
    env_prefix = site_cfg["env_prefix"]
    base_url = site_cfg["base_url"]
    env_key = f"{env_prefix}_LOGIN_COOKIE"

    username = os.environ.get(f"{env_prefix}_USERNAME", "").strip()
    password = os.environ.get(f"{env_prefix}_PASSWORD", "").strip()
    if not username or not password:
        raise SystemExit(
            f"[!] {env_prefix}_USERNAME and {env_prefix}_PASSWORD must be set "
            "in the environment or .env — see .env.example."
        )
    try:
        cookie_name, cookie_value = login_and_get_cookie(username, password, base_url)
    except RuntimeError as e:
        raise SystemExit(f"[!] {e}")
    print(f"[+] Login succeeded: {cookie_name}")
    action = update_env(cookie_name, cookie_value, env_key=env_key)
    print(f"[✓] {env_key} {action} in {ENV_FILE}.")


def main() -> None:
    _auto_login()


if __name__ == "__main__":
    main()
