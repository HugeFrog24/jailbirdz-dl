# config.py
from typing import Final

# How long a cached file size stays valid.  0 = always re-probe; large = effectively forever.
SIZE_CACHE_TTL: Final[int] = 9_999_999  # seconds (~115 days)

SITES: Final[dict[str, dict[str, str]]] = {
    "jailbirdz": {
        "base_url": "https://www.jailbirdz.com",
        "cookie_domain": "jailbirdz.com",
        "env_prefix": "JAILBIRDZ",
    },
    "pinkcuffs": {
        "base_url": "https://www.pinkcuffs.com",
        "cookie_domain": "pinkcuffs.com",
        "env_prefix": "PINKCUFFS",
    },
}
