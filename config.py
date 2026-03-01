# config.py
from typing import Final

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
