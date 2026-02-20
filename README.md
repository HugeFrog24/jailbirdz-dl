# 𝒥𝒶𝒾𝓁𝒷𝒾𝓇𝒹𝓏-𝒹𝓁

Jailbirdz.com is an Arizona-based subscription video site publishing arrest and jail roleplay scenarios featuring women. This tool scrapes the member area, downloads the videos, and re-hosts them on a self-owned PeerTube instance.

> [!NOTE]  
> This tool does not bypass authentication, modify the site, or intercept anything it isn't entitled to. A valid, paid membership is required. The scraper authenticates using your own session cookie and accesses only content your account can already view in a browser.
>
> Downloading content for private, personal use is permitted in many jurisdictions under private copy provisions (e.g., § 53 UrhG in Germany). You are responsible for determining whether this applies in yours.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt`
- `playwright install firefox`

## Setup

```bash
cp .env.example .env
```

### WP_LOGIN_COOKIE

You need to be logged into jailbirdz.com in a browser. Then either:

**Option A — auto (recommended):** let `grab_cookie.py` read it from your browser and write it to `.env` automatically:

```bash
python grab_cookie.py              # tries Firefox, Chrome, Edge, Brave in order
python grab_cookie.py -b firefox   # or target a specific browser
```

> **Note:** Chrome and Edge on Windows 130+ require the script to run as Administrator due to App-bound Encryption. Firefox works without elevated privileges.

**Option B — manual:** open `.env` and set `WP_LOGIN_COOKIE` yourself. Get the value from browser DevTools → Storage → Cookies while on jailbirdz.com — copy the full `name=value` of the `wordpress_logged_in_*` cookie.

### Other `.env` values

- `PEERTUBE_URL` — base URL of your PeerTube instance.
- `PEERTUBE_USER` — PeerTube username.
- `PEERTUBE_CHANNEL` — channel to upload to.
- `PEERTUBE_PASSWORD` — PeerTube password.

## Workflow

### 1. Scrape

Discovers all post URLs via the WordPress REST API, then visits each page with a headless Firefox browser to intercept video network requests (MP4, MOV, WebM, AVI, M4V).

```bash
python main.py
```

Results are written to `video_map.json`. Safe to re-run — already-scraped posts are skipped.

### 2. Download

```bash
python download.py [options]

Options:
  -o, --output DIR      Download directory (default: downloads)
  -t, --titles          Name files by post title
      --original        Name files by original CloudFront filename (default)
      --reorganize      Rename existing files to match current naming mode
  -w, --workers N       Concurrent downloads (default: 4)
  -n, --dry-run         Print what would be downloaded
```

Resumes partial downloads. The chosen naming mode is saved to `.naming_mode` inside the output directory and persists across runs. Filenames that would clash are placed into subfolders.

### 3. Upload

```bash
python upload.py [options]

Options:
  -i, --input DIR           MP4 source directory (default: downloads)
      --url URL             PeerTube instance URL (or set PEERTUBE_URL)
  -U, --username NAME       PeerTube username (or set PEERTUBE_USER)
  -p, --password SECRET     PeerTube password (or set PEERTUBE_PASSWORD)
  -C, --channel NAME        Channel to upload to (or set PEERTUBE_CHANNEL)
  -b, --batch-size N        Videos to upload before waiting for transcoding (default: 1)
      --poll-interval SECS  State poll interval in seconds (default: 30)
      --skip-wait           Upload without waiting for transcoding
      --nsfw                Mark videos as NSFW
  -n, --dry-run             Print what would be uploaded
```

Uploads in resumable 10 MB chunks. After each batch, waits for transcoding and object storage to complete before uploading the next batch — this prevents disk exhaustion on the PeerTube server. Videos already present on the channel (matched by name) are skipped. Progress is tracked in `.uploaded` inside the input directory.

## Utilities

### Check for filename clashes

```bash
python check_clashes.py
```

Lists filenames that map to more than one source URL, with sizes.

### Estimate total download size

```bash
python total_size.py
```

Fetches `Content-Length` for every video URL in `video_map.json` and prints a size summary. Does not download anything.

## Data files

| File             | Location         | Description                                                           |
| ---------------- | ---------------- | --------------------------------------------------------------------- |
| `video_map.json` | project root     | Scraped post URLs mapped to titles, descriptions, and video URLs      |
| `.naming_mode`   | output directory | Saved filename mode (`original` or `title`)                           |
| `.uploaded`      | input directory  | Newline-delimited list of relative paths already uploaded to PeerTube |

## FAQ

**Is this necessary?**  
Yes, obviously.

**Is this project exactly what it looks like?**  
Also yes.

**Why go to all this trouble?**  
Middle school girls bullied me so hard I decided if you're going to be the weird kid anyway, you might as well commit to the bit and build highly specific pipelines for highly specific content.  
Now it's their turn to get booked.  
Checkmate, society.  
No apologies.

**Why not just download everything manually?**  
Dude.  
Bondage fantasy.  
Not pain play.  
Huge difference.  
1,300 clicks = torture.  
Know your genres.

---

This is the most normal thing I've scripted this month.
