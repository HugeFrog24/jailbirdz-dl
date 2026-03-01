# 𝒥𝒶𝒾𝓁𝒷𝒾𝓇𝒹𝓏-𝒹𝓁

Jailbirdz.com and Pinkcuffs.com are Arizona-based subscription video sites publishing arrest and jail roleplay scenarios featuring women. This tool scrapes the member area of one or both sites, downloads the videos, and re-hosts them on a self-owned PeerTube instance.

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

### Credentials

Set credentials for whichever sites you have a membership on. You don't need both.

**Option A — credentials (recommended):** set `JAILBIRDZ_USERNAME` + `JAILBIRDZ_PASSWORD` (and/or the `PINKCUFFS_*` equivalents) in `.env`. `main.py` logs in automatically on startup.

**Option B — manual cookie:** set `JAILBIRDZ_LOGIN_COOKIE` (and/or `PINKCUFFS_LOGIN_COOKIE`) yourself. Get the value from browser DevTools → Storage → Cookies — copy the full `name=value` of the `wordpress_logged_in_*` cookie.

Sites with no credentials are skipped automatically when running `python main.py`.

### `.env` values

- `JAILBIRDZ_USERNAME` / `JAILBIRDZ_PASSWORD` — jailbirdz.com login.
- `JAILBIRDZ_LOGIN_COOKIE` — jailbirdz.com session cookie (fallback).
- `PINKCUFFS_USERNAME` / `PINKCUFFS_PASSWORD` — pinkcuffs.com login.
- `PINKCUFFS_LOGIN_COOKIE` — pinkcuffs.com session cookie (fallback).
- `PEERTUBE_URL` — base URL of your PeerTube instance.
- `PEERTUBE_USER` — PeerTube username.
- `PEERTUBE_CHANNEL` — channel to upload to.
- `PEERTUBE_PASSWORD` — PeerTube password.

## Workflow

### 1. Scrape

Discovers all post URLs via the WordPress REST API, then visits each page with a headless Firefox browser to intercept video network requests (MP4, MOV, WebM, AVI, M4V).

```bash
python main.py                    # scrape all sites you have credentials for
python main.py --site jailbirdz   # scrape one site only
python main.py --site pinkcuffs --site jailbirdz  # explicit multi-site
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
      --site SITE       Limit to one site (jailbirdz or pinkcuffs); repeatable
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

## CI / Nightly Indexing

`.github/workflows/nightly-index.yml` runs `main.py` at 03:00 UTC daily and commits any new `video_map.json` entries back to the repo.

**One-time setup — add repo secrets for each site you have a membership on:**

```bash
# jailbirdz (if you have a membership)
gh secret set JAILBIRDZ_USERNAME
gh secret set JAILBIRDZ_PASSWORD

# pinkcuffs (if you have a membership)
gh secret set PINKCUFFS_USERNAME
gh secret set PINKCUFFS_PASSWORD
```

**Seed CI with your current progress before the first run:**

```bash
git add video_map.json && git commit -m "chore: seed video_map"
```

**Trigger manually:** Actions → Nightly Index → Run workflow.

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
