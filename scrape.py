# -------------------------------
# Standard library imports
# -------------------------------
import os                # lets us read environment variables (configurable settings)
import logging           # for printing progress/info/errors in a structured way
import boto3             # AWS SDK for Python, lets us talk to S3
import botocore          # low-level AWS errors/exceptions
import requests          # HTTP library for downloading web pages/files
import time              # for adding polite delays between requests
import hashlib           # for computing MD5 checksums if needed
import urllib.robotparser as robotparser  # built-in helper for robots.txt rules
from bs4 import BeautifulSoup             # HTML parser (to find <a href> links)
from urllib.parse import urljoin, urlparse # helpers for working with URLs
from collections import deque             # efficient queue for BFS crawling
from typing import Optional               # for type hints (helps readability)

# -------------------------------
# Logging setup
# -------------------------------
# Instead of using 'print()', we set up a logger.
# This gives timestamps and levels (INFO, WARNING, ERROR).
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("scraper")  # we name this logger "scraper"

# -------------------------------
# Configuration
# -------------------------------
# Instead of hardcoding settings, we pull them from environment variables.
# This way, you can change START_URL, S3 bucket, etc., without editing code.
START_URL = os.getenv("START_URL", "https://planning.lacity.gov/resources/weekly-completed-case-report")
ALLOWED_DOMAINS = [d.strip() for d in os.getenv("ALLOWED_DOMAINS", "planning.lacity.gov/resources").split(",") if d.strip()]
FILE_EXTENSIONS = [e.strip().lower() for e in os.getenv("FILE_EXTENSIONS", "pdf,doc,docx").split(",") if e.strip()]
MAX_PAGES = int(os.getenv("MAX_PAGES", "100"))         # max number of pages to process
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "1.5")) # seconds between requests
TIMEOUT = int(os.getenv("TIMEOUT", "30"))              # how long to wait for a server before giving up

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET = os.getenv("S3_BUCKET", "myscrape1")
S3_PREFIX = os.getenv("S3_PREFIX", "mirror")  # folder prefix in S3 bucket

# Acceptable MIME types (Content-Type header values)
ALLOWED_MIME_PREFIXES = [
    m.strip().lower() for m in os.getenv("ALLOWED_MIME_PREFIXES", "application/pdf , application/msword").split(",") if m.strip()
]

# Prevent accidentally uploading giant files (100 MB default)
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", str(100 * 1024 * 1024)))

# -------------------------------
# AWS S3 client
# -------------------------------
# boto3 will use your credentials (from AWS CLI or env vars) to talk to S3.
s3 = boto3.client("s3", region_name=AWS_REGION)

# -------------------------------
# HTTP session setup
# -------------------------------
# A Session reuses TCP connections, making crawling faster.
# We also set a custom User-Agent to identify ourselves politely.
session = requests.Session()
session.headers.update({
    "User-Agent": "EducationalCrawler/1.0 (+contact: youremail@gmail.com)"
})


# -------------------------------
# Robots.txt support
# -------------------------------
# Websites use robots.txt to tell crawlers what is allowed.
# Example: https://planning.lacity.gov/robots.txt
_robot_cache = {}  # dictionary: origin → parsed robots.txt

def get_robot_parser_for(url: str):
    """Return a RobotFileParser for the site's robots.txt, caching results."""
    parts = urlparse(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    if origin not in _robot_cache:
        rp = robotparser.RobotFileParser()
        rp.set_url(f"{origin}/robots.txt")
        try:
            rp.read()  # download and parse robots.txt
        except Exception:
            # If it fails, just leave rp with no rules (be conservative)
            pass
        _robot_cache[origin] = rp
    return _robot_cache[origin]

def robots_ok(url: str) -> bool:
    """Return True if our crawler is allowed to fetch this URL."""
    rp = get_robot_parser_for(url)
    try:
        return rp.can_fetch(session.headers["User-Agent"], url)
    except Exception:
        logger.warning(f"robots.txt check failed; allowing: {url}")
        return True 

# -------------------------------
# Helper functions
# -------------------------------
def _host(s: str) -> str:
    p=urlparse(s if "://" in s else f"//{s}", scheme="http")
    return (p.hostname or "").lower()

_ALLOWED_HOSTS = {_host(d) for d in ALLOWED_DOMAINS if d.strip()}


def in_allowed_domain(url: str) -> bool:
    """Check if URL’s host matches any of our allowed domains (like arxiv.org)."""
    host = (urlparse(url).hostname or "").lower()
    if not host or not _ALLOWED_HOSTS:
        return False
    return any(host == ah or host.endswith("." + ah) for ah in _ALLOWED_HOSTS )

def looks_like_file(url: str) -> bool:
    """Check if URL ends with a known file extension (e.g., .pdf)."""
    return any(url.lower().split("?", 1)[0].endswith("." + ext) for ext in FILE_EXTENSIONS)

def head_mime_allows(url: str) -> Optional[bool]:
    """
    Do a HEAD request (only headers, no body) to check the Content-Type.
    Example: 'application/pdf' → True.
    Returns True/False if known, None if we can’t tell.
    """
    try:
        r = session.head(url, allow_redirects=True, timeout=TIMEOUT)
        ctype = r.headers.get("Content-Type", "").lower()
        if not ctype:
            return None
        return any(ctype.startswith(prefix) for prefix in ALLOWED_MIME_PREFIXES)
    except Exception:
        return None

def should_download(url: str) -> bool:
    """Return True if URL is a file we want to mirror."""
    if looks_like_file(url):
        return True
    ans = head_mime_allows(url)
    return bool(ans)

def s3_key_for(url: str) -> str:
    """
    Build the S3 key (path inside the bucket) for this URL.
    Example: url=https://planning.lacity.gov/pdf/1234.pdf
             key=mirror/arxiv.org/pdf/1234.pdf
    """
    parsed = urlparse(url)
    path = parsed.path.lstrip("/")
    if not path:  # e.g., https://example.com/
        path = "index"
    return f"{S3_PREFIX}/{parsed.netloc}{('/' + path) if path else ''}"

def already_uploaded_by_etag(url: str, etag: Optional[str]) -> bool:
    """
    Compare the file's ETag from the server with what’s in S3.
    If they match, skip re-uploading (saves bandwidth).
    """
    if not etag:
        return False
    key = s3_key_for(url)
    try:
        head = s3.head_object(Bucket=S3_BUCKET, Key=key)
        existing = head.get("ETag", "").strip('"')
        return existing == etag.strip('"')
    except botocore.exceptions.ClientError as e:
        # If object not found, return False (not uploaded yet).
        if e.response.get("Error", {}).get("Code") in ("404", "NotFound", "NoSuchKey"):
            return False
        return False

def upload_stream_to_s3(url: str, resp: requests.Response):
    """
    Upload file response directly to S3 using a streaming upload.
    - resp must come from requests.get(..., stream=True)
    - we never call resp.content, so the body is not preloaded in memory
    """
    key = s3_key_for(url)
    try:
        resp.raw.decode_content = True  # decompress gzip if needed

        # Check size before upload (if Content-Length is provided)
        clen = resp.headers.get("Content-Length")
        if clen:
            try:
                size = int(clen)
                if size > MAX_FILE_BYTES:
                    logger.info(f"Skip (too large: {size} bytes): {url}")
                    return False
            except ValueError:
                pass

        # Upload to S3 (stream → bucket → key)
        s3.upload_fileobj(
            resp.raw, S3_BUCKET, key,
            ExtraArgs={
                "Metadata": {"Source-URL": url},  # keep original source as metadata
                "ContentType": resp.headers.get("Content-Type", "application/octet-stream")
            }
        )
        logger.info(f"Uploaded: {url} -> s3://{S3_BUCKET}/{key}")
        return True
    except Exception as e:
        logger.error(f"S3 upload failed for {url}: {e}")
        return False

# -------------------------------
# Main crawl loop (Breadth-First Search)
# -------------------------------
def crawl(start_url: str):
    """
    Crawl starting from start_url.
    Steps:
      - take one URL from the queue
      - if it's a file → upload it to S3
      - if it's HTML → parse links and add them to queue
      - repeat until MAX_PAGES reached
    """
    queue = deque([start_url])  # URLs to visit next
    seen = set()                # avoid visiting the same URL twice
    pages = 0
    files = 0

    while queue and pages < MAX_PAGES:
        url = queue.popleft()

        if url in seen:
            continue
        seen.add(url)

        # Only crawl allowed domains
        if not in_allowed_domain(url):
            continue
        # Respect robots.txt rules
        if not robots_ok(url):
            logger.info(f"Blocked by robots.txt: {url}")
            continue

        # Fetch the URL
        try:
            if should_download(url):
                # stream=True for file downloads
                resp = session.get(url, timeout=TIMEOUT, stream=True, allow_redirects=True)
            else:
                # normal GET for HTML pages
                resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception as e:
            logger.error(f"Request failed for {url}: {e}")
            continue

        # Skip if not HTTP 200
        if resp.status_code != 200:
            logger.warning(f"Bad status {resp.status_code} for {url}")
            try:
                resp.close()
            except Exception:
                pass
            continue

        ctype = resp.headers.get("Content-Type", "").lower()

        if should_download(url):
            # If server provides an ETag, use it to avoid duplicates
            etag = resp.headers.get("ETag")
            if already_uploaded_by_etag(url, etag):
                logger.info(f"ETag unchanged; already mirrored: {url}")
                try: resp.close()
                except Exception: pass
            else:
                ok = upload_stream_to_s3(url, resp)
                try: resp.close()
                except Exception: pass
                if ok:
                    files += 1

        elif ctype.startswith("text/html"):
            # For HTML pages, parse and enqueue links
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])  # resolve relative link
                if in_allowed_domain(link) and link not in seen:
                    queue.append(link)

        # else: ignore non-HTML, non-downloadable stuff (like images, CSS)

        pages += 1
        logger.info(f"Processed {pages} pages, {files} files so far")
        time.sleep(REQUEST_DELAY)  # throttle ourselves

    logger.info(f"Done. Pages processed: {pages}, Files uploaded: {files}")

# -------------------------------
# Entry point
# -------------------------------
if __name__ == "__main__":
    logger.info(f"Starting crawl at {START_URL}")

    # Before crawling, check if we can reach the bucket
    try:
        s3.head_bucket(Bucket=S3_BUCKET)
    except botocore.exceptions.ClientError as e:
        logger.error(f"S3 bucket not reachable: s3://{S3_BUCKET} ({e})")

    # Start crawling!
    crawl(START_URL)
