#!/usr/bin/env python3
"""Download an exact release asset or a direct HTTPS IPA link."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 2 * 1024**3


def normalize_url(url):
    parsed = urllib.parse.urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    if hostname == "dropbox.com" or hostname.endswith(".dropbox.com"):
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query = [(k, v) for k, v in query if k != "dl"]
        query.append(("dl", "1"))
        new_query = urllib.parse.urlencode(query)
        parsed = parsed._replace(query=new_query)
        return urllib.parse.urlunsplit(parsed)
    return url


def check_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Use a direct HTTPS download URL without embedded login credentials")
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    if any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError("Download URLs must resolve to public Internet addresses")


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        check_url(new_url)
        return super().redirect_request(request, fp, code, message, headers, new_url)


def api(endpoint):
    return json.loads(subprocess.check_output(["gh", "api", endpoint], text=True, timeout=120))


def download(output):
    source = os.environ.get("IPA_SOURCE", "release")
    expected = os.environ.get("IPA_SHA256", "").strip().lower()
    if expected and not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("SHA-256 must contain exactly 64 hexadecimal characters")
    output.parent.mkdir(parents=True, exist_ok=True)
    if source == "release":
        repo = os.environ["GITHUB_REPOSITORY"]
        tag = os.environ.get("IPA_RELEASE", "ipa-input")
        name = os.environ.get("IPA_ASSET", "Infuse.ipa")
        if not tag or not name.lower().endswith(".ipa"):
            raise ValueError("Provide a release tag and the exact .ipa asset filename")
        # The tag endpoint only returns published releases. List also finds drafts.
        releases = json.loads(subprocess.check_output(
            ["gh", "api", "--paginate", "--slurp", f"repos/{repo}/releases?per_page=100"],
            text=True, timeout=120))
        matching = [r for page in releases for r in page if r["tag_name"] == tag]
        if len(matching) != 1:
            raise ValueError("Release not found. Save the upload draft with the specified tag")
        assets = api(f"repos/{repo}/releases/{int(matching[0]['id'])}/assets?per_page=100")
        matching_assets = [a for a in assets if a["name"] == name and a["state"] == "uploaded"]
        if len(matching_assets) != 1:
            raise ValueError("IPA asset not found. Use its exact filename after upload completes")
        asset = matching_assets[0]
        if not 0 < asset["size"] <= MAX_BYTES:
            raise ValueError("IPA must be at most 2 GiB")
        with output.open("wb") as target:
            subprocess.run(["gh", "api", f"repos/{repo}/releases/assets/{int(asset['id'])}",
                            "-H", "Accept: application/octet-stream"], stdout=target, check=True, timeout=1200)
        if output.stat().st_size != asset["size"]:
            raise ValueError("Incomplete release asset download")
        digest = asset.get("digest") or ""
        if digest.startswith("sha256:"):
            release_hash = digest.split(":", 1)[1]
            if expected and expected != release_hash:
                raise ValueError("Supplied SHA-256 does not match the release asset digest")
            expected = release_hash
    elif source == "url":
        url = os.environ.get("IPA_URL", "").strip()
        url = normalize_url(url)
        if os.environ.get("GITHUB_ACTIONS") == "true" and url:
            # Mask signed links before anything could print them.
            escaped = url.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print("::add-mask::" + escaped, flush=True)
        check_url(url)
        opener = urllib.request.build_opener(HTTPSRedirect())
        started = time.monotonic()
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "tvOS-IPA-workflow"}), timeout=60) as response:
            if "text/html" in response.headers.get("Content-Type", "").lower():
                raise ValueError("Link returns a web page. Provide the direct IPA download link")
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_BYTES:
                raise ValueError("IPA must be at most 2 GiB")
            total = 0
            with output.open("wb") as target:
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_BYTES or time.monotonic() - started > 1200:
                        raise ValueError("Download exceeded the 2 GiB size or 20 minute time limit")
                    target.write(chunk)
    else:
        raise ValueError("Choose release or url as the IPA source")
    digest = hashlib.sha256()
    with output.open("rb") as target:
        while chunk := target.read(1024 * 1024):
            digest.update(chunk)
    actual = digest.hexdigest()
    if expected and actual != expected:
        raise ValueError("Downloaded IPA failed SHA-256 verification")
    with output.open("rb") as target:
        if target.read(4) != b"PK\x03\x04":
            raise ValueError("Downloaded file is not an IPA/ZIP. Check the direct download link")
    print("Downloaded IPA SHA-256: " + actual)


if __name__ == "__main__":
    try:
        download(Path(sys.argv[1]))
    except urllib.error.HTTPError as error:
        print(f"ERROR: IPA download returned HTTP {error.code}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError:
        print("ERROR: Could not connect to the HTTPS download service", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Avoid printing command arguments or URLs that can contain credentials.
        print("ERROR: " + (str(error) if isinstance(error, ValueError) else "IPA download failed"), file=sys.stderr)
        sys.exit(1)
