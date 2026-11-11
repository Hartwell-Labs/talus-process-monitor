"""talus-monitor: installer/runner for the Talus eBPF ransomware agent.

Downloads the official prebuilt `process-monitor` binary from the
talus-process-monitor GitHub releases and runs it. Pure stdlib.
"""
import argparse
import hashlib
import json
import os
import stat
import sys
import urllib.request
from pathlib import Path

REPO = "BartoszOsiej/talus-process-monitor"
RELEASES_URL = f"https://github.com/{REPO}/releases/latest"
BIN_DIR = Path.home() / ".talus" / "bin"
BIN_PATH = BIN_DIR / "process-monitor"
WRAPPER_VERSION = "0.8.0"

UA = {"User-Agent": "talus-pypi-wrapper", "Accept": "application/vnd.github+json"}


def gh_latest():
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/releases/latest", headers=UA
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def pick_asset(rel):
    for a in rel.get("assets", []):
        if a["name"] == "process-monitor":
            return a
    for a in rel.get("assets", []):
        n = a["name"].lower()
        if n.startswith("process-monitor") and not n.endswith(
            (".md", ".json", ".jsonl", ".txt", ".sig", ".spdx.json")
        ):
            return a
    return None


def expected_sha256(text, name):
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        digest, filename = parts[0].lower(), parts[1].lstrip("*")
        if filename == name and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
            return digest
    return None


def do_install(_args):
    rel = gh_latest()
    tag = rel.get("tag_name", "?")
    asset = pick_asset(rel)
    if not asset:
        sys.exit(f"No prebuilt 'process-monitor' asset in {tag}. Get it from: {RELEASES_URL}")

    # Refuse an unverified download: the checksum lives in the same release, so
    # it catches corruption and a swapped asset, and keeps the wrapper honest.
    sums = next(
        (a for a in rel.get("assets", []) if a["name"] == "checksums-sha256.txt"),
        None,
    )
    if not sums:
        sys.exit(f"Release {tag} has no checksums-sha256.txt; refusing to install an unverified binary.")
    sums_req = urllib.request.Request(
        sums["browser_download_url"], headers={"User-Agent": "talus-pypi-wrapper"}
    )
    with urllib.request.urlopen(sums_req, timeout=60) as r:
        expected = expected_sha256(r.read().decode("utf-8", "replace"), asset["name"])
    if not expected:
        sys.exit(f"No checksum for {asset['name']} in {tag}; refusing to install.")

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    tmp = BIN_DIR / ".download.tmp"
    print(f"talus-monitor: downloading {tag} ({asset['name']}, {asset.get('size', 0)//1024} KB)...")
    req = urllib.request.Request(asset["browser_download_url"], headers={"User-Agent": "talus-pypi-wrapper"})
    digest = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=300) as r, open(tmp, "wb") as f:
        for chunk in iter(lambda: r.read(1024 * 1024), b""):
            digest.update(chunk)
            f.write(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        tmp.unlink(missing_ok=True)
        sys.exit(f"checksum mismatch for {asset['name']}: expected {expected}, got {actual}; nothing installed")
    print(f"talus-monitor: sha256 verified ({actual})")
    tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    tmp.replace(BIN_PATH)
    print(f"Installed {tag} -> {BIN_PATH}")
    print("Next steps:")
    print(f"  Self-check:   sudo {BIN_PATH} monitor --diagnose")
    print(f"  Observe mode: sudo {BIN_PATH} monitor")
    print(f"  Field Guide:  https://bartoszosiej.github.io/talus-process-monitor/field-guide.html")


def do_run(args):
    exe = os.environ.get("TALUS_BIN") or str(BIN_PATH)
    if not Path(exe).exists():
        sys.exit("Agent not installed. Run: talus-monitor install")
    os.execv(exe, [exe, *args.args])


def do_status(_args):
    try:
        latest = gh_latest().get("tag_name", "?")
    except Exception as e:
        latest = f"(unreachable: {e})"
    if BIN_PATH.exists():
        print(f"agent: installed at {BIN_PATH}")
        print(f"latest release: {latest}")
        print("update with: talus-monitor install")
    else:
        print(f"agent: NOT installed | latest release: {latest}")
        print("install with: talus-monitor install")


def main():
    p = argparse.ArgumentParser(
        prog="talus-monitor",
        description="Installer/runner for the Talus eBPF ransomware agent "
        "(fetches the official prebuilt binary from GitHub releases).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("install", "update"):
        sp = sub.add_parser(name, help="download & install the latest release binary")
        sp.set_defaults(func=do_install)
    sp = sub.add_parser("status", help="show install status & latest release")
    sp.set_defaults(func=do_status)
    sp = sub.add_parser("run", help="run the installed agent, e.g.: talus-monitor run monitor --json")
    sp.add_argument("args", nargs=argparse.REMAINDER)
    sp.set_defaults(func=do_run)
    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
