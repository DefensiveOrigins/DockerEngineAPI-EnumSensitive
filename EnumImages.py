#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# local import for progress; keep at top-level to fail early if missing
from alive_progress import alive_bar

DEFAULT_URL = "http://localhost:2375"
DEFAULT_TIMEOUT = 10

# --- heuristics / patterns ---
PATTERNS = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key_header": re.compile(r"-----BEGIN (RSA |OPENSSH |PRIVATE )?PRIVATE KEY-----", re.I),
    "private_key_any": re.compile(r"-----BEGIN .*PRIVATE KEY-----", re.I),
    "password_assignment": re.compile(r"(password|passwd|pwd|secret|token)\s*(=|:)\s*[\S]+", re.I),
    "basic_auth_like": re.compile(r"[uU]sername[:=]\s*\S+|[pP]assword[:=]\s*\S+"),
    # long base64-like string (>=40 chars of base64 chars, optional padding)
    "long_base64": re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})"),
    # hex-like long string (likely API tokens / sha1/sha256 if long)
    "long_hex": re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    # likely jwts: three base64url segments separated by dots (header.payload.signature)
    "jwt_like": re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$"),
}

MIN_ENTROPY_LEN = 20
ENTROPY_THRESHOLD = 4.2  # heuristic threshold for high-entropy (0..~6.5 for ascii)
# higher thresholds reduce false positives; tuned conservative


# --- utility functions ---
def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy for string s (bits/char)."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def find_matches_in_text(text: str) -> List[Dict[str, Any]]:
    """Run regex heuristics and entropy checks on text, return list of findings."""
    findings: List[Dict[str, Any]] = []
    if not text:
        return findings

    # quick checks for patterns
    for name, pat in PATTERNS.items():
        for m in pat.finditer(text):
            candidate = m.group(0)
            ent = shannon_entropy(candidate) if len(candidate) >= MIN_ENTROPY_LEN else 0.0
            findings.append(
                {
                    "type": name,
                    "match": candidate,
                    "context_snippet": _context_snippet(text, m.start(), m.end()),
                    "entropy": round(ent, 3),
                }
            )

    # scan for potential high-entropy substrings separated by whitespace/punctuation
    # break into tokens and test long tokens
    tokens = re.split(r"[\s\"'`<>(){}[\],;]+", text)
    for t in tokens:
        if len(t) >= MIN_ENTROPY_LEN:
            ent = shannon_entropy(t)
            if ent >= ENTROPY_THRESHOLD:
                findings.append(
                    {
                        "type": "high_entropy_token",
                        "match": t[:200] if len(t) > 200 else t,
                        "entropy": round(ent, 3),
                        "length": len(t),
                    }
                )

    return findings


def _context_snippet(text: str, start: int, end: int, window: int = 40) -> str:
    s = max(0, start - window)
    e = min(len(text), end + window)
    snippet = text[s:e]
    return snippet.replace("\n", " ")  # single-line snippet


# --- Docker API helpers ---
def get_engine_info(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/info", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] Failed to /info: {e}", file=sys.stderr)
        return {}


def get_images(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/images/json?all=true", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] Failed to list images: {e}", file=sys.stderr)
        return []


def inspect_image(base_url: str, image_ref: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
    # image_ref may be id or repo:tag. Use id if available.
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/images/{image_ref}/json", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return None


def image_history(base_url: str, image_ref: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/images/{image_ref}/history", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return []


# --- main scanning logic ---
def scan_image(base_url: str, image: Dict[str, Any], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Examine an image metadata and history for suspicious items.
    Returns a dict with findings.
    """
    img_id = image.get("Id") or image.get("ID") or image.get("id") or image.get("Digest") or "<unknown>"
    tags = image.get("RepoTags") or image.get("Names") or []
    size = image.get("Size")
    created = image.get("Created")
    # prefer a short friendly name for API calls; use tag if present
    call_ref = img_id
    # strip "sha256:" prefix when calling API with ID sometimes works with full id too; leave as-is

    details = inspect_image(DEFAULT_URL if base_url is None else base_url, call_ref, timeout=timeout) or {}
    history = image_history(DEFAULT_URL if base_url is None else base_url, call_ref, timeout=timeout)

    findings: List[Dict[str, Any]] = []
    # gather candidate strings to scan
    candidate_texts: List[Tuple[str, str]] = []  # (source, text)

    # Repo tags
    if tags:
        candidate_texts.append(("repo_tags", " ".join(tags) if isinstance(tags, list) else str(tags)))

    # Config section from inspect result
    cfg = details.get("Config") or {}
    if cfg:
        # Env
        envs = cfg.get("Env") or []
        if envs:
            candidate_texts.append(("env", "\n".join(envs)))
        # Labels
        labels = cfg.get("Labels") or {}
        if labels:
            # join label keys and values
            candidate_texts.append(("labels", " ".join(f"{k}={v}" for k, v in labels.items())))
        # Cmd / Entrypoint
        cmd = cfg.get("Cmd")
        if cmd:
            candidate_texts.append(("cmd", " ".join(cmd)))
        entry = cfg.get("Entrypoint")
        if entry:
            candidate_texts.append(("entrypoint", " ".join(entry)))
        working_dir = cfg.get("WorkingDir")
        if working_dir:
            candidate_texts.append(("working_dir", working_dir))

    # ContainerConfig also may hold env/cmd
    ccfg = details.get("ContainerConfig") or {}
    if ccfg:
        if ccfg.get("Env"):
            candidate_texts.append(("container_config_env", " ".join(ccfg.get("Env"))))
        if ccfg.get("Cmd"):
            candidate_texts.append(("container_config_cmd", " ".join(ccfg.get("Cmd"))))

    # History: created_by often includes the RUN lines
    if history:
        # created_by fields are useful for seeing RUN commands
        created_bys = []
        for h in history:
            cb = h.get("CreatedBy") or ""
            if cb:
                created_bys.append(cb)
        if created_bys:
            candidate_texts.append(("history_created_by", "\n".join(created_bys)))

    # tags in image manifest / repo digests
    if image.get("RepoDigests"):
        candidate_texts.append(("repo_digests", " ".join(image.get("RepoDigests"))))

    # also include raw JSON dump of details (shortened) for scanning
    if details:
        # convert to string but limit size to avoid scanning huge blobs
        jdump = json.dumps(details, default=str)
        candidate_texts.append(("inspect_json", jdump[:20000]))  # cap to 20k chars

    # run heuristics on each candidate text
    for source, txt in candidate_texts:
        matches = find_matches_in_text(txt)
        for m in matches:
            finding = dict(m)
            finding["source"] = source
            findings.append(finding)

    # Summarize some metadata
    summary = {
        "image_id": img_id,
        "tags": tags,
        "size": size,
        "created": created,
        "findings": findings,
        "inspect_available": bool(details),
        "history_entries": len(history),
    }
    return summary


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Audit Docker images for potential sensitive information (metadata + history).")
    p.add_argument("--url", default=DEFAULT_URL, help=f"Docker Engine API base URL (default: {DEFAULT_URL})")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout in seconds.")
    p.add_argument("--out", metavar="FILE", help="Optional JSON output file to save report.")
    p.add_argument("--min-findings", type=int, default=0, help="Only include images with at least this many findings in printed summary.")
    p.add_argument("--show-inspect-json", action="store_true", help="Print full inspect JSON for images (can be verbose).")
    return p.parse_args()


def print_engine_overview(info: Dict[str, Any]) -> None:
    if not info:
        print("Engine Info: (unavailable)")
        return
    print("=== Docker Engine Overview (/info) ===")
    print(f"Server Version : {info.get('ServerVersion')}")
    print(f"OS / Arch      : {info.get('OperatingSystem')} ({info.get('OSType')}/{info.get('Architecture')})")
    print(f"CPUs / Memory  : {info.get('NCPU')} / {info.get('MemTotal')}")
    print(f"Storage Driver : {info.get('Driver')}")
    print("=" * 36)


def main() -> int:
    args = parse_args()
    base_url = args.url.rstrip("/")
    timeout = args.timeout

    engine_info = get_engine_info(base_url, timeout=timeout)
    print_engine_overview(engine_info)

    images = get_images(base_url, timeout=timeout)
    if not images:
        print("No images returned by /images/json.")
        return 0

    report: Dict[str, Any] = {"engine_info": engine_info, "images": []}

    print(f"Found {len(images)} images. Scanning metadata and history for sensitive information...")

    with alive_bar(len(images), title="Scanning images") as bar:
        for img in images:
            summary = scan_image(base_url, img, timeout=timeout)
            # Collect and optionally print summary
            if len(summary["findings"]) >= args.min_findings:
                print("\n---")
                tags = summary.get("tags") or []
                tagstr = ", ".join(tags) if tags else "(untagged)"
                print(f"Image: {tagstr}")
                print(f"ID: {summary.get('image_id')}")
                print(f"Size bytes: {summary.get('size')}, history entries: {summary.get('history_entries')}")
                if summary["findings"]:
                    print("Findings:")
                    for f in summary["findings"]:
                        # compact display
                        typ = f.get("type")
                        ent = f.get("entropy")
                        src = f.get("source")
                        snippet = f.get("context_snippet") or f.get("match")
                        snippet = f.get("context_snippet") or f.get("match")
                        print(f" - [{typ}] source={src} entropy={ent} match={repr(f.get('match'))}")
                        if snippet:
                            print(f"    → snippet: {snippet}")
                else:
                    print("Findings: None")
                if args.show_inspect_json and summary.get("inspect_available"):
                    # call inspect again to print full JSON
                    details = inspect_image(base_url, summary["image_id"], timeout=timeout)
                    if details:
                        print("Full inspect JSON (truncated):")
                        print(json.dumps(details, indent=2)[:4000])
            report["images"].append(summary)
            bar()

    # Save JSON report if requested
    if args.out:
        try:
            p = Path(args.out)
            p.write_text(json.dumps(report, indent=2))
            print(f"\nSaved JSON report to {p.resolve()}")
        except Exception as e:
            print(f"[!] Failed to save report to {args.out}: {e}", file=sys.stderr)
            return 2

    print("\nScan complete. Review flagged findings manually — these are heuristics, not definitive evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
