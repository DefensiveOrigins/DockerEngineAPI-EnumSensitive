#!/usr/bin/env python3
import argparse
import base64
import json
import sys
from pathlib import Path

import requests
from alive_progress import alive_bar

DEFAULT_URL = "http://localhost:2375"  # Docker Engine API (no auth; enable with care)


def fmt_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(n)
    for u in units:
        if size < 1024.0:
            return f"{size:.1f} {u}"
        size /= 1024.0
    return f"{size:.1f} EB"


def get_engine_info(base_url: str, timeout: int = 10) -> dict:
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/info", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] Failed to get engine info from {base_url}: {e}", file=sys.stderr)
        return {}


def get_secrets(base_url: str, timeout: int = 10):
    """
    Return (secrets_list, error_message).
    If the Docker API returns an error (e.g., not a Swarm manager), we parse and return it.
    """
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/secrets", timeout=timeout)
        if resp.status_code != 200:
            # Try to extract { "message": "..." } or fall back to text
            err = None
            try:
                j = resp.json()
                err = j.get("message") or j
            except Exception:
                err = (resp.text or "").strip()
            if not err:
                err = f"HTTP {resp.status_code}"
            return [], str(err)
        return resp.json(), None
    except requests.RequestException as e:
        return [], f"Request failed: {e}"


def get_secret_detail(base_url: str, secret_id: str, timeout: int = 10):
    """Return secret detail (usually metadata only)."""
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/secrets/{secret_id}", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] Failed to get info for secret {secret_id[:12]}: {e}", file=sys.stderr)
        return None


def maybe_decode_base64(val):
    """Try to base64-decode a string; return (decoded_text_or_bytes, success_flag)."""
    if not isinstance(val, (bytes, str)):
        return None, False
    try:
        if isinstance(val, str):
            s = val.strip()
            pad_len = (-len(s)) % 4
            s = s + ("=" * pad_len)
            raw = base64.b64decode(s, validate=False)
        else:
            raw = base64.b64decode(val, validate=False)
    except Exception:
        return None, False

    try:
        return raw.decode("utf-8", errors="replace"), True
    except Exception:
        return raw, True


def parse_args():
    p = argparse.ArgumentParser(
        description="Enumerate Docker secrets (metadata) and optionally attempt to extract values."
    )
    p.add_argument("--url", default=DEFAULT_URL, help=f"Docker Engine API base URL (default: {DEFAULT_URL})")
    p.add_argument("--out", metavar="FILE", help="Optional path to save results as JSON (e.g., secrets.json)")
    p.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    p.add_argument("--show-info-json", action="store_true", help="Also print the full /info JSON after the overview.")
    p.add_argument(
        "--attempt-values",
        action="store_true",
        help="Attempt to read and base64-decode a value-like field if present (non-standard; usually unavailable).",
    )
    return p.parse_args()


def print_engine_overview(info: dict):
    if not info:
        print("Engine Info: (unavailable)")
        return
    server_ver = info.get("ServerVersion")
    os_name = info.get("OperatingSystem")
    os_type = info.get("OSType")
    arch = info.get("Architecture")
    ncpu = info.get("NCPU")
    mem = info.get("MemTotal")
    driver = info.get("Driver")
    print("=== Docker Engine Overview (/info) ===")
    print(f"Server Version : {server_ver}")
    print(f"OS / Arch      : {os_name} ({os_type}/{arch})")
    print(f"CPUs / Memory  : {ncpu} / {fmt_bytes(mem) if isinstance(mem, int) else mem}")
    print(f"Storage Driver : {driver}")
    print("=" * 36)


def main():
    args = parse_args()

    # 1) Engine /info
    engine_info = get_engine_info(args.url, timeout=args.timeout)
    print_engine_overview(engine_info)
    if args.show_info_json and engine_info:
        print(json.dumps(engine_info, indent=2))

    # 2) Secrets enumeration (with error capture)
    secrets, err = get_secrets(args.url, timeout=args.timeout)

    results = {"engine_info": engine_info, "secrets": []}
    if err:
        # Mirror the Docker API error clearly for the user
        print(f"[!] Failed to enumerate secrets: {err}", file=sys.stderr)
        # Common hint for Swarm-related errors
        if "swarm" in err.lower() and "manager" in err.lower():
            print("Hint: Connect to a Swarm **manager** node to enumerate secrets.", file=sys.stderr)
        # Save partial output if requested
        if args.out:
            try:
                Path(args.out).write_text(json.dumps({**results, "error": err}, indent=2))
                print(f"\nSaved results (with error) to {Path(args.out).resolve()}")
            except Exception as e:
                print(f"[!] Failed to write output file '{args.out}': {e}", file=sys.stderr)
                return 2
        return 0  # Exit gracefully; we surfaced the error

    if not secrets:
        print("No secrets found.")
        if args.out:
            try:
                Path(args.out).write_text(json.dumps(results, indent=2))
                print(f"\nSaved results to {Path(args.out).resolve()}")
            except Exception as e:
                print(f"[!] Failed to write output file '{args.out}': {e}", file=sys.stderr)
                return 2
        return 0

    print(f"Found {len(secrets)} secrets. Inspecting")

    # 3) Inspect each secret (metadata; value usually unavailable)
    from alive_progress import alive_bar  # local import to speed startup if not used
    with alive_bar(len(secrets), title="Investigating secrets") as bar:
        for s in secrets:
            secret_id = s.get("ID") or s.get("Id") or ""
            spec = s.get("Spec", {}) or {}
            name = spec.get("Name") or s.get("Name") or "(unnamed)"

            detail = get_secret_detail(args.url, secret_id, timeout=args.timeout) or {}

            print(f"\nSecret Name: {name}")
            print(f"Secret ID: {secret_id}")

            if args.attempt_values:
                raw_val = (
                    detail.get("Spec", {}).get("Data")
                    or detail.get("Spec", {}).get("Value")
                    or detail.get("Data")
                    or detail.get("Value")
                )
                if raw_val is not None:
                    decoded, ok = maybe_decode_base64(raw_val)
                    if ok:
                        if isinstance(decoded, (bytes, bytearray)):
                            print("Secret Value (decoded bytes):", decoded)
                        else:
                            print("Secret Value (decoded):")
                            for line in str(decoded).splitlines() or ["(empty)"]:
                                print(f"  {line}")
                        results["secrets"].append(
                            {"id": secret_id, "name": name, "detail": detail, "decoded_value": decoded}
                        )
                    else:
                        print("Secret Value: (present but could not decode)")
                        results["secrets"].append({"id": secret_id, "name": name, "detail": detail})
                else:
                    print("Secret Value: (not available via Docker API)")
                    results["secrets"].append({"id": secret_id, "name": name, "detail": detail})
            else:
                print("Secret Value: (skipped; use --attempt-values to try extracting when available)")
                results["secrets"].append({"id": secret_id, "name": name, "detail": detail})

            bar()  # progress

    # 4) Save if requested
    if args.out:
        try:
            out_path = Path(args.out)
            out_path.write_text(json.dumps(results, indent=2))
            print(f"\nSaved results to {out_path.resolve()}")
        except Exception as e:
            print(f"[!] Failed to write output file '{args.out}': {e}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
