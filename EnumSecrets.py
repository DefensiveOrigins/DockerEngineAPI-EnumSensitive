#!/usr/bin/env python3
import argparse
import json
import sys
import base64
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
    """Return list of secrets (metadata)."""
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/secrets", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] Failed to get secrets from {base_url}: {e}", file=sys.stderr)
        return []


def get_secret_detail(base_url: str, secret_id: str, timeout: int = 10):
    """Return secret detail (usually metadata only; value is not exposed by Docker API)."""
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/secrets/{secret_id}", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] Failed to get info for secret {secret_id[:12]}: {e}", file=sys.stderr)
        return None


def maybe_decode_base64(val):
    """Try to base64-decode a string; return (decoded_text, success_flag)."""
    if not isinstance(val, (bytes, str)):
        return None, False
    if isinstance(val, str):
        s = val.strip()
        # base64 requires length multiple of 4; try padding
        pad_len = (-len(s)) % 4
        s_padded = s + ("=" * pad_len)
        try:
            raw = base64.b64decode(s_padded, validate=False)
            try:
                return raw.decode("utf-8", errors="replace"), True
            except Exception:
                return raw, True
        except Exception:
            return None, False
    else:
        # bytes; try to decode directly
        try:
            raw = base64.b64decode(val, validate=False)
            try:
                return raw.decode("utf-8", errors="replace"), True
            except Exception:
                return raw, True
        except Exception:
            return None, False


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

    # 2) Secrets enumeration
    secrets = get_secrets(args.url, timeout=args.timeout)
    if not secrets:
        print("No secrets found.")
        results = {"engine_info": engine_info, "secrets": []}
        if args.out:
            try:
                Path(args.out).write_text(json.dumps(results, indent=2))
                print(f"\nSaved results to {Path(args.out).resolve()}")
            except Exception as e:
                print(f"[!] Failed to write output file '{args.out}': {e}", file=sys.stderr)
                return 2
        return 0

    print(f"Found {len(secrets)} secrets. Inspecting")
    results = {"engine_info": engine_info, "secrets": []}

    with alive_bar(len(secrets), title="Investigating secrets") as bar:
        for s in secrets:
            secret_id = s.get("ID") or s.get("Id") or ""
            spec = s.get("Spec", {}) or {}
            name = spec.get("Name") or s.get("Name") or "(unnamed)"

            # Fetch detail (usually metadata only)
            detail = get_secret_detail(args.url, secret_id, timeout=args.timeout) or {}

            # Attempt to find a value-like field (non-standard)
            decoded_text = None
            value_found = False
            if args.attempt-values:  # <-- hyphen not allowed in var name; fix below
                pass
            # ^ We'll fix in code block below.

            # Print
            print(f"\nSecret Name: {name}")
            print(f"Secret ID: {secret_id}")
            if args.attempt_values:
                # Look in a few plausible spots
                raw_val = (
                    detail.get("Spec", {}).get("Data")
                    or detail.get("Spec", {}).get("Value")
                    or detail.get("Data")
                    or detail.get("Value")
                )
                if raw_val is not None:
                    decoded_text, value_found = maybe_decode_base64(raw_val)
                if value_found:
                    # If bytes, show repr; if text, show text
                    if isinstance(decoded_text, (bytes, bytearray)):
                        print("Secret Value (decoded bytes):", decoded_text)
                    else:
                        print("Secret Value (decoded):")
                        # indent multi-line for readability
                        for line in str(decoded_text).splitlines() or ["(empty)"]:
                            print(f"  {line}")
                else:
                    print("Secret Value: (not available via Docker API or could not decode)")
            else:
                print("Secret Value: (skipped; use --attempt-values to try extracting when available)")

            results["secrets"].append(
                {
                    "id": secret_id,
                    "name": name,
                    "detail": detail,
                    **({"decoded_value": decoded_text} if value_found else {}),
                }
            )

            bar()  # progress

    # 3) Save if requested
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
