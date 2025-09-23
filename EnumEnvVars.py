#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

import requests
from alive_progress import alive_bar


DEFAULT_URL = "http://localhost:2375"  # Docker Engine API (no auth; enable with care)


def fmt_bytes(n: int) -> str:
    """Human-friendly bytes."""
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(n)
    for u in units:
        if size < 1024.0:
            return f"{size:.1f} {u}"
        size /= 1024.0
    return f"{size:.1f} EB"


def get_engine_info(base_url: str, timeout: int = 10) -> dict:
    """Return Docker Engine info from /info."""
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/info", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] Failed to get engine info from {base_url}: {e}", file=sys.stderr)
        return {}


def get_containers(base_url: str, timeout: int = 10):
    """Return list of container summary objects (like `docker ps -a`)."""
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/containers/json?all=true", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] Failed to get containers from {base_url}: {e}", file=sys.stderr)
        return []


def get_container_env(base_url: str, container_id: str, timeout: int = 10):
    """Return list of Env strings for a container (e.g., ['KEY=VALUE', ...])."""
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/containers/{container_id}/json", timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return data.get("Config", {}).get("Env", []) or []
    except requests.RequestException as e:
        print(f"[!] Failed to get info for container {container_id[:12]}: {e}", file=sys.stderr)
        return []


def parse_args():
    p = argparse.ArgumentParser(
        description="Enumerate Docker containers and print their environment variables."
    )
    p.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Docker Engine API base URL (default: {DEFAULT_URL})",
    )
    p.add_argument(
        "--out",
        metavar="FILE",
        help="Optional path to save results as JSON (e.g., results.json)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds (default: 10)",
    )
    p.add_argument(
        "--show-info-json",
        action="store_true",
        help="Also print the full /info JSON after the overview.",
    )
    return p.parse_args()


def print_engine_overview(info: dict):
    """Pretty, concise overview of key /info fields."""
    if not info:
        print("Engine Info: (unavailable)")
        return

    server_ver = info.get("ServerVersion")
    os_name = info.get("OperatingSystem")
    os_type = info.get("OSType")
    arch = info.get("Architecture")
    ncpu = info.get("NCPU")
    mem = info.get("MemTotal")
    containers = info.get("Containers")
    images = info.get("Images")
    driver = info.get("Driver")
    swarm = info.get("Swarm", {})
    swarm_state = (swarm.get("LocalNodeState") or "inactive").lower()

    print("=== Docker Engine Overview (/info) ===")
    print(f"Server Version : {server_ver}")
    print(f"OS / Arch      : {os_name} ({os_type}/{arch})")
    print(f"CPUs / Memory  : {ncpu} / {fmt_bytes(mem) if isinstance(mem, int) else mem}")
    print(f"Storage Driver : {driver}")
    print(f"Containers     : {containers}")
    print(f"Images         : {images}")
    print(f"Swarm State    : {swarm_state}")
    if info.get("RegistryConfig", {}).get("InsecureRegistryCIDRs"):
        print("Insecure Registries configured")
    if info.get("ExperimentalBuild"):
        print("Experimental features: enabled")
    print("=" * 36)


def main():
    args = parse_args()

    # 1) Capture and print /info first
    engine_info = get_engine_info(args.url, timeout=args.timeout)
    print_engine_overview(engine_info)
    if args.show_info_json and engine_info:
        print(json.dumps(engine_info, indent=2))

    # 2) Enumerate containers with a progress bar
    containers = get_containers(args.url, timeout=args.timeout)
    if not containers:
        print("No containers found.")
        results = {"engine_info": engine_info, "containers": []}
        if args.out:
            try:
                Path(args.out).write_text(json.dumps(results, indent=2))
                print(f"\nSaved results to {Path(args.out).resolve()}")
            except Exception as e:
                print(f"[!] Failed to write output file '{args.out}': {e}", file=sys.stderr)
                return 2
        return 0

    results = {"engine_info": engine_info, "containers": []}

    print(f"Found {len(containers)} containers. Inspecting")
    with alive_bar(len(containers), title="Investigating containers") as bar:
        for c in containers:
            container_id = c.get("Id", "") or ""
            names = c.get("Names") or []
            name = names[0] if names else ""
            if name.startswith("/"):
                name = name[1:]

            env_vars = get_container_env(args.url, container_id, timeout=args.timeout)

            # Print to stdout
            print(f"\nContainer Name: {name or '(unnamed)'}")
            print(f"Container ID: {container_id}")
            if env_vars:
                print("Environment Variables:")
                for env in env_vars:
                    print(f"  - {env}")
            else:
                print("No environment variables found.")

            # Append to results
            results["containers"].append(
                {
                    "id": container_id,
                    "name": name,
                    "env": env_vars,
                }
            )

            bar()  # advance progress

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
