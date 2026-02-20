#!/usr/bin/env python3
"""Generate an Obsidian Canvas network map from Nmap XML scans.

The script walks subdirectories under an input directory, discovers Nmap XML files,
extracts host/interface information, and emits a Canvas JSON file.

Design:
- One host node per discovered host.
- One subnet node per detected IPv4 subnet (configurable prefix length).
- Host-to-subnet edges for each interface address, so dual-homed / multi-address
  systems visibly connect multiple subnet nodes.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
import xml.etree.ElementTree as ET


@dataclass
class HostRecord:
    """Aggregated host data across scan files."""

    key: str
    display_name: str
    ipv4_addrs: set[str] = field(default_factory=set)
    ipv6_addrs: set[str] = field(default_factory=set)
    mac_addrs: set[str] = field(default_factory=set)
    source_files: set[str] = field(default_factory=set)


def discover_nmap_xml_files(scan_root: Path) -> list[Path]:
    """Return likely Nmap XML files from all subdirectories of scan_root."""
    xml_files: list[Path] = []
    for path in scan_root.rglob("*.xml"):
        if path.is_file() and is_nmap_xml(path):
            xml_files.append(path)
    return sorted(xml_files)


def is_nmap_xml(path: Path) -> bool:
    """Check whether an XML file appears to be an Nmap output file."""
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return False

    root = tree.getroot()
    return root.tag == "nmaprun"


def parse_host_entries(xml_path: Path) -> list[dict[str, object]]:
    """Extract host entries from one Nmap XML file."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts: list[dict[str, object]] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ipv4_addrs: list[str] = []
        ipv6_addrs: list[str] = []
        mac_addrs: list[str] = []

        for address in host.findall("address"):
            addr = address.get("addr")
            addrtype = (address.get("addrtype") or "").lower()
            if not addr:
                continue

            if addrtype == "ipv4":
                ipv4_addrs.append(addr)
            elif addrtype == "ipv6":
                ipv6_addrs.append(addr)
            elif addrtype == "mac":
                mac_addrs.append(addr)

        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        hosts.append(
            {
                "hostname": hostname,
                "ipv4": ipv4_addrs,
                "ipv6": ipv6_addrs,
                "mac": mac_addrs,
            }
        )

    return hosts


def choose_host_key(hostname: str | None, mac_addrs: list[str], ipv4_addrs: list[str], fallback_seed: str) -> str:
    """Select a stable-ish key for host deduplication across scans."""
    if mac_addrs:
        return f"mac:{sorted(mac_addrs)[0].lower()}"
    if hostname:
        return f"host:{hostname.lower()}"
    if ipv4_addrs:
        return f"ipv4:{sorted(ipv4_addrs)[0]}"
    return f"unknown:{fallback_seed}"


def aggregate_hosts(xml_files: list[Path]) -> dict[str, HostRecord]:
    """Aggregate host data from all XML files."""
    hosts: dict[str, HostRecord] = {}

    for xml_file in xml_files:
        parsed_hosts = parse_host_entries(xml_file)
        for idx, host in enumerate(parsed_hosts):
            hostname = host["hostname"]
            ipv4_addrs = host["ipv4"]
            ipv6_addrs = host["ipv6"]
            mac_addrs = host["mac"]

            key = choose_host_key(
                hostname if isinstance(hostname, str) else None,
                mac_addrs if isinstance(mac_addrs, list) else [],
                ipv4_addrs if isinstance(ipv4_addrs, list) else [],
                fallback_seed=f"{xml_file.name}:{idx}",
            )

            if key not in hosts:
                display_name = (
                    hostname
                    if isinstance(hostname, str) and hostname
                    else (sorted(ipv4_addrs)[0] if isinstance(ipv4_addrs, list) and ipv4_addrs else key)
                )
                hosts[key] = HostRecord(key=key, display_name=display_name)

            record = hosts[key]
            if isinstance(ipv4_addrs, list):
                record.ipv4_addrs.update(ipv4_addrs)
            if isinstance(ipv6_addrs, list):
                record.ipv6_addrs.update(ipv6_addrs)
            if isinstance(mac_addrs, list):
                record.mac_addrs.update([m.lower() for m in mac_addrs])
            record.source_files.add(str(xml_file))

    return hosts


def build_canvas(hosts: dict[str, HostRecord], subnet_prefix: int) -> dict[str, object]:
    """Create Obsidian Canvas JSON from aggregated host records."""
    nodes: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []

    host_node_ids: dict[str, str] = {}
    subnet_node_ids: dict[str, str] = {}

    subnets: set[str] = set()
    for record in hosts.values():
        for ip in record.ipv4_addrs:
            try:
                network = ipaddress.ip_network(f"{ip}/{subnet_prefix}", strict=False)
            except ValueError:
                continue
            subnets.add(str(network))

    sorted_subnets = sorted(subnets, key=lambda n: (ipaddress.ip_network(n).network_address, n))

    host_x = 60
    host_y_start = 60
    host_y_step = 180

    for i, host_key in enumerate(sorted(hosts.keys())):
        record = hosts[host_key]
        node_id = str(uuid.uuid4())
        host_node_ids[host_key] = node_id

        subtitle_parts = []
        if record.ipv4_addrs:
            subtitle_parts.append("IPv4: " + ", ".join(sorted(record.ipv4_addrs)))
        if record.ipv6_addrs:
            subtitle_parts.append("IPv6: " + ", ".join(sorted(record.ipv6_addrs)))
        if record.mac_addrs:
            subtitle_parts.append("MAC: " + ", ".join(sorted(record.mac_addrs)))

        text = record.display_name
        if subtitle_parts:
            text += "\n" + "\n".join(subtitle_parts)

        nodes.append(
            {
                "id": node_id,
                "type": "text",
                "x": host_x,
                "y": host_y_start + i * host_y_step,
                "width": 380,
                "height": 130,
                "text": text,
            }
        )

    subnet_x = 600
    subnet_y_start = 100
    subnet_y_step = 160

    for i, subnet in enumerate(sorted_subnets):
        node_id = str(uuid.uuid4())
        subnet_node_ids[subnet] = node_id
        nodes.append(
            {
                "id": node_id,
                "type": "text",
                "x": subnet_x,
                "y": subnet_y_start + i * subnet_y_step,
                "width": 260,
                "height": 90,
                "text": f"Subnet\n{subnet}",
            }
        )

    for host_key, record in hosts.items():
        host_node_id = host_node_ids[host_key]
        for ip in sorted(record.ipv4_addrs):
            try:
                subnet = str(ipaddress.ip_network(f"{ip}/{subnet_prefix}", strict=False))
            except ValueError:
                continue

            subnet_node_id = subnet_node_ids.get(subnet)
            if not subnet_node_id:
                continue

            edges.append(
                {
                    "id": str(uuid.uuid4()),
                    "fromNode": host_node_id,
                    "fromSide": "right",
                    "toNode": subnet_node_id,
                    "toSide": "left",
                    "label": ip,
                }
            )

    return {"nodes": nodes, "edges": edges}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate subdirectories for Nmap XML scans and generate an Obsidian "
            "Canvas network map."
        )
    )
    parser.add_argument("scan_dir", type=Path, help="Root directory containing Nmap scan subdirectories")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("network_map.canvas"),
        help="Output Obsidian Canvas file path (default: network_map.canvas)",
    )
    parser.add_argument(
        "--subnet-prefix",
        type=int,
        default=24,
        help="Prefix length to group IPv4 addresses into subnet nodes (default: 24)",
    )

    args = parser.parse_args()

    if not args.scan_dir.exists() or not args.scan_dir.is_dir():
        raise SystemExit(f"Scan directory does not exist or is not a directory: {args.scan_dir}")

    if not (0 <= args.subnet_prefix <= 32):
        raise SystemExit("--subnet-prefix must be between 0 and 32")

    xml_files = discover_nmap_xml_files(args.scan_dir)
    if not xml_files:
        raise SystemExit(f"No Nmap XML files found under: {args.scan_dir}")

    hosts = aggregate_hosts(xml_files)
    canvas_data = build_canvas(hosts, args.subnet_prefix)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(canvas_data, indent=2), encoding="utf-8")

    print(f"Discovered {len(xml_files)} scan file(s)")
    print(f"Discovered {len(hosts)} host(s)")
    print(f"Wrote canvas file: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
