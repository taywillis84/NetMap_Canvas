#!/usr/bin/env python3
"""Generate an Obsidian Canvas network map from Nmap XML scans.

The script walks subdirectories under an input directory, discovers Nmap XML files,
extracts host/interface information, and emits a Canvas JSON file.
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
    hostname: str | None = None
    open_ports: set[str] = field(default_factory=set)
    is_kali_attack_box: bool = False


KALI_ATTACK_BOX_KEY = "special:kali-attack-box"
DEFAULT_HEADER_TO_HOST_GAP = 40


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
    """Extract host entries from one Nmap XML file.

    Hosts without any open ports are excluded.
    """
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

        open_ports: list[str] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid = port.get("portid")
            protocol = port.get("protocol") or "tcp"
            if not portid:
                continue

            service_label = ""
            service = port.find("service")
            if service is not None:
                service_name = (service.get("name") or "").strip()
                service_product = (service.get("product") or "").strip()
                service_version = (service.get("version") or "").strip()
                service_extra = (service.get("extrainfo") or "").strip()

                service_parts = [part for part in [service_name, service_product, service_version, service_extra] if part]
                if service_parts:
                    service_label = f" ({' '.join(service_parts)})"

            open_ports.append(f"{portid}/{protocol}{service_label}")

        if not open_ports:
            continue

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
                "open_ports": open_ports,
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
                display_name = sorted(ipv4_addrs)[0] if isinstance(ipv4_addrs, list) and ipv4_addrs else key
                hosts[key] = HostRecord(key=key, display_name=display_name)

            record = hosts[key]
            if isinstance(hostname, str) and hostname and not record.hostname:
                record.hostname = hostname
            if isinstance(ipv4_addrs, list):
                record.ipv4_addrs.update(ipv4_addrs)
            if isinstance(ipv6_addrs, list):
                record.ipv6_addrs.update(ipv6_addrs)
            if isinstance(mac_addrs, list):
                record.mac_addrs.update([m.lower() for m in mac_addrs])
            open_ports = host.get("open_ports")
            if isinstance(open_ports, list):
                record.open_ports.update([str(p) for p in open_ports])
            record.source_files.add(str(xml_file))

    return hosts


def estimate_text_node_size(
    lines: list[str],
    *,
    min_width: int,
    min_height: int,
    max_width: int = 980,
    horizontal_padding: int = 80,
    vertical_padding: int = 44,
    char_width: int = 7,
    line_height: int = 24,
) -> tuple[int, int]:
    """Estimate canvas node size from text line count and line length."""
    non_empty_lines = lines or [""]
    max_line_len = max((len(line) for line in non_empty_lines), default=0)

    width = max(min_width, min(max_width, max_line_len * char_width + horizontal_padding))
    height = max(min_height, len(non_empty_lines) * line_height + vertical_padding)
    return width, height


def build_canvas(hosts: dict[str, HostRecord], subnet_prefix: int, kali_ip: str) -> dict[str, object]:
    """Create Obsidian Canvas JSON from aggregated host records.

    The map is column-oriented by subnet and intentionally contains no edges.
    """
    nodes: list[dict[str, object]] = []

    subnet_to_hosts: dict[str, list[tuple[HostRecord, str]]] = {}

    for record in hosts.values():
        if record.is_kali_attack_box:
            continue
        for ip in sorted(record.ipv4_addrs):
            try:
                subnet = str(ipaddress.ip_network(f"{ip}/{subnet_prefix}", strict=False))
            except ValueError:
                continue
            subnet_to_hosts.setdefault(subnet, []).append((record, ip))

    sorted_subnets = sorted(subnet_to_hosts.keys(), key=lambda n: (ipaddress.ip_network(n).network_address, n))

    kali_record = hosts[KALI_ATTACK_BOX_KEY]

    col_x_start = 60
    col_x_step = 620
    header_y = 40
    host_y_start = 170
    host_y_step = 210

    # Draw a dedicated leftmost column for the Kali attack box.
    kali_header_text = "Attack Infrastructure\nKali Attack Box"
    kali_header_lines = kali_header_text.splitlines()
    kali_header_width, kali_header_height = estimate_text_node_size(kali_header_lines, min_width=460, min_height=110)
    nodes.append(
        {
            "id": str(uuid.uuid4()),
            "type": "text",
            "x": col_x_start,
            "y": header_y,
            "width": 460,
            "height": 110,
            "color": "1",
            "text": "Attack Infrastructure\nKali Attack Box",
        }
    )

    kali_subnet = str(ipaddress.ip_network(f"{kali_ip}/{subnet_prefix}", strict=False))
    kali_host_lines = [
        kali_record.hostname or "Kali Attack Box",
        f"Subnet IPs: {kali_ip}",
        f"All IPv4: {kali_ip}",
        f"Subnet: {kali_subnet}",
    ]
    kali_host_text = "\n".join(kali_host_lines)
    kali_host_width, kali_host_height = estimate_text_node_size(kali_host_lines, min_width=460, min_height=180)
    kali_host_y = header_y + kali_header_height + header_to_host_gap
    nodes.append(
        {
            "id": str(uuid.uuid4()),
            "type": "text",
            "x": col_x_start,
            "y": host_y_start,
            "width": 460,
            "height": 180,
            "color": "1",
            "text": "\n".join(
                [
                    kali_record.hostname or "Kali Attack Box",
                    f"Subnet IPs: {kali_ip}",
                    f"All IPv4: {kali_ip}",
                    f"Subnet: {kali_subnet}",
                ]
            ),
        }
    )

    next_col_x = col_x_start + max(kali_header_width, kali_host_width) + col_gap

    for subnet in sorted_subnets:
        col_x = next_col_x

        subnet_hosts = subnet_to_hosts[subnet]
        unique_host_keys = {record.key for record, _ in subnet_hosts}

        subnet_header_text = f"Subnet\n{subnet}\nHosts: {len(unique_host_keys)}"
        subnet_header_lines = subnet_header_text.splitlines()
        subnet_header_width, subnet_header_height = estimate_text_node_size(
            subnet_header_lines,
            min_width=460,
            min_height=110,
        )

        nodes.append(
            {
                "id": str(uuid.uuid4()),
                "type": "text",
                "x": col_x,
                "y": header_y,
                "width": 460,
                "height": 110,
                "color": "6",
                "text": f"Subnet\n{subnet}\nHosts: {len(unique_host_keys)}",
            }
        )

        by_host: dict[str, list[str]] = {}
        host_records: dict[str, HostRecord] = {}
        for record, ip in subnet_hosts:
            by_host.setdefault(record.key, []).append(ip)
            host_records[record.key] = record

        column_max_width = subnet_header_width
        next_host_y = header_y + subnet_header_height + header_to_host_gap

        for host_key in sorted(by_host.keys()):
            record = host_records[host_key]
            ips_in_subnet = sorted(set(by_host[host_key]))

            subtitle_parts: list[str] = []
            if record.hostname:
                subtitle_parts.append(record.hostname)

            subtitle_parts.append(f"Subnet IPs: {', '.join(ips_in_subnet)}")
            if record.ipv4_addrs:
                all_ipv4 = ", ".join(sorted(record.ipv4_addrs))
                subtitle_parts.append(f"All IPv4: {all_ipv4}")
            if record.ipv6_addrs:
                subtitle_parts.append("IPv6: " + ", ".join(sorted(record.ipv6_addrs)))
            if record.mac_addrs:
                subtitle_parts.append("MAC: " + ", ".join(sorted(record.mac_addrs)))
            if record.open_ports:
                subtitle_parts.append("Open Ports:\n" + "\n".join(sorted(record.open_ports)))

            host_text = "\n".join(subtitle_parts)
            host_text_lines = host_text.splitlines()
            host_width, host_height = estimate_text_node_size(host_text_lines, min_width=460, min_height=180)
            column_max_width = max(column_max_width, host_width)
            nodes.append(
                {
                    "id": str(uuid.uuid4()),
                    "type": "text",
                    "x": col_x,
                    "y": host_y_start + row_idx * host_y_step,
                    "width": 460,
                    "height": 180,
                    "color": "1" if record.is_kali_attack_box else "4",
                    "text": "\n".join(subtitle_parts),
                }
            )
            next_host_y += host_height + host_row_gap

        next_col_x += column_max_width + col_gap

    return {"nodes": nodes, "edges": []}


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
        "--kali-ip",
        required=True,
        help="Kali Linux IPv4 address to include in the leftmost column as a red node.",
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

    try:
        ipaddress.IPv4Address(args.kali_ip)
    except ipaddress.AddressValueError as exc:
        raise SystemExit(f"Invalid --kali-ip value: {args.kali_ip}") from exc

    xml_files = discover_nmap_xml_files(args.scan_dir)
    if not xml_files:
        raise SystemExit(f"No Nmap XML files found under: {args.scan_dir}")

    hosts = aggregate_hosts(xml_files)
    hosts[KALI_ATTACK_BOX_KEY] = HostRecord(
        key=KALI_ATTACK_BOX_KEY,
        display_name=args.kali_ip,
        ipv4_addrs={args.kali_ip},
        hostname="Kali Attack Box",
        is_kali_attack_box=True,
    )

    canvas_data = build_canvas(hosts, args.subnet_prefix, args.kali_ip)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(canvas_data, indent=2), encoding="utf-8")

    print(f"Discovered {len(xml_files)} scan file(s)")
    print(f"Discovered {len(hosts)} host(s)")
    print(f"Wrote canvas file: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
