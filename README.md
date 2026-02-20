# NetMap_Canvas

Generate Obsidian Canvas network maps from Nmap scan results.

## Script

`netmap_canvas.py` walks a directory tree, finds Nmap XML files, and builds a `.canvas` file with:

> Only hosts with at least one **open port** in the scan are included as nodes.

- one node per host,
- one subnet header node per subnet column (subnets are separated horizontally),
- host nodes listed under their attached subnet column(s),
- no connecting lines/edges in the canvas output.

This makes dual-homed or multi-address hosts easy to spot because they appear in multiple subnet columns.
- one node per subnet,
- edges from host nodes to subnet nodes labeled with host IP addresses.

This makes dual-homed or multi-address hosts easy to spot because they connect to multiple subnet nodes.

## Usage

```bash
python3 netmap_canvas.py /path/to/scans --kali-ip 192.168.56.10 -o network_map.canvas
```

Optional subnet grouping prefix (default `/24`):

```bash
python3 netmap_canvas.py /path/to/scans --kali-ip 192.168.56.10 -o network_map.canvas --subnet-prefix 24
```


`--kali-ip` is required. It adds a **Kali Attack Box** host node (colored red) into the leftmost subnet column.

## Expected input

The script expects Nmap XML output files (e.g. from `nmap -oX scan.xml ...`) anywhere under the provided root directory.
