# NetMap_Canvas

Generate Obsidian Canvas network maps from Nmap scan results.

## Script

`netmap_canvas.py` walks a directory tree, finds Nmap XML files, and builds a `.canvas` file with:

- one node per host,
- one node per subnet,
- edges from host nodes to subnet nodes labeled with host IP addresses.

This makes dual-homed or multi-address hosts easy to spot because they connect to multiple subnet nodes.

## Usage

```bash
python3 netmap_canvas.py /path/to/scans -o network_map.canvas
```

Optional subnet grouping prefix (default `/24`):

```bash
python3 netmap_canvas.py /path/to/scans -o network_map.canvas --subnet-prefix 24
```

## Expected input

The script expects Nmap XML output files (e.g. from `nmap -oX scan.xml ...`) anywhere under the provided root directory.
