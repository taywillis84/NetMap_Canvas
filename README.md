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
