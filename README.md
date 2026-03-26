# ft_nmap

## Overview

`ft_nmap` is a compact, educational network port scanner implemented in C. It exercises raw packet crafting, libpcap-based reply capture, and a small thread pool to scan targets with several TCP/UDP probe types.

This repository contains the scanner implementation, a small test harness, and convenience helpers used during development.

## Features

- Supported scan types: SYN, NULL, ACK, FIN, XMAS, UDP
- Multithreaded scanning (configurable worker count, up to 250)
- Scan a single IP (`--ip`) or the first target from a file (`--file`)
- Flexible port selection: single ports, ranges, and comma-separated lists
- Optional extras: JSON output, pcap dump, top-ports mode, decoy spoofing, timing evasion
- Best-effort banner grabbing for open TCP services

## Platform & privileges

- Requires Linux for the included testing and pcap device usage.
- Raw SYN scanning and IP spoofing require root privileges. When run unprivileged the program falls back to a non-privileged connect-scan mode.
- Capturing with libpcap may require appropriate permissions (or running as root).

## Build

Install dependencies (libpcap development headers) and build with make:

```bash
# Debian/Ubuntu example
sudo apt-get install build-essential libpcap-dev
make
```

Developer tip: to run the test suite with AddressSanitizer enabled:

```bash
make clean
make CFLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer -Wall -Wextra -Werror" test
```

## Usage

```
./ft_nmap [OPTIONS]
```

Key options:

- `--help`            Show help
- `--ip <addr>`       Target IPv4 address (dotted)
- `--file <path>`     File with targets (first non-empty line is used)
- `--ports <list>`    Ports (e.g. `1-1024`, `22,80,443`)
- `--speedup <n>`     Number of worker threads (0 => single-threaded)
- `--scan <types>`    Scan types (SYN NULL ACK FIN XMAS UDP). Can be space- or comma-separated.
- `--json <path>`     Write results as JSON to file
- `--save-pcap <path>` Write captured packets to pcap file
- `--top-ports <N>`   Scan built-in top N ports
- `--decoy <ips>`     Comma-separated decoy IPs (raw-only, best-effort)
- `--evade`           Add small timing jitter between probes

Run `./ft_nmap --help` for the full help text and examples.

## Examples

- SYN scan ports 20–80 with 50 threads:

```bash
./ft_nmap --ip 192.168.1.1 --ports 20-80 --scan SYN --speedup 50
```

- Scan ports 1–1024 with default all-scan types:

```bash
./ft_nmap --ip 192.168.1.1 --ports 1-1024
```

- Scan target from a file and save pcap/JSON output:

```bash
./ft_nmap --file targets.txt --ports 80,443 --scan SYN --save-pcap out.pcap --json out.json
```

## Tests

This repo includes a small test harness. Run the tests with:

```bash
make test
```

For development we run the test suite under AddressSanitizer to catch leaks and memory errors (see Build section).

## Notes & limitations

- Decoy source IP spoofing requires raw sockets and suitable network setup; when unprivileged the program uses the connect-scan fallback and decoys are not used.
- Pcap dumping and precise reply correlation depend on the capture device and kernel stack; results may vary across environments.
- The implementation focuses on correctness and readability for an academic project and is not intended to be a replacement for production tools.

## Author

- Mohammed Annahri

## License / Disclaimer

This project was developed as an academic exercise (1337 School). Use responsibly and only on networks where you have permission.
