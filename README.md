# 🔍 Port Scanner

A fast, multithreaded TCP port scanner written in Python. No third-party dependencies — uses only the standard library.

## Features

-  Multithreaded scanning for high speed
-  Live progress bar
-  Automatic service name detection
-  Optional banner grabbing (`-b`) to identify service versions
-  Built-in top 100 common ports preset (`--top100`)
-  Save results to a text file (`-o`)

## Requirements

- Python 3.9+
- No external packages needed

## Usage

```bash
python port_scanner.py <host> [options]
```

### Examples

```bash
# Scan well-known ports (1–1024) — default
python port_scanner.py 192.168.1.1

# Scan specific ports
python port_scanner.py 192.168.1.1 -p 22,80,443,3306

# Scan a custom range
python port_scanner.py 192.168.1.1 -p 1-5000

# Scan the 100 most common ports
python port_scanner.py 192.168.1.1 --top100

# Grab service banners from open ports
python port_scanner.py 192.168.1.1 --top100 -b

# Save output to a file
python port_scanner.py 192.168.1.1 -o results.txt

# Fast scan with more threads and lower timeout
python port_scanner.py 192.168.1.1 -p 1-65535 -t 300 --timeout 0.5
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `host` | Target hostname or IP address | *(required)* |
| `-p`, `--ports` | Port range `1-1024`, list `22,80,443`, or single `80` | `1-1024` |
| `--top100` | Scan the 100 most common ports (overrides `-p`) | off |
| `-t`, `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout in seconds | `1.0` |
| `-b`, `--banner` | Attempt to grab service banners from open ports | off |
| `-o`, `--output` | Save results to a text file | off |

## Example Output

```
Resolving scanme.nmap.org...
  Host: scanme.nmap.org → 45.33.32.156
  Scanning top 100 common ports...

  [████████████████████████████████████████] 100/100

Scan report for scanme.nmap.org (45.33.32.156)
Scanned at 2024-11-01 14:23:07 - completed in 3.45s

  PORT       SERVICE            BANNER
  ------------------------------------------------------------
. 22/tcp     ssh                SSH-2.0-OpenSSH_6.6.1p1
. 80/tcp     http               Apache/2.4.7 (Ubuntu)

  2 open port(s) found.
```

## ⚠️ Legal Notice

Only scan hosts you **own** or have **explicit written permission** to scan. Unauthorized port scanning may be illegal in your jurisdiction. This tool is intended for network administration, security research, and educational use on systems you are authorized to test.

## Author

**Andrew Ruiz**
[LinkedIn](https://linkedin.com/in/andrew-ruiz-491320366)
