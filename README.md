# SYN Scan with Scapy - syn_scan.py

A multi-threaded Python application that performs a TCP SYN port scan on a provided target IP address or range of IP addresses using the Scapy library. It provides a wide range of customization options through command-line arguments. 

## Features

- **Ping Sweep:** Initially, the script conducts a "ping sweep" to check the online status of the targets before performing the scan. The --force option can bypass this process to scan the host regardless of its status.

- **Port Selection:** Users can define specific ports to be scanned using the --ports option. The --top20 and --top50 options allow users to quickly scan the most common ports while the --all option scans all available ports.

- **Multi-threading:** The script supports multi-threading to expedite the scan process. Users can define the maximum number of concurrent threads using the --max-threads option (default is 10).

- **Verbose Output:** The --verbose option provides a more detailed output.

## SYN Scan Methodology

SYN scanning involves sending a TCP packet with the SYN (synchronize) flag set. If the target responds with a TCP packet with the SYN and ACK (acknowledge) flags set, the port is considered open. The script will then close the connection with a RST (reset) packet to avoid completing the TCP handshake process and remain stealthy. If there is no response or the target sends a RST packet, the port is considered closed.

## Usage

```bash
usage: syn_scan.py [-h] -t TARGET [-p PORTS] [-a] [-top20] [-top50] [-v] [-f] [-m MAX_THREADS]

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target IP (e.g. 192.168.1.1), IP range (e.g. 192.168.1.0/24, 192.168.1.1-5) or IP list (e.g.
                        192.168.1.1,192.168.1.2)
  -p PORTS, --ports PORTS
                        Ports or ranges to scan (e.g. 22,80,1000-2000)
  -a, --all             Scan all ports
  -top20, --top20       Perform a scan of top 20 ports
  -top50, --top50       Perform a scan of top 50 ports
  -v, --verbose         Verbose output
  -f, --force           Force scan even if host seems down
  -m MAX_THREADS, --max-threads MAX_THREADS
                        Maximum number of concurrent threads (default 10)
```
