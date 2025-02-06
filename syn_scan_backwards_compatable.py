#!/usr/bin/env python

import argparse
import time
import ipaddress
import threading
import traceback
import sys
import os

try:
    from Queue import Queue  # For Python 2.x compatibility
except ImportError:
    from queue import Queue  # For Python 3.x

import socket
import subprocess

# List of the top 20 most commonly used ports (source: nmap)
TOP_20_PORTS = [21, 22, 23, 25, 80, 110, 139, 443, 445,
                1433, 3306, 3389, 5900, 8080, 8443, 8888]

# List of the top 50 most commonly used ports (source: nmap)
TOP_50_PORTS = [21, 22, 23, 25, 26, 53, 80, 81, 110, 111,
                113, 135, 139, 143, 179, 199, 443, 445, 465,
                514, 515, 548, 554, 587, 646, 993, 995, 1025,
                1026, 1027, 1433, 1720, 1723, 2000, 2001, 3306,
                3389, 5060, 5666, 5900, 6001, 8000, 8008, 8080,
                8443, 8888, 10000, 32768, 49152, 49154]


def is_host_up(ip, verbose, semaphore, queue):
    """
    Check if a host is up by issuing a ping request via subprocess.

    This is a simple method that calls the system's ping command.
    Returns True if the host responds, False otherwise.
    """
    semaphore.acquire()
    try:
        # For cross-platform support:
        #   On Windows: ping -n 1 -w 1
        #   On Linux/Mac: ping -c 1 -W 1
        # We redirect output to devnull to avoid clutter
        with open(os.devnull, 'w') as devnull:
            if sys.platform.startswith('win'):
                command = ["ping", "-n", "1", "-w", "1000", str(ip)]
            else:
                command = ["ping", "-c", "1", "-W", "1", str(ip)]
            return_code = subprocess.call(command, stdout=devnull, stderr=devnull)

        if return_code == 0:
            print("* Host {} is UP".format(ip))
            queue.put((ip, True))
        else:
            if verbose:
                print("* Host {} is DOWN".format(ip))
            queue.put((ip, False))

    except Exception as e:
        if verbose:
            print("Ping check failed for {} with error: {}".format(ip, e))
        queue.put((ip, False))
    finally:
        semaphore.release()


def scan_port(ip, port, verbose, semaphore):
    """
    Attempt to connect to a port to determine if it is open or closed.
    This is a basic TCP connect approach (NOT a true SYN scan).
    """
    try:
        # Using a standard TCP socket (SOCK_STREAM)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        result = sock.connect_ex((str(ip), port))
        sock.close()

        # connect_ex() returns 0 if the operation succeeded (i.e., port is open)
        if result == 0:
            print("Port {} - OPEN".format(port))
        else:
            if verbose:
                print("Port {} - CLOSED".format(port))
    except Exception as e:
        # In case of any unexpected exception (e.g., permission issues)
        if verbose:
            print("An error occurred while scanning port {}: {}".format(port, e))
        traceback.print_exc()
    finally:
        # Release the semaphore lock so another thread can start
        semaphore.release()


def scan_ports(ip, ports, verbose, max_threads):
    """
    Scan multiple ports on a host (using a TCP connect approach).
    """
    semaphore = threading.Semaphore(max_threads)
    threads = []

    for port in ports:
        # Acquire a lock before creating a new thread
        semaphore.acquire()
        thread = threading.Thread(
            target=scan_port, args=(ip, port, verbose, semaphore)
        )
        try:
            thread.start()
            threads.append(thread)
        except Exception as e:
            print("Failed to start thread for port {} with error: {}".format(port, e))
            semaphore.release()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()


def scan_hosts(ips, verbose, max_threads, force):
    """
    Check which hosts in a list of IP addresses are online.
    Returns a list of hosts that are up (or includes all if 'force' is True).
    """
    semaphore = threading.Semaphore(max_threads)
    threads = []
    results_queue = Queue()

    # Ping each IP to see if it's up
    for ip in ips:
        thread = threading.Thread(
            target=is_host_up, args=(ip, verbose, semaphore, results_queue)
        )
        thread.daemon = True
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    online_ips = []
    while not results_queue.empty():
        ip, is_up = results_queue.get()
        if is_up or force:
            online_ips.append(ip)

    return online_ips


def scan_target(target, ports, verbose, max_threads, force):
    """
    Expand the target (IP, IP range, or subnet) into a list of IP addresses,
    check which ones are up, and then scan their ports.
    """
    if ',' in target:
        # Comma-delimited list of IPs
        ips = [ipaddress.IPv4Address(ip.strip()) for ip in target.split(',')]
    elif '-' in target:
        # Range of addresses like 192.168.1.1-10
        ip_parts = target.split('.')
        start_ip = ipaddress.IPv4Address('.'.join(
            ip_parts[:-1] + [ip_parts[-1].split('-')[0]]
        ))
        end_ip = ipaddress.IPv4Address('.'.join(
            ip_parts[:-1] + [ip_parts[-1].split('-')[1]]
        ))
        ips = [ipaddress.IPv4Address(ip) for ip in range(
            int(start_ip), int(end_ip) + 1
        )]
    else:
        # Single IP or subnet
        ips = [ip for ip in ipaddress.IPv4Network(target)]

    # First check which IPs are up (unless forced)
    online_ips = scan_hosts(ips, verbose, max_threads, force)

    # For each IP that is up (or forced), scan the specified ports
    for ip in online_ips:
        print("\nScanning chosen ports for target {} ...".format(ip))
        scan_ports(ip, ports, verbose, max_threads)


def parse_ports(port_arg):
    """
    Parse the ports argument into a list of ports (integers).
    Can handle single values (80) or ranges (1000-2000).
    """
    ports = []
    for p in port_arg.split(','):
        if '-' in p:
            start, end = map(int, p.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(p))
    return ports


def main():
    """
    Main entry point: parse command-line arguments, then run the scan.
    """
    parser = argparse.ArgumentParser(description="TCP Connect Scan (no scapy)")

    parser.add_argument("-t", "--target", required=True,
                        help="Target IP (e.g. 192.168.1.1), IP range (e.g. 192.168.1.0/24, 192.168.1.1-5) "
                             "or IP list (e.g. 192.168.1.1,192.168.1.2)")
    parser.add_argument("-p", "--ports",
                        help="Ports or ranges to scan (e.g. 22,80,1000-2000)")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Scan all ports (1-65535)")
    parser.add_argument("-top20", "--top20", action="store_true",
                        help="Scan the top 20 most common ports")
    parser.add_argument("-top50", "--top50", action="store_true",
                        help="Scan the top 50 most common ports")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("-f", "--force", action="store_true",
                        help="Force scan even if host seems down")
    parser.add_argument("-m", "--max-threads", type=int, default=10,
                        help="Maximum number of concurrent threads (default 10)")

    args = parser.parse_args()

    # Decide which ports to scan based on the flags
    if args.ports:
        ports = parse_ports(args.ports)
    elif args.all:
        ports = list(range(1, 65536))
    elif args.top20:
        ports = TOP_20_PORTS
    elif args.top50:
        ports = TOP_50_PORTS
    else:
        print("Error: No ports specified.")
        parser.print_help()
        return

    start_time = time.time()
    print("Starting TCP connect scan of {} ...".format(args.target))

    scan_target(args.target, ports, args.verbose, args.max_threads, args.force)

    duration = time.time() - start_time
    print("\nScan completed in {:.2f} seconds".format(duration))


if __name__ == '__main__':
    main()
