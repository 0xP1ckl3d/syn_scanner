#! /bin/python3

import argparse
import time
import ipaddress
import threading
import traceback
from queue import Queue
from scapy.all import *

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Filters out scapy error messages when it cannot ping a host

# List of the top 20 most commonly used ports (source nmap)
TOP_20_PORTS = [21,22,23,25,80,110,139,443,445,1433,3306,3389,5900,8080,8443,8888]

# List of the top 50 most commonly used ports (source nmap)
TOP_50_PORTS = [21,22,23,25,26,53,80,81,110,111,113,135,139,143,179,199,443,445,465,514,515,548,554,587,646,993,995,1025,1026,1027,1433,1720,1723,2000,2001,3306,3389,5060,5666,5900,6001,8000,8008,8080,8443,8888,10000,32768,49152,49154]


def is_up(ip, verbose, semaphore, queue):
    """Check if a host is up by sending it an ICMP packet (ping request).

    Args:
        ip (str): The IP address of the host.
        verbose (bool): If True, print verbose output.
        semaphore (Semaphore): A threading semaphore.
        queue (Queue): A Queue to hold the result of each ping.
    """
    # Acquire a thread lock to ensure only one thread can execute the following code at once
    semaphore.acquire()
    # Create an ICMP packet (ping request) to the target IP
    icmp = IP(dst=str(ip))/ICMP()
    # Send the ICMP packet and capture the response
    resp = sr1(icmp, timeout=10, verbose=0)
    # Release the thread lock so other threads can acquire it
    semaphore.release()
    if resp is not None:
        # If there is a response, it means the host is up
        print(f"* Host {ip} is UP") 
        # Put the result (ip address and status) in the queue
        queue.put((ip, True))
    else:
        # If there is no response, it means the host is down
        if verbose:  # only print when host is down if verbose mode is enabled
            print(f"* Host {ip} is DOWN")
        # Put the result (ip address and status) in the queue
        queue.put((ip, False))


def scan_port(ip, port, verbose, semaphore):
    """Scan a port by sending a TCP SYN packet and analyzing the response.

    Args:
        ip (str): The IP address of the host.
        port (int): The port to scan.
        verbose (bool): If True, print verbose output.
        semaphore (Semaphore): A threading semaphore.
    """
    try:
        # Create a TCP SYN packet to the target IP and port
        pkt = IP(dst=str(ip)) / TCP(dport=port, flags='S')
        # Send the TCP SYN packet and capture the response
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp is None:
            # If there is no response, it means the port is closed
            if verbose:
                print(f"Port {port} - CLOSED")
        elif resp.haslayer(TCP):
            # If there is a response and it has a TCP layer
            if resp.getlayer(TCP).flags == 0x12:
                # If the flags field has the SYN-ACK flag (0x12), it means the port is open
                # Send a RST-ACK packet to close the connection
                send_rst = sr(IP(dst=str(ip)) / TCP(dport=port, flags='AR'), timeout=1, verbose=0)
                print(f"Port {port} - OPEN")
            elif resp.getlayer(TCP).flags == 0x14:
                # If the flags field has the RST-ACK flag (0x14), it means the port is closed
                if verbose:
                    print(f"Port {port} - CLOSED")
    except Exception as e:
        # If there is an exception during the execution, print the error message
        print(f"An error occurred while scanning port {port}: {e}")
        # Print the stack trace of the exception
        traceback.print_exc()
    finally:
        # Release the thread lock so other threads can acquire it
        semaphore.release()


def scan_ports(ip, ports, verbose, max_threads):
    """Scan multiple ports on a host.

    Args:
        ip (str): The IP address of the host.
        ports (list of int): The ports to scan.
        verbose (bool): If True, print verbose output.
        max_threads (int): The maximum number of concurrent threads.
    """
    # Create a semaphore with the maximum number of threads that can run concurrently
    semaphore = threading.Semaphore(max_threads)
    # Initialize an empty list to hold the thread objects
    threads = []
    for port in ports:
        # Acquire the semaphore before creating a new thread
        semaphore.acquire()
        # For each port in the list of ports, create a new thread that calls the scan_port function
        thread = threading.Thread(target=scan_port, args=(ip, port, verbose, semaphore))
        # Try to start the newly created thread
        try:
            thread.start()
            # Add the thread to the list of threads
            threads.append(thread)
        except Exception as e:
            print(f"Failed to start thread for port {port} with error: {e}")
            semaphore.release()
    # Wait for all the threads in the list to complete their tasks
    for thread in threads:
        thread.join()


def scan_hosts(ips, verbose, max_threads, force):
    """Scan multiple hosts to see if they're up.

    Args:
        ips (list of str): The IP addresses of the hosts.
        verbose (bool): If True, print verbose output.
        max_threads (int): The maximum number of concurrent threads.
        force (bool): If True, scan hosts even if they seem down.
    Returns:
        list of str: The IP addresses of hosts that are up.
    """
    # Create a semaphore with the maximum number of threads that can run concurrently
    semaphore = threading.Semaphore(max_threads)
    # Initialize an empty list to hold the thread objects
    threads = []
    # Create a queue to hold the results from the is_up function
    results_queue = Queue()
    for ip in ips:
        # For each IP in the list of IPs, create a new thread that calls the is_up function
        thread = threading.Thread(target=is_up, args=(ip, verbose, semaphore, results_queue), daemon=True)
        # Start the newly created thread
        thread.start()
        # Add the thread to the list of threads
        threads.append(thread)
    # Wait for all the threads in the list to complete their tasks
    for thread in threads:
        thread.join()
    # Initialize an empty list to hold the IPs of online hosts
    online_ips = []
    # Retrieve the results from the queue
    while not results_queue.empty():
        ip, is_host_up = results_queue.get()
        # If a host is up or if the force option is true, add the IP to the list of online IPs
        if is_host_up or force:
            online_ips.append(ip)
    # Return the list of online IPs
    return online_ips


def scan_target(target, ports, verbose, max_threads, force):
    """Scan a target (IP or IP range) on multiple ports.

    Args:
        target (str): The IP or IP range of the target.
        ports (list of int): The ports to scan.
        verbose (bool): If True, print verbose output.
        max_threads (int): The maximum number of concurrent threads.
        force (bool): If True, scan hosts even if they seem down.
    """
    if ',' in target: # Check if the target contains a comma, indicating a list of IPs
        # Convert each IP in the list to a IPv4Address object
        ips = [ipaddress.IPv4Address(ip.strip()) for ip in target.split(',')]
    elif '-' in target:  # Check if the target contains a hyphen, indicating a range of IPs
        # Break the target into individual parts
        ip_parts = target.split('.')
        # Create the start IP of the range
        start_ip = ipaddress.IPv4Address('.'.join(ip_parts[:-1] + [ip_parts[-1].split('-')[0]]))
        # Create the end IP of the range
        end_ip = ipaddress.IPv4Address('.'.join(ip_parts[:-1] + [ip_parts[-1].split('-')[1]]))
        # Generate all IPs in the range
        ips = [ipaddress.IPv4Address(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
    else:  # If the target is a single IP or a subnet
        # Generate all IPs in the subnet
        ips = [ip for ip in ipaddress.IPv4Network(target)]
    # Perform a host scan on the generated IPs
    online_ips = scan_hosts(ips, verbose, max_threads, force)
    for ip in online_ips:
        print(f"\nScanning chosen ports for target {ip} ...")
        # Perform a port scan on each online IP
        scan_ports(ip, ports, verbose, max_threads)


def parse_ports(port_arg):
    """Parse the ports argument into a list of ports.

    Args:
        port_arg (str): The ports argument as a string.
    
    Returns:
        list of int: The parsed ports.
    """
    # Initialize an empty list to hold the parsed ports
    ports = []
    # Split the port_arg on the comma to separate individual ports or ranges
    for p in port_arg.split(','):
        if '-' in p:  # Check if the port is a range
            # Split the range into start and end, then generate all ports in the range
            start, end = map(int, p.split('-'))
            ports.extend(range(start, end + 1))
        else:  # If the port is not a range
            ports.append(int(p)) # Convert the port to an integer and add it to the list
    # Return the list of parsed ports
    return ports


def main():
    """
    The main function of the script. Parses command-line arguments and initiates the scan.
    """
    # Setting up a parser for command-line arguments
    parser = argparse.ArgumentParser(description="SYN Scan with Scapy")
    
    # Each add_argument call adds a command-line argument
    # The `required` argument specifies whether or not the command-line option is required
    # The `help` argument provides a description of the command-line option
    parser.add_argument("-t", "--target", required=True, help="Target IP (e.g. 192.168.1.1), IP range (e.g. 192.168.1.0/24, 192.168.1.1-5) or IP list (e.g. 192.168.1.1,192.168.1.2)")
    parser.add_argument("-p", "--ports", help="Ports or ranges to scan (e.g. 22,80,1000-2000)")
    parser.add_argument("-a", "--all", action="store_true", help="Scan all ports")
    parser.add_argument("-top20", "--top20", action="store_true", help="Perform a scan of top 20 ports")
    parser.add_argument("-top50", "--top50", action="store_true", help="Perform a scan of top 50 ports")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-f", "--force", action="store_true", help="Force scan even if host seems down")
    parser.add_argument("-m", "--max-threads", type=int, default=10, help="Maximum number of concurrent threads (default 10)")

    # Parse the command-line arguments
    args = parser.parse_args()

    # Determine the ports to scan based on the given arguments
    # The `ports` argument takes precedence over `all`, `top20`, and `top50`
    # If no port-related argument is provided, an error message is printed and the program exits
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

    # Record the start time of the scan
    start_time = time.time()
    print(f"SYN scan of {args.target} ...")

    # Start scanning the target with the specified ports, verbosity, thread limit, and force option
    scan_target(args.target, ports, args.verbose, args.max_threads, args.force)
    
    # Print out the time it took to complete the scan
    print(f"\nScan completed in {time.time() - start_time:.2f} seconds")


if __name__ == '__main__':
    main()
