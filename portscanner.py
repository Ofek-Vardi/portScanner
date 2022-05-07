#!/usr/bin/python3

import socket
from termcolor import colored as clr
import sys
import ipaddress
import argparse


def verify_ipv4(addr: str) -> bool:
    """
    Ths function verifies whether the specified IP address is a valid IPv4 address.
    :param addr: Specified IP address
    :type addr: string
    :return: True if 'addr' is a valid IPv4 address, False otherwise
    :rtype: bool
    """
    try:
        ipaddress.IPv4Address(addr)
        return True
    except ipaddress.AddressValueError as err:
        print(clr(f"[!] Invalid IPv4 address - {err}", "red"))
        return False


def scan_port(ipaddr: str, port: int) -> None:
    """
    This function scans the target address & port, and grabs the banner if the port is open.
    :param ipaddr: IP address string
    :type ipaddr: string
    :param port: Port number
    :type port: int
    :return: None
    """
    global SUMMARY
    data = b""
    try:
        if PROTOCOL.upper() == "TCP":
            sock = socket.socket()  # IPv4 & TCP by default
            sock.settimeout(1)
            sock.connect((ipaddr, port))
            data = sock.recv(1024)  # Get banner

        elif PROTOCOL.upper() == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # IPv4 & UDP
            sock.settimeout(1)
            try:
                sock.connect((ipaddr, port))
                if VERBOSE:
                    print(f"{clr('[*] Connected:', 'yellow')} {ipaddr}{clr(':', 'yellow')}{port}")
                # Verify connectivity
                packet = b"Hello"
                sock.sendto(packet, (ipaddr, port))
                if VERBOSE:
                    print(f"{clr('[*] Sent packet:', 'yellow')} {packet}")
                data, addr = sock.recvfrom(2048)  # Get banner
                if VERBOSE:
                    print(clr(f"[*] Received response!", "yellow"))
            except socket.timeout as err:  # Port is open, but no banner was received
                if DEBUG:
                    print(err)
        else:
            print(clr(f"[!] Invalid protocol specified: ", "red") + PROTOCOL)
            sys.exit()

        # The following code is only executed for open ports
        try:
            data = data.decode()
        except UnicodeDecodeError as err:  # Coding method other than 'utf-8'
            if DEBUG:
                print(err)
            data = str(data)

        # Summarise data collected for the current '(ipaddr, port)'
        res = f"{clr('[+] Open port -', 'green')} {ipaddr}{clr(':', 'green')}{str(port)}{clr('/', 'green')}" \
              f"{socket.getservbyport(port, PROTOCOL.lower())}{clr(', Banner: ', 'green') + data.strip()}"
        if VERBOSE:
            print(res)
        SUMMARY += (res + "\n")
        sock.close()
    except Exception as err:  # Port is closed
        if DEBUG:
            print(err)


def scan(target: str, start: int, end: int) -> None:
    """
    This function initiates a port scan for each port in 'ports' on 'target'.
    :param target: IP address string
    :type target: string
    :param start: Starting port
    :type start: int
    :param end: Final port
    :type end: int
    :return: None
    """
    if verify_ipv4(target):
        print(clr("[*] Scanning target - ", "yellow") + target)
        for port in range(start, end + 1):
            if VERBOSE:
                print(clr("[*] Scanning port - ", "yellow") + str(port))
            scan_port(target, port)


def verify_ports(ports: str) -> tuple[int, int]:
    """
    Verifies the specified ports are valid.
    :param ports: Range of ports
    :type ports: string
    :return: Start port, End port
    :rtype: tuple(int, int)
    """
    # Verify specified ports
    try:
        if "-" in ports:
            ports = ports.split("-")
            start = int(ports[0])
            end = int(ports[1])
        else:
            start = end = int(ports)
    except ValueError:
        print(f"{clr('[!] Invalid port specified:', 'red')} {ports}")
        sys.exit()
    return start, end


def main() -> None:
    """
    This script receives a range of ports, a protocol and a list of targets, then proceeds to scan them.
    :return: None
    """
    sport, eport = verify_ports(PORTS)
    if "," in TARGETS:
        print(clr("[*] Scanning multiple targets", "yellow"))
        for target in TARGETS.split(","):
            scan(target.strip(" "), sport, eport)
    else:
        scan(TARGETS.strip(" "), sport, eport)

    # Results summary
    print(clr("\n[*] Summary:", "yellow"))
    if SUMMARY == "":
        print(clr("[!] No open ports found!", "red"))
    else:
        print(SUMMARY)


if __name__ == "__main__":
    # Initialize the parser
    parser = argparse.ArgumentParser(
        description="Description: Python Port Scanner"
    )
    # Add the parameters positional/optional
    parser.add_argument("targets", help="Comma separated list of IPv4 addresses (addr1,addr2...)", type=str,
                        default="300.1.1.1,1.-1.0.1,1.2,192.168.247.129")  # Default value used for testing
    parser.add_argument('-p', '--ports', help="Range of Ports (int-int / int)", type=str, default="1-100")
    parser.add_argument('-r', '--protocol', help="Transport Protocol (Default: TCP / UDP)", default="TCP")
    parser.add_argument('-v', '--verbose', help="Increase verbosity level", type=int, default=0, nargs='?',
                        const=1)
    parser.add_argument('-d', '--debug', help="Print debugging notes", type=int, default=0, nargs='?',
                        const=1)
    # Parse the arguments
    args = parser.parse_args()

    # Global variables
    TARGETS = args.targets
    PORTS = args.ports
    PROTOCOL = args.protocol
    VERBOSE = args.verbose
    DEBUG = args.debug
    SUMMARY = ""

    if DEBUG:
        print(args)

    try:
        main()
    except KeyboardInterrupt:
        pass  # graceful shutdown
