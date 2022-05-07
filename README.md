# Python Port Scanner

## Description

This is a port scanner written in python.\
Please run this tool using python3 and above.

## Imports

- socket
- sys
- ipaddress
- argparse
- termcolor.colored

## Command Line Arguments

    positional arguments:
    targets               Comma separated list of IPv4 addresses (addr1,addr2...)

    options:
    -h, --help            show this help message and exit
    -p PORTS, --ports PORTS
                            Range of Ports (int-int / int)
    -r PROTOCOL, --protocol PROTOCOL
                            Transport Protocol (Default: TCP / UDP)
    -v [VERBOSE], --verbose [VERBOSE]
                            Increase verbosity level
    -d [DEBUG], --debug [DEBUG]
                            Print debugging notes

## Examples

**Display help message:**

    python3 portScanner.py -h

**Scan ports 20-50:**

    python3 portScanner.py 127.0.0.1 -p 20-50

**Set UDP port 53:**

    python3 portScanner.py 127.0.0.1 -p 53 -r UDP
