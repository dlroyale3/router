

# Router Project

## Assignment & Requirements

This project is based on the assignment described here: [PCOM Homework 1 - Router Dataplane](https://pcom.pages.upb.ro/tema1/). Please consult the official requirements for full details, deadlines, and grading policies.

### Assignment Context
The goal is to implement the dataplane of a router, which is the component responsible for forwarding packets according to a static routing table. You do **not** need to implement routing algorithms (RIP, OSPF, BGP); the routing table is provided as input and does not change during execution.

The router operates with multiple interfaces, receives packets on any of them, and forwards them according to the rules in the routing table. The project is designed for educational purposes and is typically run in a simulated network environment (e.g., Mininet).

### Key Requirements
- Parse and use a static routing table from a file.
- Forward IP packets using the longest prefix match algorithm.
- Handle ARP requests and replies to resolve MAC addresses for next hops.
- Generate and respond to ICMP messages (Echo Reply, Time Exceeded, Destination Unreachable).
- Queue packets waiting for ARP resolution and send them once the MAC address is known.
- Respond to ARP requests for local IPs.
- Maintain an ARP cache to avoid redundant requests.
- All packet headers must be handled in network byte order.
- The router must be single-threaded and use blocking I/O for packet reception.

## Recommended Reading
Before starting, review the following resources:
- [The Internet Protocol (YouTube)](https://www.youtube.com/watch?v=rPoalUa4m8E&list=PLowKtXNTBypH19whXTVoG3oKSuOcw_XeW&index=8)
- [ARP: Mapping between IP and Ethernet (YouTube)](https://www.youtube.com/watch?v=aamG4-tH_m8&list=PLowKtXNTBypH19whXTVoG3oKSuOcw_XeW&index=9)
- [Hop-by-hop routing (YouTube)](https://www.youtube.com/watch?v=VWJ8GmYnjTs&list=PLowKtXNTBypH19whXTVoG3oKSuOcw_XeW&index=11)
- [Looking at ARP and ping packets (YouTube)](https://www.youtube.com/watch?v=xNbdeyEI-nE&list=PLowKtXNTBypH19whXTVoG3oKSuOcw_XeW&index=12)
- Computer Networking: A Top-Down Approach (6th Edition), Chapters 4.3, 4.4.3, 5.4.1

## Technical Details

### Packet Processing Flow
1. **Initialization:**
  - The router sets up its network interfaces and loads the static routing table from a file.
2. **Packet Reception:**
  - The router listens for packets on all interfaces. Each packet is parsed to determine its type (IP or ARP).
3. **IP Packet Handling:**
  - Checks if the packet is destined for the router (by IP address).
  - If so, and the packet is an ICMP Echo Request, sends an ICMP Echo Reply.
  - Verifies the IP header checksum and decrements the TTL. If TTL expires, sends an ICMP Time Exceeded message.
  - Uses longest prefix match to find the best route for forwarding. If no route is found, sends ICMP Destination Unreachable.
  - If the next hop's MAC address is unknown, sends an ARP request and queues the packet. Otherwise, forwards the packet.
4. **ARP Packet Handling:**
  - Responds to ARP requests for its own IP addresses with an ARP reply.
  - On receiving an ARP reply, updates the ARP cache and sends any queued packets waiting for that MAC address.

### Data Structures
- **Routing Table:** Array of entries, each with prefix, mask, next hop, and interface.
- **ARP Cache:** Stores IP-to-MAC mappings for quick lookup.
- **Packet Queue:** Holds packets waiting for ARP resolution.
- **Packet Structure:** Contains pointers to parsed Ethernet, IP, and ARP headers for easy manipulation.

### Error Handling
- All critical operations use error checking macros (see `DIE` macro in `lib.h`).
- ICMP error messages are generated for TTL expiration and unreachable destinations.

### Performance
- Routing table is sorted and searched using longest prefix match for efficiency.
- ARP cache prevents redundant ARP requests and speeds up forwarding.

## Project Structure
- `router.c` / `router2.c`: Main router logic, including packet parsing, forwarding, ARP/ICMP handling, and queue management.
- `include/`: Header files defining data structures and function prototypes:
  - `lib.h`: Core router functions, interface management, checksum calculation, routing/ARP table parsing.
  - `protocols.h`: Ethernet, IP, ARP, and ICMP header structures.
  - `list.h`, `queue.h`: Generic list and queue data structures for packet management.
- `lib/`: Implementation of utility functions:
  - `lib.c`: Interface setup, packet send/receive, checksum, routing/ARP table parsing.
  - `list.c`, `queue.c`: List and queue operations.
- `Makefile`: Build and run instructions for the router.

## Building and Running
To build the project, run:

```sh
make
```

To run the router with a specific routing table and interfaces (example for router0):

```sh
make run_router0
```

or manually:

```sh
./router rtable0.txt rr-0-1 r-0 r-1
```

Replace `rtable0.txt` and interface names as needed for your setup.

## Testing and Simulation
The router is designed to be tested in a virtual network environment using [Mininet](http://mininet.org/). Mininet allows you to simulate complex network topologies and test your router implementation with real kernel and application code. See the assignment page for setup instructions and recommended tools (e.g., `tshark`, `xterm`).

## Notes
- All packet headers are handled in network byte order; conversion is performed as needed.
- The router is single-threaded and uses blocking I/O for packet reception.
- The code is intended for learning and experimentation, not for production use.
- For full requirements, deadlines, and grading, see [PCOM Homework 1 - Router Dataplane](https://pcom.pages.upb.ro/tema1/).

## Authors
Dumitru Luca (and contributors)

## License
This project is for educational use only.

## Overview
This project implements a simplified software router in C, designed for educational purposes. It handles basic packet forwarding, ARP resolution, and ICMP error handling, simulating the behavior of a real network router. The router processes Ethernet frames, IP packets, and ARP requests/replies, and uses a routing table to determine packet forwarding paths.

## Features
- **Packet Forwarding:** Forwards IP packets based on the longest prefix match in the routing table.
- **ARP Handling:** Resolves MAC addresses using ARP requests and replies, maintaining a cache for efficiency.
- **ICMP Support:** Generates ICMP Echo Replies, Time Exceeded, and Destination Unreachable messages as needed.
- **Queue Management:** Queues packets waiting for ARP resolution and sends them once the MAC address is known.

## Project Structure
- `router.c` / `router2.c`: Main router logic, including packet parsing, forwarding, ARP/ICMP handling, and queue management.
- `include/`: Header files defining data structures and function prototypes:
  - `lib.h`: Core router functions, interface management, checksum calculation, routing/ARP table parsing.
  - `protocols.h`: Ethernet, IP, ARP, and ICMP header structures.
  - `list.h`, `queue.h`: Generic list and queue data structures for packet management.
- `lib/`: Implementation of utility functions:
  - `lib.c`: Interface setup, packet send/receive, checksum, routing/ARP table parsing.
  - `list.c`, `queue.c`: List and queue operations.
- `Makefile`: Build and run instructions for the router.

## Main Logic
1. **Initialization:**
    - Sets up network interfaces and loads the routing table.
2. **Packet Reception:**
    - Receives packets from any interface and parses Ethernet, IP, and ARP headers.
3. **IP Packet Handling:**
    - Verifies destination, checksum, and TTL.
    - Performs longest prefix match to find the next hop.
    - If MAC address for next hop is unknown, sends ARP request and queues the packet.
    - If MAC address is known, forwards the packet.
    - Generates ICMP errors if needed (TTL expired, destination unreachable).
4. **ARP Packet Handling:**
    - Responds to ARP requests for local IPs.
    - Updates cache on ARP replies and sends queued packets waiting for MAC resolution.

## Notes
- All packet headers are handled in network byte order; conversion is performed as needed.
- The router is single-threaded and uses blocking I/O for packet reception.
- The code is intended for learning and experimentation, not for production use.

## Authors
Dumitru Luca (and contributors)
