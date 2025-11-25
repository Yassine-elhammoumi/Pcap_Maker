# DHCP PCAP Generator

This project is a simple C program that generates **DHCP packets** and saves them in a **PCAP file** compatible with Wireshark. It supports multiple DHCP message types including Discover, Request, Offer, and ACK.

This project was made to help me understand [this](https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html) specification.

## Features

- Generate DHCP **client messages**: DISCOVER, REQUEST
- Generate DHCP **server messages**: OFFER, ACK
- Save packets in **PCAP format** for analysis
- User-friendly CLI for entering MAC addresses, IPs, and DHCP type
- Modular code, easy to extend with other DHCP types

## Requirements

- GCC compiler
- Wireshark (optional, for viewing PCAP files)

## Usage

1. Compile the program:

```bash
gcc pcap_maker.c -o pcap_maker
```
2. Run the program:

```bash
./dhcp_pcap_generator
```

3. Follow the prompts:

- Enter destination MAC
- Enter source MAC
- Enter source IP
- Enter destination IP
- Select DHCP message type (1=DISCOVER, 2=OFFER, 3=REQUEST, 5=ACK)
  - If a server message, enter offered IP and server IP

The program will generate `dhcp_packet.pcap` which you can open in Wireshark.

Example

    Generate a DHCP Discover packet from a client:

```bash
Enter destination MAC: ff:ff:ff:ff:ff:ff
Enter source MAC: 00:11:22:33:44:55
Enter source IP: 0.0.0.0
Enter destination IP: 255.255.255.255
Select DHCP type (1=DISCOVER,2=OFFER,3=REQUEST,5=ACK): 1

Output: dhcp_packet.pcap ready to inspect in Wireshark.
```
