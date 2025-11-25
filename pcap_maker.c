#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/time.h>

#pragma pack(push, 1)  // Ensure no padding

// --- PCAP structures ---
struct pcap_global_header {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

// --- Ethernet ---
struct ethernet_frame {
    uint64_t dest_mac : 48;
    uint64_t src_mac : 48;
    uint16_t ethertype;
};

// --- IPv4 ---
struct ipv4_header {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

// --- UDP ---
struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

// --- DHCP ---
struct dhcp_packet {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[64];
};

// DHCP message types
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7
#define DHCP_INFORM   8

// DHCP options
#define DHCP_OPTION_MSG_TYPE 53
#define DHCP_OPTION_END      255

// --- Helpers ---
uint32_t ip_to_decimal(const char *ip_address) {
    struct in_addr ip_struct;
    inet_pton(AF_INET, ip_address, &ip_struct);
    return ntohl(ip_struct.s_addr);
}

uint64_t mac_to_decimal(const char *mac_address) {
    unsigned int octets[6];
    if (sscanf(mac_address, "%x:%x:%x:%x:%x:%x",
               &octets[0], &octets[1], &octets[2],
               &octets[3], &octets[4], &octets[5]) != 6) {
        printf("Invalid MAC address format.\n");
        return 0;
    }
    uint64_t mac = 0;
    for (int i = 0; i < 6; i++)
        mac |= ((uint64_t)octets[i]) << ((5 - i) * 8);
    return mac;
}

void write_pcap_global_header(FILE *file) {
    struct pcap_global_header gh = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1
    };
    fwrite(&gh, sizeof(gh), 1, file);
}

void write_pcap_packet(FILE *file, struct ethernet_frame *eth, struct ipv4_header *ip,
                       struct udp_header *udp, struct dhcp_packet *dhcp, uint32_t packet_size) {
    struct pcap_packet_header ph;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    ph.ts_sec = tv.tv_sec;
    ph.ts_usec = tv.tv_usec;
    ph.incl_len = packet_size;
    ph.orig_len = packet_size;

    fwrite(&ph, sizeof(ph), 1, file);
    fwrite(eth, sizeof(*eth), 1, file);
    fwrite(ip, sizeof(*ip), 1, file);
    fwrite(udp, sizeof(*udp), 1, file);
    fwrite(dhcp, sizeof(*dhcp), 1, file);
}

// Fill a DHCP packet (client-side by default)
void fill_dhcp_packet(struct dhcp_packet *dhcp, uint8_t type, uint64_t client_mac,
                      uint32_t offered_ip, uint32_t server_ip, int is_server) {
    memset(dhcp, 0, sizeof(*dhcp));
    dhcp->op = is_server ? 2 : 1;  // BOOTREPLY=2, BOOTREQUEST=1
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    dhcp->xid = htonl(rand());
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000);
    dhcp->ciaddr = 0;
    dhcp->yiaddr = htonl(offered_ip); // only for server responses
    dhcp->siaddr = htonl(server_ip);  // only for server responses
    dhcp->giaddr = 0;

    memcpy(dhcp->chaddr, &client_mac, 6);

    // DHCP options
    dhcp->options[0] = DHCP_OPTION_MSG_TYPE;
    dhcp->options[1] = 1;
    dhcp->options[2] = type;
    dhcp->options[3] = DHCP_OPTION_END;
}

int main() {
    srand(time(NULL));
    char input[128];
    FILE *pcap_file = fopen("dhcp_packet.pcap", "wb");
    if (!pcap_file) { perror("Failed to open PCAP file"); return 1; }

    write_pcap_global_header(pcap_file);

    printf("Enter destination MAC (xx:xx:xx:xx:xx:xx): "); scanf("%s", input);
    uint64_t dest_mac = mac_to_decimal(input);

    printf("Enter source MAC (xx:xx:xx:xx:xx:xx): "); scanf("%s", input);
    uint64_t src_mac = mac_to_decimal(input);

    printf("Enter source IP (x.x.x.x): "); scanf("%s", input);
    uint32_t src_ip = ip_to_decimal(input);

    printf("Enter destination IP (x.x.x.x): "); scanf("%s", input);
    uint32_t dest_ip = ip_to_decimal(input);

    printf("Select DHCP type (1=DISCOVER,2=OFFER,3=REQUEST,5=ACK): "); int dhcp_type; scanf("%d", &dhcp_type);

    int is_server = (dhcp_type == DHCP_OFFER || dhcp_type == DHCP_ACK);
    uint32_t offered_ip = 0; // For server responses
    uint32_t server_ip = 0;

    if(is_server) {
        printf("Enter offered IP (x.x.x.x): "); scanf("%s", input); offered_ip = ip_to_decimal(input);
        printf("Enter DHCP server IP (x.x.x.x): "); scanf("%s", input); server_ip = ip_to_decimal(input);
    }

    struct ethernet_frame eth = { dest_mac, src_mac, htons(0x0800) };
    struct ipv4_header ip = {
        .version_ihl = 0x45,
        .dscp_ecn = 0,
        .total_length = htons(sizeof(struct ipv4_header) + sizeof(struct udp_header) + sizeof(struct dhcp_packet)),
        .identification = htons(54321),
        .flags_fragment_offset = htons(0x4000),
        .ttl = 64,
        .protocol = 17,
        .header_checksum = 0,
        .src_ip = htonl(src_ip),
        .dest_ip = htonl(dest_ip)
    };
    struct udp_header udp = {
        .src_port = htons(is_server ? 67 : 68),
        .dest_port = htons(is_server ? 68 : 67),
        .length = htons(sizeof(struct udp_header) + sizeof(struct dhcp_packet)),
        .checksum = 0
    };
    struct dhcp_packet dhcp;
    fill_dhcp_packet(&dhcp, dhcp_type, src_mac, offered_ip, server_ip, is_server);

    uint32_t packet_size = sizeof(eth) + sizeof(ip) + sizeof(udp) + sizeof(dhcp);
    write_pcap_packet(pcap_file, &eth, &ip, &udp, &dhcp, packet_size);

    fclose(pcap_file);
    printf("PCAP file 'dhcp_packet.pcap' created successfully.\n");
    return 0;
}

