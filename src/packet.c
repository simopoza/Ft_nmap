#include "../includes/ft_nmap.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <stdio.h>

// Helpers for checksum
static uint16_t checksum(void *vdata, size_t length)
{
    // From RFC 1071
    char *data = (char *)vdata;
    uint32_t sum = 0;

    while (length > 1) {
        sum += (uint16_t)((data[0] << 8) | (data[1] & 0xFF));
        data += 2;
        length -= 2;
    }
    if (length > 0) {
        sum += (uint8_t)data[0] << 8;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum & 0xFFFF;
}

// TCP checksum including pseudo-header
static uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, const uint8_t *payload, int payload_len)
{
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t protocol;
        uint16_t length;
    } pseudo;

    pseudo.src = iph->saddr;
    pseudo.dst = iph->daddr;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.length = htons(sizeof(struct tcphdr) + payload_len);

    int total_len = sizeof(pseudo) + sizeof(struct tcphdr) + payload_len;
    uint8_t *buf = malloc(total_len);
    if (!buf) return 0;

    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcph, sizeof(struct tcphdr));
    if (payload_len > 0 && payload)
        memcpy(buf + sizeof(pseudo) + sizeof(struct tcphdr), payload, payload_len);

    uint16_t sum = checksum(buf, total_len);
    free(buf);
    return sum;
}

int send_syn_packet(int raw_sock, const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port)
{
    return send_tcp_packet(raw_sock, src_ip, dst_ip, src_port, dst_port, 0x02);
}

int send_tcp_packet(int raw_sock, const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t flags)
{
    // Build IP + TCP headers in a buffer
    uint8_t packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Fill IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = inet_addr(dst_ip);
    iph->check = 0;
    iph->check = checksum(iph, sizeof(struct iphdr));

    // Fill TCP header
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(0x1000 + dst_port); // pseudo-random seq
    tcph->doff = 5;
    tcph->syn = (flags & 0x02) ? 1 : 0;
    tcph->fin = (flags & 0x01) ? 1 : 0;
    tcph->psh = (flags & 0x08) ? 1 : 0;
    tcph->urg = (flags & 0x20) ? 1 : 0;
    tcph->ack = (flags & 0x10) ? 1 : 0;
    tcph->window = htons(64240);
    tcph->check = 0;

    // TCP checksum
    tcph->check = tcp_checksum(iph, tcph, NULL, 0);

    // Destination
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = tcph->dest;
    sin.sin_addr.s_addr = iph->daddr;

    // Send
    ssize_t sent = sendto(raw_sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                          (struct sockaddr *)&sin, sizeof(sin));
    if (sent < 0)
        return -1;
    return 0;
}

int send_udp_probe(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in local, dest;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(src_port);
    local.sin_addr.s_addr = inet_addr(src_ip);

    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
        close(sock);
        return -1;
    }

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    dest.sin_addr.s_addr = inet_addr(dst_ip);

    // send an empty datagram
    ssize_t s = sendto(sock, "", 0, 0, (struct sockaddr *)&dest, sizeof(dest));
    close(sock);
    if (s < 0) return -1;
    return 0;
}
