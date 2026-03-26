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
    /* Try multiple UDP probes with exponential backoff. If binding to the requested
       source port fails (e.g., reserved socket already bound), fall back to sending
       from an ephemeral source port so the probe still reaches the target. */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    dest.sin_addr.s_addr = inet_addr(dst_ip);

    int attempts = 3;
    int backoff_ms[] = {0, 200, 500};
    for (int a = 0; a < attempts; a++)
    {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return -1;

        if (a > 0) usleep(backoff_ms[a] * 1000);

        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_port = htons(src_port);
        local.sin_addr.s_addr = inet_addr(src_ip);

        /* Try to bind to requested source port; if it fails we'll send from ephemeral port */
        (void)bind(sock, (struct sockaddr *)&local, sizeof(local));

        /* Choose a small payload for certain well-known UDP services to elicit a reply.
           For example, send a minimal DNS query when probing port 53. For other ports
           we keep an empty payload to minimize noise. */
        const uint8_t *payload = NULL;
        size_t payload_len = 0;

        if (dst_port == 53)
        {
            /* Minimal DNS query for A record of "www.example.com" */
            static const uint8_t dns_query[] = {
                0x12, 0x34, /* Transaction ID */
                0x01, 0x00, /* Standard query, recursion desired */
                0x00, 0x01, /* QDCOUNT: 1 */
                0x00, 0x00, /* ANCOUNT: 0 */
                0x00, 0x00, /* NSCOUNT: 0 */
                0x00, 0x00, /* ARCOUNT: 0 */
                /* QNAME: www.example.com */
                0x03, 'w','w','w',
                0x07, 'e','x','a','m','p','l','e',
                0x03, 'c','o','m',
                0x00,
                0x00, 0x01, /* QTYPE A */
                0x00, 0x01  /* QCLASS IN */
            };
            payload = dns_query;
            payload_len = sizeof(dns_query);
        }

        ssize_t s = sendto(sock, payload, payload_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        close(sock);
        if (s >= 0)
            return 0;

        /* on failure, try again with backoff */
    }
    return -1;
}
