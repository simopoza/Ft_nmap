#include "../includes/ft_nmap.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

// pcap listener thread: receives packets and maps replies to scanned ports
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    (void)h; // unused
    t_nmap_args *args = (t_nmap_args *)user;
    /* Compute IP header offset based on datalink type */
    int l3_offset = 0;
    switch (args->pcap_dlt)
    {
#ifdef DLT_EN10MB
        case DLT_EN10MB: l3_offset = 14; break; /* Ethernet */
#endif
#ifdef DLT_RAW
        case DLT_RAW: l3_offset = 0; break; /* raw IP */
#endif
#ifdef DLT_NULL
        case DLT_NULL: l3_offset = 4; break; /* loopback (BSD style) */
#endif
#ifdef DLT_LOOP
        case DLT_LOOP: l3_offset = 4; break; /* loopback */
#endif
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL: l3_offset = 16; break; /* cooked capture */
#endif
        default: l3_offset = 0; break;
    }

    if (h->caplen < (size_t)l3_offset + sizeof(struct iphdr))
        return;

    const u_char *ip_ptr = bytes + l3_offset;
    /* quick sanity check: first nibble should be 4 (IPv4) */
    if ((ip_ptr[0] >> 4) != 4)
    {
        /* fallback: crude scan looking for IPv4 header */
        ip_ptr = NULL;
        for (int i = 0; i < 64 && i < (int)h->caplen; i++)
        {
            if (bytes[i] == 0x45) { ip_ptr = bytes + i; break; }
        }
        if (!ip_ptr) return;
    }

    struct iphdr *iph = (struct iphdr *)ip_ptr;

    int ip_header_len = iph->ihl * 4;
    if (h->caplen < (size_t)l3_offset + ip_header_len)
        return;

    /* Handle TCP replies */
    if (iph->protocol == IPPROTO_TCP)
    {
        if (h->caplen < (size_t)l3_offset + ip_header_len + sizeof(struct tcphdr))
            return;
        struct tcphdr *tcph = (struct tcphdr *)(ip_ptr + ip_header_len);
        uint16_t dst_port = ntohs(tcph->dest);
        uint8_t flags = *((uint8_t *)tcph + 13);
        int syn = flags & 0x02;
        int ack = flags & 0x10;
        int rst = flags & 0x04;
        uint16_t our_src = dst_port; // packet dest is our source port

        pthread_mutex_lock(&args->map_mutex);
        int map_v = args->srcport_map[our_src];
        if (map_v == -2)
        {
            /* Shared pool port: multiple map_v entries may map to this src port. Scan map_to_srcport. */
            if (args->map_to_srcport)
            {
                int total = args->port_count * SCAN_COUNT;
                for (int mv = 0; mv < total; mv++)
                {
                    if (args->map_to_srcport[mv] != our_src) continue;
                    int idx = mv / SCAN_COUNT;
                    int sidx = mv % SCAN_COUNT;
                    if (sidx == SCAN_IDX_SYN)
                    {
                        if (syn && ack)
                            args->results[idx].scan_results[sidx] = STATUS_OPEN;
                        else if (rst)
                            args->results[idx].scan_results[sidx] = STATUS_CLOSED;
                    }
                    else if (sidx == SCAN_IDX_ACK)
                    {
                        if (rst)
                            args->results[idx].scan_results[sidx] = STATUS_UNFILTERED;
                        else
                            args->results[idx].scan_results[sidx] = STATUS_FILTERED;
                    }
                    else
                    {
                        if (rst)
                            args->results[idx].scan_results[sidx] = STATUS_CLOSED;
                        else
                            args->results[idx].scan_results[sidx] = STATUS_OPEN;
                    }
                    /* mark this map entry as handled */
                    args->map_to_srcport[mv] = -1;
                }
            }
            args->srcport_map[our_src] = -1;
        }
        else if (map_v != -1)
        {
            int idx = map_v / SCAN_COUNT;
            int sidx = map_v % SCAN_COUNT;
            if (sidx == SCAN_IDX_SYN)
            {
                if (syn && ack)
                    args->results[idx].scan_results[sidx] = STATUS_OPEN;
                else if (rst)
                    args->results[idx].scan_results[sidx] = STATUS_CLOSED;
            }
            else if (sidx == SCAN_IDX_ACK)
            {
                if (rst)
                    args->results[idx].scan_results[sidx] = STATUS_UNFILTERED; // RST indicates unfiltered
                else
                    args->results[idx].scan_results[sidx] = STATUS_FILTERED;
            }
            else
            {
                if (rst)
                    args->results[idx].scan_results[sidx] = STATUS_CLOSED;
                else
                    args->results[idx].scan_results[sidx] = STATUS_OPEN; /* active reply -> likely open */
            }

            args->srcport_map[our_src] = -1;
        }
        pthread_mutex_unlock(&args->map_mutex);
        return;
    }

    /* Handle UDP replies (direct UDP response) */
    if (iph->protocol == IPPROTO_UDP)
    {
        if (h->caplen < (size_t)l3_offset + ip_header_len + sizeof(struct udphdr))
            return;
        struct udphdr *udph = (struct udphdr *)(ip_ptr + ip_header_len);
        uint16_t our_src = ntohs(udph->dest);
        pthread_mutex_lock(&args->map_mutex);
        int map_v = args->srcport_map[our_src];
        if (map_v == -2)
        {
            if (args->map_to_srcport)
            {
                int total = args->port_count * SCAN_COUNT;
                for (int mv = 0; mv < total; mv++)
                {
                    if (args->map_to_srcport[mv] != our_src) continue;
                    int idx = mv / SCAN_COUNT;
                    int sidx = mv % SCAN_COUNT;
                    args->results[idx].scan_results[sidx] = STATUS_OPEN;
                    args->map_to_srcport[mv] = -1;
                }
            }
            args->srcport_map[our_src] = -1;
        }
        else if (map_v != -1)
        {
            int idx = map_v / SCAN_COUNT;
            int sidx = map_v % SCAN_COUNT;
            if (sidx == SCAN_IDX_UDP)
            {
                args->results[idx].scan_results[sidx] = STATUS_OPEN; // UDP reply -> open
            }
            else
            {
                args->results[idx].scan_results[sidx] = STATUS_OPEN;
            }
            args->srcport_map[our_src] = -1;
        }
        pthread_mutex_unlock(&args->map_mutex);
        return;
    }

    /* Handle ICMP (e.g., port unreachable) */
    if (iph->protocol == IPPROTO_ICMP)
    {
        if (h->caplen < (size_t)l3_offset + ip_header_len + sizeof(struct icmphdr))
            return;
        struct icmphdr *icmph = (struct icmphdr *)(ip_ptr + ip_header_len);
        if (icmph->type == 3) /* Destination Unreachable */
        {
            int code = icmph->code;
            const u_char *inner = ip_ptr + ip_header_len + sizeof(struct icmphdr);
            if ((size_t)(inner - bytes) + sizeof(struct iphdr) > h->caplen) return;
            struct iphdr *inner_iph = (struct iphdr *)inner;
            int inner_ihl = inner_iph->ihl * 4;
            if ((size_t)(inner - bytes) + inner_ihl + 4 > h->caplen) return;

            if (inner_iph->protocol == IPPROTO_UDP)
            {
                struct udphdr *inner_udph = (struct udphdr *)((u_char *)inner + inner_ihl);
                uint16_t our_src = ntohs(inner_udph->source);
                pthread_mutex_lock(&args->map_mutex);
                int map_v = args->srcport_map[our_src];
                if (map_v == -2)
                {
                    if (args->map_to_srcport)
                    {
                        int total = args->port_count * SCAN_COUNT;
                        for (int mv = 0; mv < total; mv++)
                        {
                            if (args->map_to_srcport[mv] != our_src) continue;
                            int idx = mv / SCAN_COUNT;
                            int sidx = mv % SCAN_COUNT;
                            if (sidx == SCAN_IDX_UDP)
                            {
                                if (code == 3) args->results[idx].scan_results[sidx] = STATUS_CLOSED;
                                else args->results[idx].scan_results[sidx] = STATUS_FILTERED;
                            }
                            args->map_to_srcport[mv] = -1;
                        }
                    }
                    args->srcport_map[our_src] = -1;
                }
                else if (map_v != -1)
                {
                    int idx = map_v / SCAN_COUNT;
                    int sidx = map_v % SCAN_COUNT;
                    if (sidx == SCAN_IDX_UDP)
                    {
                        if (code == 3) args->results[idx].scan_results[sidx] = STATUS_CLOSED;
                        else args->results[idx].scan_results[sidx] = STATUS_FILTERED;
                    }
                    else
                        args->results[idx].scan_results[sidx] = STATUS_CLOSED;
                    args->srcport_map[our_src] = -1;
                }
                pthread_mutex_unlock(&args->map_mutex);
            }
            else if (inner_iph->protocol == IPPROTO_TCP)
            {
                struct tcphdr *inner_tcph = (struct tcphdr *)((u_char *)inner + inner_ihl);
                uint16_t our_src = ntohs(inner_tcph->source);
                pthread_mutex_lock(&args->map_mutex);
                int map_v = args->srcport_map[our_src];
                if (map_v != -1)
                {
                    int idx = map_v / SCAN_COUNT;
                    int sidx = map_v % SCAN_COUNT;
                    args->results[idx].scan_results[sidx] = STATUS_CLOSED;
                    args->srcport_map[our_src] = -1;
                }
                pthread_mutex_unlock(&args->map_mutex);
            }
        }
    }
}

void *pcap_listener_thread(void *arg)
{
    t_nmap_args *args = (t_nmap_args *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Choose device. Prefer loopback when target is loopback to capture replies
    const char *dev = "any";
    if (strncmp(args->ip, "127.", 4) == 0 || strcmp(args->ip, "localhost") == 0)
        dev = "lo";

    // Open device to capture replies from kernel
    args->pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!args->pcap_handle)
    {
        fprintf(stderr, "pcap_open_live failed on %s: %s\n", dev, errbuf);
        return NULL;
    }

    /* Record datalink type so packet handler can compute offsets */
    args->pcap_dlt = pcap_datalink(args->pcap_handle);

    // Build filter: capture TCP, UDP, ICMP packets from target IP
    struct bpf_program fp;
    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp), "(tcp or udp or icmp) and src host %s and dst portrange %d-%d",
             args->ip, SRC_PORT_BASE, SRC_PORT_BASE + SRC_PORT_RANGE - 1);
    if (pcap_compile(args->pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "pcap_compile failed\n");
        pcap_close(args->pcap_handle);
        args->pcap_handle = NULL;
        return NULL;
    }
    if (pcap_setfilter(args->pcap_handle, &fp) == -1)
    {
        fprintf(stderr, "pcap_setfilter failed\n");
        pcap_freecode(&fp);
        pcap_close(args->pcap_handle);
        args->pcap_handle = NULL;
        return NULL;
    }
    pcap_freecode(&fp);

    // Loop and dispatch to handler
    while (1)
    {
        int ret = pcap_dispatch(args->pcap_handle, -1, packet_handler, (u_char *)args);
        if (ret == -1 || ret == -2) break;
        // ret == 0 means timeout; continue
    }

    pcap_close(args->pcap_handle);
    args->pcap_handle = NULL;
    return NULL;
}
