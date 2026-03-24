#include "../includes/ft_nmap.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>

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
    if (iph->protocol != IPPROTO_TCP) return;

    int ip_header_len = iph->ihl * 4;
    if (h->caplen < (size_t)l3_offset + ip_header_len + sizeof(struct tcphdr))
        return;

    struct tcphdr *tcph = (struct tcphdr *)(ip_ptr + ip_header_len);

    uint16_t dst_port = ntohs(tcph->dest);

    // Flags
    uint8_t flags = *((uint8_t *)tcph + 13);
    int syn = flags & 0x02;
    int ack = flags & 0x10;
    int rst = flags & 0x04;

    uint16_t our_src = dst_port; // packet dest is our source port
    (void)iph; (void)tcph; /* no-op to avoid unused warnings if debug removed */

    pthread_mutex_lock(&args->map_mutex);
    int idx = args->srcport_map[our_src];
    if (idx != -1)
    {
        if (syn && ack)
        {
            args->results[idx].scan_results[SCAN_IDX_SYN] = STATUS_OPEN;
        }
        else if (rst)
        {
            args->results[idx].scan_results[SCAN_IDX_SYN] = STATUS_CLOSED;
        }
        /* consume mapping */
        args->srcport_map[our_src] = -1;
    }
    pthread_mutex_unlock(&args->map_mutex);
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

    // Build filter: TCP packets from target IP
    struct bpf_program fp;
    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp), "tcp and src host %s", args->ip);
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
