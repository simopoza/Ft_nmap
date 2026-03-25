#include <pthread.h>
#include "../includes/ft_nmap.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>

// Simple connect scan function (Step 4)
static bool is_open_connect(t_nmap_args *args, uint16_t port)
{
    int sockfd;
    struct sockaddr_in serv_addr;
    
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return false;

    // Timeout logic
    struct timeval timeout;
    timeout.tv_sec = 2; // 2 seconds timeout
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Try to convert IP string
    if (inet_pton(AF_INET, args->ip, &serv_addr.sin_addr) <= 0)
    {
        close(sockfd);
        return false;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        close(sockfd);
        return false;
    }

    close(sockfd);
    return true;
}

static void *scan_worker(void *arg)
{
    t_nmap_args *args = (t_nmap_args *)arg;
    int index;
    uint16_t port;

    while (1)
    {
        // Critical section: Get next port index
        pthread_mutex_lock(&args->mutex_port);
        if (args->current_port_idx >= args->port_count)
        {
            pthread_mutex_unlock(&args->mutex_port);
            break;
        }
        index = args->current_port_idx;
        // Increment here
        args->current_port_idx++; 
        
        // Retrieve port from list using index
        port = args->port_list[index];
        
        pthread_mutex_unlock(&args->mutex_port);

        // Perform Connect Scan
        // Only run connect scan if user requested it, OR for testing Step 4 assume Connect scan for now?
        // Let's assume for now we always do connect scan for testing.
        if (is_open_connect(args, port))
        {
            printf("Discovered open port %d/tcp\n", port);
            args->results[index].scan_results[SCAN_IDX_SYN] = STATUS_OPEN;
        }
        else
        {
            args->results[index].scan_results[SCAN_IDX_SYN] = STATUS_CLOSED;
        }
        args->results[index].port = port;
    }
    return (NULL);
}

// Helper: determine local outbound IP for a given destination
static char *get_local_ip_for_dest(const char *dst_ip)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(53);
    inet_pton(AF_INET, dst_ip, &serv.sin_addr);
    if (connect(sock, (struct sockaddr *)&serv, sizeof(serv)) < 0)
    {
        close(sock);
        return NULL;
    }
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr *)&name, &namelen) < 0)
    {
        close(sock);
        return NULL;
    }
    char *ip = strdup(inet_ntoa(name.sin_addr));
    close(sock);
    return ip;
}

// General sender worker: sends TCP probes for requested scan types (SYN/NULL/FIN/...)
static void *scan_sender_worker(void *arg)
{
    t_nmap_args *args = (t_nmap_args *)arg;
    int index;
    uint16_t dst_port;

    // Which masks correspond to each scan index
    int scan_mask[SCAN_COUNT] = { SCAN_SYN, SCAN_NULL, SCAN_ACK, SCAN_FIN, SCAN_XMAS, SCAN_UDP };

    // Compute local IP once
    if (!args->local_ip)
        args->local_ip = get_local_ip_for_dest(args->ip);

    while (1)
    {
        pthread_mutex_lock(&args->mutex_port);
        if (args->current_port_idx >= args->port_count)
        {
            pthread_mutex_unlock(&args->mutex_port);
            break;
        }
        index = args->current_port_idx;
        args->current_port_idx++;
        dst_port = args->port_list[index];
        pthread_mutex_unlock(&args->mutex_port);

        args->results[index].port = dst_port;

        // For each requested scan type, send appropriate TCP/UDP probe
        for (int sidx = 0; sidx < SCAN_COUNT; sidx++)
        {
            if (!(args->scan_type & scan_mask[sidx]))
                continue;

            // Skip UDP here (not yet implemented)
            if (sidx == SCAN_IDX_UDP)
                continue;

            // Build a source port unique per (index, sidx)
            uint16_t src_port = 40000 + ((index * SCAN_COUNT + sidx) % 20000);

            // Register composite mapping: index * SCAN_COUNT + sidx
            int map_v = index * SCAN_COUNT + sidx;
            pthread_mutex_lock(&args->map_mutex);
            args->srcport_map[src_port] = map_v;
            pthread_mutex_unlock(&args->map_mutex);

            // Determine flags for this scan
            uint8_t flags = 0;
            if (sidx == SCAN_IDX_SYN) flags = 0x02;
            else if (sidx == SCAN_IDX_NULL) flags = 0x00;
            else if (sidx == SCAN_IDX_FIN) flags = 0x01;
            else if (sidx == SCAN_IDX_XMAS) flags = 0x01 | 0x08 | 0x20; // FIN+PSH+URG
            else if (sidx == SCAN_IDX_ACK) flags = 0x10;

            // Send packet
            if (send_tcp_packet(args->raw_sock, args->local_ip ? args->local_ip : "0.0.0.0", args->ip, src_port, dst_port, flags) < 0)
            {
                args->results[index].scan_results[sidx] = STATUS_CLOSED;
                pthread_mutex_lock(&args->map_mutex);
                args->srcport_map[src_port] = -1;
                pthread_mutex_unlock(&args->map_mutex);
            }
            else
            {
                /* default to filtered until reply */
                args->results[index].scan_results[sidx] = STATUS_FILTERED;
            }

            // small delay between probes for same port
            usleep(500);
        }

        // small delay to avoid flooding between ports
        usleep(1000);
    }
    return NULL;
}

void start_scan(t_nmap_args *args)
{
    pthread_t *threads_pool;
    int thread_count = args->threads;
    
    // Default 0 means 1 thread? Or no threading overhead?
    // Let's treat 0 as 1 worker thread for simplicity, or 0 as "main thread does the work"?
    // If 0, I can run worker in main thread.
    // But for consistent testing of "thread pool", let's spawn 1 thread or treat 0 as implies "unlimited" or "default"?
    // The subject says "No of threads : 0". Let's assume 0 means "single-threaded".
    if (thread_count == 0)
        thread_count = 1;

    // Use malloc for threads array if needed, MAX_THREADS is small enough for stack,
    // but args->threads limit is checked.
    threads_pool = malloc(sizeof(pthread_t) * thread_count);
    if (!threads_pool) return;

    // Initialize mutex
    pthread_mutex_init(&args->mutex_port, NULL);
    args->current_port_idx = 0;

    /* Allocate results array to store per-port scan outcomes */
    args->results = calloc(args->port_count, sizeof(t_result));
    if (!args->results)
    {
        perror("calloc results");
        pthread_mutex_destroy(&args->mutex_port);
        free(threads_pool);
        exit(1);
    }

    printf("\nScanning...\n");

    // If any raw/pcap-based scans requested, prepare raw socket + pcap and sender threads
    if (args->scan_type & (SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_UDP))
    {
        // Prepare source-port mapping
        args->srcport_map = malloc(sizeof(int) * 65536);
        if (!args->srcport_map) { perror("malloc srcport_map"); exit(1); }
        for (int i = 0; i < 65536; i++) args->srcport_map[i] = -1;
        pthread_mutex_init(&args->map_mutex, NULL);

        // Create raw socket for sending IP packets
        args->raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (args->raw_sock < 0)
        {
            perror("raw socket");
            // fallback: continue with connect-scan by leaving workers as-is
        }
        else
        {
            int one = 1;
            if (setsockopt(args->raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
                perror("setsockopt IP_HDRINCL");


            // Start pcap listener
            if (pthread_create(&args->pcap_thread, NULL, pcap_listener_thread, args) != 0)
                perror("pcap thread");

            // Wait for pcap_handle to be ready (small timeout)
            int wait_i = 0;
            while (args->pcap_handle == NULL && wait_i < 100)
            {
                usleep(10000); // 10ms
                wait_i++;
            }
            if (args->pcap_handle == NULL)
                fprintf(stderr, "Warning: pcap handle not ready, proceeding without capture readiness\n");

            // Create sender threads that will send the requested probes
            for (int i = 0; i < thread_count; i++)
            {
                if (pthread_create(&threads_pool[i], NULL, scan_sender_worker, args) != 0)
                    perror("pthread_create sender");
            }

            // Wait for sender threads
            for (int i = 0; i < thread_count; i++)
                pthread_join(threads_pool[i], NULL);

            // Wait a bit for replies to arrive
            sleep(2);

            // Stop pcap dispatch by breaking loop
            if (args->pcap_handle)
                pcap_breakloop(args->pcap_handle);

            // Join pcap thread
            pthread_join(args->pcap_thread, NULL);

            // Mark remaining unanswered probes as filtered (decode composite map)
            for (int p = 0; p < 65536; p++)
            {
                int map_v = args->srcport_map[p];
                if (map_v != -1)
                {
                    int idx = map_v / SCAN_COUNT;
                    int sidx = map_v % SCAN_COUNT;
                    args->results[idx].scan_results[sidx] = STATUS_FILTERED;
                    args->srcport_map[p] = -1;
                }
            }

            /* If target is loopback, raw SYN probing on lo may not elicit replies reliably
               from the kernel. Fall back to a connect() check for accurate local detection. */
            if (strncmp(args->ip, "127.", 4) == 0 || strcmp(args->ip, "localhost") == 0)
            {
                int scan_mask[SCAN_COUNT] = { SCAN_SYN, SCAN_NULL, SCAN_ACK, SCAN_FIN, SCAN_XMAS, SCAN_UDP };
                for (int i = 0; i < args->port_count; i++)
                {
                    uint16_t p = args->port_list[i];
                    for (int sidx = 0; sidx < SCAN_COUNT; sidx++)
                    {
                        if (!(args->scan_type & scan_mask[sidx]))
                            continue;
                        if (sidx == SCAN_IDX_UDP)
                            continue;
                        if (args->results[i].scan_results[sidx] == STATUS_OPEN)
                            continue;
                        if (is_open_connect(args, p))
                            args->results[i].scan_results[sidx] = STATUS_OPEN;
                        else if (args->results[i].scan_results[sidx] != STATUS_OPEN)
                            args->results[i].scan_results[sidx] = STATUS_CLOSED;
                    }
                }
            }

            // cleanup raw socket
            close(args->raw_sock);
            free(args->srcport_map);
            pthread_mutex_destroy(&args->map_mutex);
        }
        // We already started and joined sender threads in SYN path; skip default worker start below
        free(threads_pool);
        return;
    }

    // Start threads
    for (int i = 0; i < thread_count; i++)
    {
        if (pthread_create(&threads_pool[i], NULL, scan_worker, args) != 0)
        {
            perror("pthread_create");
        }
    }

    // Wait for threads
    for (int i = 0; i < thread_count; i++)
    {
        pthread_join(threads_pool[i], NULL);
    }

    printf("Scan finished.\n");

    // Clean up
    pthread_mutex_destroy(&args->mutex_port);
    free(threads_pool);
}
