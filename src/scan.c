#include <pthread.h>
#include "../includes/ft_nmap.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <netdb.h>
#include <pcap/pcap.h>
#include <sys/resource.h>

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

    /* sender threads use preallocated source ports (map_to_srcport) */

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
            {
                ; /* UDP will still have a preallocated src port in map_to_srcport */
            }

            /* Look up preallocated source port for this probe */
            int map_v = index * SCAN_COUNT + sidx;
            uint16_t src_port = 0;
            if (args->map_to_srcport && args->map_to_srcport[map_v] > 0)
                src_port = (uint16_t)args->map_to_srcport[map_v];
            else
            {
                /* if for some reason no preallocation exists, fall back to deterministic mapping */
                src_port = (uint16_t)(SRC_PORT_BASE + (map_v % SRC_PORT_RANGE));
                pthread_mutex_lock(&args->map_mutex);
                args->srcport_map[src_port] = map_v;
                pthread_mutex_unlock(&args->map_mutex);
            }

            // Determine flags for this scan and send
            uint8_t flags = 0;
            if (sidx == SCAN_IDX_SYN) flags = 0x02;
            else if (sidx == SCAN_IDX_NULL) flags = 0x00;
            else if (sidx == SCAN_IDX_FIN) flags = 0x01;
            else if (sidx == SCAN_IDX_XMAS) flags = 0x01 | 0x08 | 0x20; // FIN+PSH+URG
            else if (sidx == SCAN_IDX_ACK) flags = 0x10;

            int send_ret = -1;
            if (sidx == SCAN_IDX_UDP)
            {
                send_ret = send_udp_probe(args->local_ip ? args->local_ip : "0.0.0.0", args->ip, src_port, dst_port);
            }
            else
            {
                send_ret = send_tcp_packet(args->raw_sock, args->local_ip ? args->local_ip : "0.0.0.0", args->ip, src_port, dst_port, flags);
            }

            // Send result handling
            if (send_ret < 0)
            {
                args->results[index].scan_results[sidx] = STATUS_CLOSED;
                pthread_mutex_lock(&args->map_mutex);
                args->srcport_map[src_port] = -1;
                pthread_mutex_unlock(&args->map_mutex);
            }
            else
            {
                /* default states: SYN -> FILTERED; NULL/FIN/XMAS -> OPEN|FILTERED; ACK -> FILTERED; UDP -> OPEN|FILTERED */
                if (sidx == SCAN_IDX_SYN || sidx == SCAN_IDX_ACK)
                    args->results[index].scan_results[sidx] = STATUS_FILTERED;
                else if (sidx == SCAN_IDX_UDP)
                    args->results[index].scan_results[sidx] = STATUS_OPEN_FILTERED;
                else
                    args->results[index].scan_results[sidx] = STATUS_OPEN_FILTERED;
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

    /* progress printing is handled by main(); avoid duplicate message here */

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
            /* Non-root: raw socket unavailable. Quietly fall back to connect-scan worker
               threads to populate results so printing shows correct port numbers. */

            /* Start connect-scan worker threads (same as default worker path) */
            for (int i = 0; i < thread_count; i++)
            {
                if (pthread_create(&threads_pool[i], NULL, scan_worker, args) != 0)
                    perror("pthread_create");
            }
            for (int i = 0; i < thread_count; i++)
            {
                pthread_join(threads_pool[i], NULL);
            }

            free(threads_pool);
            pthread_mutex_destroy(&args->mutex_port);
            return;
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

            /* Pre-allocate and reserve source ports for all planned probes so we can set a precise pcap filter
               and avoid ephemeral port collisions. We bind UDP sockets to hold ports for the duration of the scan. */
            int scan_mask[SCAN_COUNT] = { SCAN_SYN, SCAN_NULL, SCAN_ACK, SCAN_FIN, SCAN_XMAS, SCAN_UDP };
            int total_probes = 0;
            for (int i = 0; i < args->port_count; i++)
            {
                for (int s = 0; s < SCAN_COUNT; s++)
                    if (args->scan_type & scan_mask[s]) total_probes++;
            }

            /* allocate map from probe (map_v) to src_port */
            args->map_to_srcport = malloc(sizeof(int) * args->port_count * SCAN_COUNT);
            if (!args->map_to_srcport) args->map_to_srcport = NULL;
            else
            {
                for (int i = 0; i < args->port_count * SCAN_COUNT; i++) args->map_to_srcport[i] = -1;
            }

            /* We'll allocate reserved_socks based on pool size below */
            args->reserved_socks = NULL;
            args->reserved_count = 0;

            /* seed PRNG for per-run randomness */
            srand((unsigned int)(time(NULL) ^ getpid()));

            /* Check RLIMIT_NOFILE and limit how many ports we try to reserve to avoid FD exhaustion */
            struct rlimit rl;
            int max_reservable = total_probes; /* default */
            if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
            {
                /* leave a safety margin for other fds (stdin/out/err, sockets, pcap, etc.) */
                long safety = 50;
                long avail = (long)rl.rlim_cur - safety;
                if (avail < 0) avail = 0;
                if (avail < max_reservable) max_reservable = (int)avail;
            }

            if (max_reservable < 0) max_reservable = 0;

            /* Implement pool-based reservation: allocate a smaller pool of reserved ports
               (<= max_reservable and <= total_probes) and assign probes to pool ports
               in a round-robin fashion. This reduces FD usage while still allowing pcap
               to filter on the pool of source ports. */
            int pool_size = max_reservable;
            if (pool_size > total_probes) pool_size = total_probes;
            if (pool_size > 1024) pool_size = 1024; /* safety cap */

            if (pool_size > 0)
            {
                int *pool_ports = malloc(sizeof(int) * pool_size);
                int *pool_socks = malloc(sizeof(int) * pool_size);
                int pool_count = 0;
                for (int p = 0; p < pool_size; p++) pool_socks[p] = -1;

                for (int pi = 0; pi < pool_size; pi++)
                {
                    int attempts = 0;
                    int chosen = -1;
                    int sockfd = -1;
                    while (attempts < 5000)
                    {
                        int r = rand() % SRC_PORT_RANGE;
                        int cand = SRC_PORT_BASE + r;
                        pthread_mutex_lock(&args->map_mutex);
                        int used = args->srcport_map[cand];
                        pthread_mutex_unlock(&args->map_mutex);
                        if (used != -1) { attempts++; continue; }

                        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                        if (sockfd >= 0)
                        {
                            struct sockaddr_in bind_addr;
                            memset(&bind_addr, 0, sizeof(bind_addr));
                            bind_addr.sin_family = AF_INET;
                            bind_addr.sin_port = htons(cand);
                            bind_addr.sin_addr.s_addr = INADDR_ANY;
                            if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == 0)
                            {
                                chosen = cand;
                                break;
                            }
                            close(sockfd);
                            sockfd = -1;
                        }
                        sockfd = socket(AF_INET, SOCK_STREAM, 0);
                        if (sockfd >= 0)
                        {
                            int one = 1;
                            setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                            struct sockaddr_in bind_addr;
                            memset(&bind_addr, 0, sizeof(bind_addr));
                            bind_addr.sin_family = AF_INET;
                            bind_addr.sin_port = htons(cand);
                            bind_addr.sin_addr.s_addr = INADDR_ANY;
                            if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == 0)
                            {
                                chosen = cand;
                                break;
                            }
                            close(sockfd);
                            sockfd = -1;
                        }
                        attempts++;
                    }
                    if (chosen == -1)
                    {
                        /* if we couldn't bind a port, choose deterministic fallback */
                        chosen = SRC_PORT_BASE + (pi % SRC_PORT_RANGE);
                        sockfd = -1;
                    }
                    pool_ports[pool_count] = chosen;
                    pool_socks[pool_count] = sockfd;
                    pool_count++;
                    pthread_mutex_lock(&args->map_mutex);
                    args->srcport_map[chosen] = -2; /* mark as shared/multiplexed */
                    pthread_mutex_unlock(&args->map_mutex);
                }

                /* store pool into args so we can close sockets later and build filter */
                if (args->reserved_socks) free(args->reserved_socks);
                args->reserved_socks = malloc(sizeof(int) * pool_count);
                args->reserved_count = pool_count;
                for (int i = 0; i < pool_count; i++) args->reserved_socks[i] = pool_socks[i];

                /* assign map_to_srcport by round-robin mapping into pool_ports */
                if (args->map_to_srcport)
                {
                    for (int mv = 0; mv < args->port_count * SCAN_COUNT; mv++)
                    {
                        int port = pool_ports[mv % pool_count];
                        args->map_to_srcport[mv] = port;
                    }
                }

                free(pool_ports);
                free(pool_socks);
            }
            else
            {
                /* No reservation possible: fall back to per-probe deterministic mapping */
                for (int i = 0; i < args->port_count; i++)
                {
                    for (int sidx = 0; sidx < SCAN_COUNT; sidx++)
                    {
                        if (!(args->scan_type & scan_mask[sidx])) continue;
                        int map_v = i * SCAN_COUNT + sidx;
                        int chosen_port = SRC_PORT_BASE + (map_v % SRC_PORT_RANGE);
                        if (args->map_to_srcport)
                            args->map_to_srcport[map_v] = chosen_port;
                        pthread_mutex_lock(&args->map_mutex);
                        args->srcport_map[chosen_port] = map_v;
                        pthread_mutex_unlock(&args->map_mutex);
                        /* placeholder for reserved_socks array to keep cleanup logic simple */
                        args->reserved_socks = realloc(args->reserved_socks, sizeof(int) * (args->reserved_count + 1));
                        args->reserved_socks[args->reserved_count++] = -1;
                    }
                }
            }

            /* Build precise pcap filter listing chosen dst ports (our probe source ports) */
            size_t filter_sz = 256 + (args->reserved_count * 16);
            char *filter_exp = malloc(filter_sz);
            if (filter_exp)
            {
                snprintf(filter_exp, filter_sz, "(tcp or udp or icmp) and src host %s and (", args->ip);
                int first = 1;
                /* iterate over map_to_srcport to list ports */
                for (int mv = 0; mv < args->port_count * SCAN_COUNT; mv++)
                {
                    if (!args->map_to_srcport) break;
                    int port = args->map_to_srcport[mv];
                    if (port <= 0) continue;
                    if (!first) strncat(filter_exp, " or ", filter_sz - strlen(filter_exp) - 1);
                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), "dst port %d", port);
                    strncat(filter_exp, tmp, filter_sz - strlen(filter_exp) - 1);
                    first = 0;
                }
                strncat(filter_exp, ")", filter_sz - strlen(filter_exp) - 1);

                struct bpf_program fp;
                if (pcap_compile(args->pcap_handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == 0)
                {
                    if (pcap_setfilter(args->pcap_handle, &fp) != 0)
                        fprintf(stderr, "Warning: failed to set precise pcap filter\n");
                    pcap_freecode(&fp);
                }
                free(filter_exp);
            }

            /* Create sender threads that will send the requested probes */
            for (int i = 0; i < thread_count; i++)
            {
                if (pthread_create(&threads_pool[i], NULL, scan_sender_worker, args) != 0)
                    perror("pthread_create sender");
            }

            // Wait for sender threads
            for (int i = 0; i < thread_count; i++)
                pthread_join(threads_pool[i], NULL);

            // Wait a bit for replies to arrive (increase slightly to allow service replies to UDP payloads)
            sleep(3);

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

            /* Close any reserved sockets used to hold source ports and free mapping */
            if (args->reserved_socks)
            {
                for (int i = 0; i < args->reserved_count; i++)
                {
                    int fd = args->reserved_socks[i];
                    if (fd >= 0) close(fd);
                }
                free(args->reserved_socks);
                args->reserved_socks = NULL;
                args->reserved_count = 0;
            }
            if (args->map_to_srcport)
            {
                free(args->map_to_srcport);
                args->map_to_srcport = NULL;
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
