#include <pthread.h>
#include "../includes/ft_nmap.h"

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
            args->results[index].status = 1; // Open
        }
        else
        {
            args->results[index].status = 0; // Closed
        }
        args->results[index].port = port;
    }
    return (NULL);
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
