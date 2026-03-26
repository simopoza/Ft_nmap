#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../includes/ft_nmap.h"

/* TCP server that accepts a connection and keeps it briefly */
static void *tcp_server_thread(void *arg)
{
    int port = *(int *)arg;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return NULL; }
    if (listen(sock, 1) < 0) { close(sock); return NULL; }

    int client = accept(sock, NULL, NULL);
    if (client >= 0) {
        sleep(1);
        close(client);
    }
    close(sock);
    return NULL;
}

int main(void)
{
    int scan_masks[5] = { SCAN_SYN, SCAN_NULL, SCAN_ACK, SCAN_FIN, SCAN_XMAS };

    for (int i = 0; i < 5; i++)
    {
        /* create ephemeral listening socket to discover port for this iteration */
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) { fprintf(stderr, "FAIL: cannot create helper socket\n"); return 2; }
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) { close(s); fprintf(stderr, "FAIL: bind\n"); return 2; }
        socklen_t alen = sizeof(a);
        if (getsockname(s, (struct sockaddr *)&a, &alen) < 0) { close(s); fprintf(stderr, "FAIL: getsockname\n"); return 2; }
        int port = ntohs(a.sin_port);
        close(s);

        pthread_t thr;
        if (pthread_create(&thr, NULL, tcp_server_thread, &port) != 0) { fprintf(stderr, "FAIL: pthread_create\n"); return 2; }

        t_nmap_args args;
        memset(&args, 0, sizeof(args));
        args.ip = strdup("127.0.0.1");
        args.port_count = 1;
        args.port_list = malloc(sizeof(uint16_t));
        args.port_list[0] = port;
        args.threads = 1;
        args.scan_type = scan_masks[i];

        start_scan(&args);

        int open_detected = 0;
        if (args.results)
        {
            for (int k = 0; k < SCAN_COUNT; k++)
            {
                if (args.results[0].scan_results[k] == STATUS_OPEN || args.results[0].scan_results[k] == STATUS_OPEN_FILTERED)
                {
                    open_detected = 1;
                    break;
                }
            }
            if (args.results[0].scan_results[SCAN_IDX_SYN] == STATUS_OPEN) open_detected = 1;
        }

        if (!open_detected)
        {
            fprintf(stderr, "FAIL: scan flag %d did not detect open port\n", scan_masks[i]);
            if (args.results) free(args.results);
            if (args.port_list) free(args.port_list);
            if (args.ip) free(args.ip);
            pthread_join(thr, NULL);
            return 2;
        }

        if (args.results) free(args.results);
        if (args.port_list) free(args.port_list);
        if (args.ip) free(args.ip);
        pthread_join(thr, NULL);
    }
    printf("PASS: scan each TCP flag test\n");
    return 0;
}
