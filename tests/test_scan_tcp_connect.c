#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../includes/ft_nmap.h"

/* Small helper TCP server that accepts one connection then exits */
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
        /* keep connection briefly then close */
        sleep(1);
        close(client);
    }
    close(sock);
    return NULL;
}

int main(void)
{
    /* pick an ephemeral port and start server */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { fprintf(stderr, "FAIL: cannot create helper socket\n"); return 2; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0; /* ephemeral */
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) { close(s); fprintf(stderr, "FAIL: bind\n"); return 2; }
    socklen_t alen = sizeof(a);
    if (getsockname(s, (struct sockaddr *)&a, &alen) < 0) { close(s); fprintf(stderr, "FAIL: getsockname\n"); return 2; }
    int port = ntohs(a.sin_port);
    close(s);

    pthread_t thr;
    if (pthread_create(&thr, NULL, tcp_server_thread, &port) != 0) { fprintf(stderr, "FAIL: pthread_create\n"); return 2; }

    /* prepare args for start_scan */
    t_nmap_args args;
    memset(&args, 0, sizeof(args));
    args.ip = strdup("127.0.0.1");
    args.ports = NULL;
    args.port_count = 1;
    args.port_list = malloc(sizeof(uint16_t) * 1);
    args.port_list[0] = port;
    args.threads = 1;
    args.scan_type = SCAN_SYN; /* request SYN scan (will fall back to connect-scan when not root) */

    start_scan(&args);

    int ok = 0;
    if (args.results && args.results[0].scan_results[SCAN_IDX_SYN] == STATUS_OPEN)
        ok = 1;

    /* cleanup */
    if (args.results) free(args.results);
    if (args.port_list) free(args.port_list);
    if (args.ip) free(args.ip);

    pthread_join(thr, NULL);

    if (ok) { printf("PASS: tcp connect scan test\n"); return 0; }
    else { printf("FAIL: tcp connect scan test\n"); return 2; }
}
