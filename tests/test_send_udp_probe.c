#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../includes/ft_nmap.h"

/* UDP helper server: bind to ephemeral port and wait for one packet */
static int start_udp_server(int *out_port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* ephemeral */
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }
    socklen_t alen = sizeof(addr);
    if (getsockname(sock, (struct sockaddr *)&addr, &alen) < 0) { close(sock); return -1; }
    *out_port = ntohs(addr.sin_port);
    return sock;
}

int main(void)
{
    int port = 0;
    int sock = start_udp_server(&port);
    if (sock < 0) { fprintf(stderr, "FAIL: cannot start udp server\n"); return 2; }

    /* send a probe to the server */
    int rc = send_udp_probe("127.0.0.1", "127.0.0.1", 40000 + (rand() % 1000), port);

    /* wait for one recv with small timeout */
    struct timeval tv;
    tv.tv_sec = 2; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[512];
    ssize_t r = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    close(sock);

    if (r >= 0 && rc == 0)
    {
        printf("PASS: udp probe send test (recv %zd bytes)\n", r);
        return 0;
    }
    else
    {
        printf("FAIL: udp probe send test (rc=%d, recv=%zd)\n", rc, r);
        return 2;
    }
}
