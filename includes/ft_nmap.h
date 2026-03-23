#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <stdint.h>
# include <ctype.h>
# include <stdbool.h>
# include <pthread.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <errno.h>

# define MAX_THREADS 250
# define DEFAULT_PORTS "1-1024"
# define MAX_PORTS_TO_SCAN 1024

/* Scan types */
# define SCAN_SYN  1
# define SCAN_NULL 2
# define SCAN_ACK  4
# define SCAN_FIN  8
# define SCAN_XMAS 16
# define SCAN_UDP  32

typedef struct s_result {
    uint16_t    port;
    char        *service;
    uint8_t     scan_type; // Which scan found it
    int         status;    // 0: Closed, 1: Open, 2: Filtered, etc.
} t_result;

typedef struct s_nmap_args {
    char        *ip;
    char        *file;
    char        *ports;
    uint16_t    *port_list;
    int         port_count;
    int         threads;
    int         scan_type;

    // Threading
    pthread_mutex_t mutex_port;
    int             current_port_idx;
    t_result        *results;
} t_nmap_args;

/* Function Prototypes */
void    parse_args(int argc, char **argv, t_nmap_args *args);
void    parse_ports(t_nmap_args *args);
void    resolve_target(t_nmap_args *args);
void    start_scan(t_nmap_args *args);
void    print_help(void);
void    print_config(t_nmap_args *args);

#endif
