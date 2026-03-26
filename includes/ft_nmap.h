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
#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif
/* libpcap */
#include <pcap/pcap.h>

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

/* Scan indices for result arrays */
#define SCAN_IDX_SYN  0
#define SCAN_IDX_NULL 1
#define SCAN_IDX_ACK  2
#define SCAN_IDX_FIN  3
#define SCAN_IDX_XMAS 4
#define SCAN_IDX_UDP  5
#define SCAN_COUNT    6

#define STATUS_CLOSED 0
#define STATUS_OPEN 1
#define STATUS_FILTERED 2
/* Additional states */
#define STATUS_UNFILTERED 3
#define STATUS_OPEN_FILTERED 4

/* Source port allocation for probes: range used for ephemeral source ports we control */
#define SRC_PORT_BASE 40000
#define SRC_PORT_RANGE 20000

typedef struct s_result {
    uint16_t    port;
    char        *service;
    char        *banner; /* optional banner/version string obtained via TCP banner grab */
    uint8_t     scan_results[SCAN_COUNT]; /* per-scan-type status */
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
    char            *local_ip; /* cached local source IP for sending */
    /* SYN scan specific fields */
    int             *srcport_map; /* maps our source port -> index in port_list */
    int             raw_sock;
    pcap_t          *pcap_handle;
    int             pcap_dlt;
    pthread_t       pcap_thread;
    pthread_mutex_t map_mutex;
    /* Reservation helpers: keep sockets open to reserve source ports and mapping from probe to src port */
    int             *reserved_socks; /* fds of bound UDP sockets to hold ports */
    int             reserved_count;
    int             *map_to_srcport; /* maps composite map_v -> src_port */
    int             scan_done; /* flag set when scan finished (used by progress indicator) */
    /* Bonus/extra flags */
    char            *json_file; /* write results to JSON */
    char            *pcap_file; /* optional pcap dump filename */
    pcap_dumper_t   *pcap_dumper; /* opened dumper if pcap_file is set */
    int             top_ports; /* if >0, use top N ports list */
    char            *target_name; /* reverse DNS name for target if available */
    /* Bonus: evasion / decoy options */
    char            *decoy_list; /* comma-separated decoy IPs (string from args) */
    char            **decoys;    /* parsed decoy IP array */
    int             decoy_count;
    int             evade;       /* boolean: enable timing randomization / jitter to evade IDS */
} t_nmap_args;

/* Function Prototypes */
/* parse_args return codes: 0 = ok, 1 = error, 2 = help (printed) */
#define PARSE_OK 0
#define PARSE_ERR 1
#define PARSE_HELP 2

int     parse_args(int argc, char **argv, t_nmap_args *args);
void    parse_ports(t_nmap_args *args);
void    resolve_target(t_nmap_args *args);
char    *resolve_target_str(const char *name);
void    start_scan(t_nmap_args *args);
void    print_help(void);
void    print_config(t_nmap_args *args);
char    *grab_banner(t_nmap_args *args, uint16_t port);

/* Packet/pcap helpers */
int     send_syn_packet(int raw_sock, const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port);
int     send_tcp_packet(int raw_sock, const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t flags);
int     send_udp_probe(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port);
void    *pcap_listener_thread(void *arg);

#endif
