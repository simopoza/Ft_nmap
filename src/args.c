#include "../includes/ft_nmap.h"

void    print_help(void)
{
    printf("Usage: ./ft_nmap [OPTIONS]\n");
    printf("Options:\n");
    printf("  --help     Show help menu\n");
    printf("  --ip       Target IP address\n");
    printf("  --file     File containing list of IPs\n");
    printf("  --ports    Ports to scan (e.g., 1-100, 22,80) [default 1-1024]\n");
    printf("  --speedup  Number of threads (max: 250) [default 0]\n");
    printf("  --scan     Scan type(s) (SYN, NULL, FIN, XMAS, ACK, UDP) [default ALL]\n");
    printf("  --json     Write results as JSON to file\n");
    printf("  --save-pcap Write captured packets to pcap file (raw-only, requires root)\n");
    printf("  --top-ports N  Scan built-in top N common ports\n");
    printf("  --decoy    Comma-separated list of decoy IPs to spoof (best-effort, raw only)\n");
    printf("  --evade    Enable small timing jitter to try to evade naive IDS/firewalls\n");
}

void    print_config(t_nmap_args *args)
{
    printf("Scan Configurations\n");
    if (args->ip)
        printf("Target Ip-Address : %s\n", args->ip);
    else if (args->file)
        printf("Target File : %s\n", args->file);
    else
        printf("Target : None (Error)\n");
    
    printf("No of Ports to scan : %d\n", args->port_count);
    
    printf("Scans to be performed :");
    if (args->scan_type & SCAN_SYN) printf(" SYN");
    if (args->scan_type & SCAN_NULL) printf(" NULL");
    if (args->scan_type & SCAN_ACK) printf(" ACK");
    if (args->scan_type & SCAN_FIN) printf(" FIN");
    if (args->scan_type & SCAN_XMAS) printf(" XMAS");
    if (args->scan_type & SCAN_UDP) printf(" UDP");
    printf("\n");

    printf("No of threads : %d\n", args->threads);
}

int     match_scan_type(char *str)
{
    /* Case-insensitive matching */
    if (strcasecmp(str, "SYN") == 0) return SCAN_SYN;
    if (strcasecmp(str, "NULL") == 0) return SCAN_NULL;
    if (strcasecmp(str, "ACK") == 0) return SCAN_ACK;
    if (strcasecmp(str, "FIN") == 0) return SCAN_FIN;
    if (strcasecmp(str, "XMAS") == 0) return SCAN_XMAS;
    if (strcasecmp(str, "UDP") == 0) return SCAN_UDP;
    return (0);
}

int     parse_args(int argc, char **argv, t_nmap_args *args)
{
    int i = 1;

    int parse_ret = PARSE_OK;

    // Set defaults
    args->ip = NULL;
    args->file = NULL;
    args->ports = strdup(DEFAULT_PORTS);
    args->threads = 0;
    args->scan_type = 0;
    args->json_file = NULL;
    args->pcap_file = NULL;
    args->top_ports = 0;
    args->target_name = NULL;
    args->decoy_list = NULL;
    args->decoys = NULL;
    args->decoy_count = 0;
    args->evade = 0;

    int scan_flag_present = 0;

    while (i < argc)
    {
        if (strcmp(argv[i], "--help") == 0)
        {
            print_help();
            parse_ret = PARSE_HELP;
            goto parse_cleanup;
        }
        else if (strcmp(argv[i], "--ip") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --ip requires an argument\n");
                exit(1);
            }
            args->ip = argv[++i];
        }
        else if (strcmp(argv[i], "--file") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --file requires an argument\n");
                exit(1);
            }
            args->file = argv[++i];
        }
        else if (strcmp(argv[i], "--ports") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --ports requires an argument\n");
                exit(1);
            }
            free(args->ports); // free default
            args->ports = strdup(argv[++i]);
        }
        else if (strcmp(argv[i], "--speedup") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --speedup requires an argument\n");
                exit(1);
            }
            args->threads = atoi(argv[++i]);
            if (args->threads > MAX_THREADS)
            {
                fprintf(stderr, "Error: max threads is %d\n", MAX_THREADS);
                exit(1);
            }
        }
        else if (strcmp(argv[i], "--json") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --json requires an argument\n");
                exit(1);
            }
            args->json_file = argv[++i];
        }
        else if (strcmp(argv[i], "--save-pcap") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --save-pcap requires an argument\n");
                exit(1);
            }
            args->pcap_file = argv[++i];
        }
        else if (strcmp(argv[i], "--top-ports") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --top-ports requires an argument\n");
                exit(1);
            }
            args->top_ports = atoi(argv[++i]);
            if (args->top_ports < 1) { fprintf(stderr, "Error: --top-ports requires a positive integer\n"); exit(1); }
            /* Build a ports string from a small built-in top ports list */
            const int top_list[] = {80,443,22,21,23,25,110,139,445,143,53,3306,8080,111,995,993,5900,179,161,20};
            int top_sz = sizeof(top_list)/sizeof(top_list[0]);
            if (args->top_ports > top_sz) args->top_ports = top_sz;
            /* create comma-separated ports string */
            int buf_sz = args->top_ports * 6 + 1;
            char *buf = malloc(buf_sz);
            if (!buf) { perror("malloc"); exit(1); }
            buf[0] = '\0';
            for (int ii = 0; ii < args->top_ports; ii++)
            {
                char tmp[8];
                if (ii > 0) strncat(buf, ",", buf_sz - strlen(buf) - 1);
                snprintf(tmp, sizeof(tmp), "%d", top_list[ii]);
                strncat(buf, tmp, buf_sz - strlen(buf) - 1);
            }
            free(args->ports);
            args->ports = buf; /* take ownership */
        }
        else if (strcmp(argv[i], "--scan") == 0)
        {
            scan_flag_present = 1;
            i++;
            // Check following args until next flag or end
            while (i < argc && argv[i][0] != '-')
            {
                /* Support comma-separated values like "SYN,UDP" and space-separated tokens */
                char *s = argv[i];
                if (strchr(s, ','))
                {
                    char *tmp = strdup(s);
                    char *saveptr = NULL;
                    char *tok = strtok_r(tmp, ",", &saveptr);
                    while (tok)
                    {
                        int type = match_scan_type(tok);
                        if (type == 0)
                        {
                            fprintf(stderr, "Error: Unknown scan type '%s'\n", tok);
                            free(tmp);
                            parse_ret = PARSE_ERR;
                            goto parse_cleanup;
                        }
                        args->scan_type |= type;
                        tok = strtok_r(NULL, ",", &saveptr);
                    }
                    free(tmp);
                }
                else
                {
                    int type = match_scan_type(s);
                    if (type == 0)
                    {
                        fprintf(stderr, "Error: Unknown scan type '%s'\n", s);
                        parse_ret = PARSE_ERR;
                        goto parse_cleanup;
                    }
                    args->scan_type |= type;
                }
                i++;
            }
            i--; // Decrement because outer loop increments
        }
        else if (strcmp(argv[i], "--decoy") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --decoy requires an argument\n");
                exit(1);
            }
            args->decoy_list = argv[++i];
        }
        else if (strcmp(argv[i], "--evade") == 0)
        {
            /* enable simple timing/randomization evasion */
            args->evade = 1;
        }
        else
        {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            print_help();
            exit(1);
        }
        i++;
    }

    /* handled inline during initial parse */

    if (scan_flag_present == 0)
    {
        // Default ALL
        args->scan_type = SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_UDP;
    }
    else if (args->scan_type == 0)
    {
        fprintf(stderr, "Error: --scan requires at least one scan type argument\n");
        return PARSE_ERR;
    }

    if (args->ip == NULL && args->file == NULL)
    {
        fprintf(stderr, "Error: Must specify --ip or --file\n");
        parse_ret = PARSE_ERR;
        goto parse_cleanup;
    }
    if (args->ip && args->file)
    {
        fprintf(stderr, "Error: Cannot specify both --ip and --file\n");
        parse_ret = PARSE_ERR;
        goto parse_cleanup;
    }

parse_cleanup:
    /* Ensure we don't leak the default ports strdup on error/help paths. Tests
       call parse_args expecting non-zero returns and don't always free args->ports. */
    if (parse_ret != PARSE_OK && args->ports)
    {
        free(args->ports);
        args->ports = NULL;
    }
    return parse_ret;
}
