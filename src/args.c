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

    // Set defaults
    args->ip = NULL;
    args->file = NULL;
    args->ports = strdup(DEFAULT_PORTS);
    args->threads = 0;
    args->scan_type = 0;

    int scan_flag_present = 0;

    while (i < argc)
    {
        if (strcmp(argv[i], "--help") == 0)
        {
            print_help();
            return PARSE_HELP;
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
                            return PARSE_ERR;
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
                        return PARSE_ERR;
                    }
                    args->scan_type |= type;
                }
                i++;
            }
            i--; // Decrement because outer loop increments
        }
        else
        {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            print_help();
            exit(1);
        }
        i++;
    }

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
        return PARSE_ERR;
    }
    if (args->ip && args->file)
    {
        fprintf(stderr, "Error: Cannot specify both --ip and --file\n");
        return PARSE_ERR;
    }

    return PARSE_OK;
}
