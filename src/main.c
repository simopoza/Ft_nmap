#include "../includes/ft_nmap.h"

int main(int argc, char **argv)
{
    t_nmap_args args;
    struct timeval tv_start, tv_end;
    double elapsed = 0.0;

    if (argc < 2)
    {
        print_help();
        return (1);
    }
    parse_args(argc, argv, &args);
    resolve_target(&args);
    parse_ports(&args);
    print_config(&args);

    // Initial scan
    gettimeofday(&tv_start, NULL);
    start_scan(&args);
    gettimeofday(&tv_end, NULL);
    elapsed = (tv_end.tv_sec - tv_start.tv_sec) + (tv_end.tv_usec - tv_start.tv_usec) / 1000000.0;

    // Print summary
    printf("\nScan completed in %.2f seconds\n", elapsed);
    printf("Open ports:\n");
    printf("Port\tService\tState\n");
    for (int i = 0; i < args.port_count; i++)
    {
        t_result *r = &args.results[i];
        if (r->scan_results[SCAN_IDX_SYN] == STATUS_OPEN)
        {
            struct servent *s = getservbyport(htons(r->port), "tcp");
            printf("%d\t%s\topen\n", r->port, s ? s->s_name : "-");
        }
    }

    // Cleanup
    free(args.port_list);
    if (args.results)
        free(args.results);
    if (args.local_ip)
        free(args.local_ip);
    return (0);
}
