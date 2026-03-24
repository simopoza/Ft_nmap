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

    /* Determine which scan columns to show based on requested scans */
    int active_idxs[SCAN_COUNT];
    const char *active_names[SCAN_COUNT];
    int active_count = 0;
    if (args.scan_type & SCAN_SYN)  { active_idxs[active_count] = SCAN_IDX_SYN;  active_names[active_count++] = "SYN"; }
    if (args.scan_type & SCAN_NULL) { active_idxs[active_count] = SCAN_IDX_NULL; active_names[active_count++] = "NULL"; }
    if (args.scan_type & SCAN_ACK)  { active_idxs[active_count] = SCAN_IDX_ACK;  active_names[active_count++] = "ACK"; }
    if (args.scan_type & SCAN_FIN)  { active_idxs[active_count] = SCAN_IDX_FIN;  active_names[active_count++] = "FIN"; }
    if (args.scan_type & SCAN_XMAS) { active_idxs[active_count] = SCAN_IDX_XMAS; active_names[active_count++] = "XMAS"; }
    if (args.scan_type & SCAN_UDP)  { active_idxs[active_count] = SCAN_IDX_UDP;  active_names[active_count++] = "UDP"; }

    /* Header */
    printf("%-6s %-12s", "Port", "Service");
    for (int a = 0; a < active_count; a++)
        printf(" %-9s", active_names[a]);
    printf("\n");

    /* Counters per active scan */
    int cnt_open[SCAN_COUNT] = {0};
    int cnt_closed[SCAN_COUNT] = {0};
    int cnt_filtered[SCAN_COUNT] = {0};

    /* Rows */
    for (int i = 0; i < args.port_count; i++)
    {
        t_result *r = &args.results[i];
        struct servent *s = getservbyport(htons(r->port), "tcp");
    printf("%-6d %-12s", r->port, s ? s->s_name : "-");
        for (int a = 0; a < active_count; a++)
        {
            uint8_t st = r->scan_results[active_idxs[a]];
            const char *st_str = (st == STATUS_OPEN) ? "open" : (st == STATUS_CLOSED) ? "closed" : (st == STATUS_FILTERED) ? "filtered" : "-";
            if (st == STATUS_OPEN) cnt_open[active_idxs[a]]++;
            else if (st == STATUS_CLOSED) cnt_closed[active_idxs[a]]++;
            else if (st == STATUS_FILTERED) cnt_filtered[active_idxs[a]]++;

            printf(" %-9s", st_str);
        }
        printf("\n");
    }

    /* Summary counts */
    printf("\nSummary:\n");
    for (int a = 0; a < active_count; a++)
    {
        int idx = active_idxs[a];
        printf("%s: %d open, %d closed, %d filtered\n", active_names[a], cnt_open[idx], cnt_closed[idx], cnt_filtered[idx]);
    }

    // Cleanup
    free(args.port_list);
    if (args.results)
        free(args.results);
    if (args.local_ip)
        free(args.local_ip);
    return (0);
}
