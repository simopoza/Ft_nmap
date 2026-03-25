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

    /* Build per-port presentation and split Open vs Others to match correction screenshots */
    // Prepare arrays
    int *is_open = calloc(args.port_count, sizeof(int));
    char **results_str = calloc(args.port_count, sizeof(char *));
    if (!is_open || !results_str) { perror("calloc"); exit(1); }

    for (int i = 0; i < args.port_count; i++)
    {
        t_result *r = &args.results[i];
        // build per-scan results like: SYN(Open) NULL(Closed) FIN(Closed)
        char buf[512];
        buf[0] = '\0';
        int any_open = 0;
        for (int a = 0; a < active_count; a++)
        {
            int sidx = active_idxs[a];
            uint8_t st = r->scan_results[sidx];
            const char *label = active_names[a];
            const char *stname;
            if (st == STATUS_OPEN) { stname = "Open"; any_open = 1; }
            else if (st == STATUS_CLOSED) stname = "Closed";
            else if (st == STATUS_FILTERED) stname = "Filtered";
            else if (st == STATUS_UNFILTERED) stname = "Unfiltered";
            else if (st == STATUS_OPEN_FILTERED) { stname = "Open|Filtered"; any_open = 1; }
            else stname = "-";

            if (a > 0) strncat(buf, " ", sizeof(buf)-strlen(buf)-1);
            strncat(buf, label, sizeof(buf)-strlen(buf)-1);
            strncat(buf, "(", sizeof(buf)-strlen(buf)-1);
            strncat(buf, stname, sizeof(buf)-strlen(buf)-1);
            strncat(buf, ")", sizeof(buf)-strlen(buf)-1);
        }
        results_str[i] = strdup(buf);
        is_open[i] = any_open;
    }

    // Print Open ports table
    printf("Open ports:\n");
    printf("Port  Service Name (if applicable)   Results\n");
    printf("--------------------------------------------------------------\n");
    for (int i = 0; i < args.port_count; i++)
    {
        if (!is_open[i]) continue;
        t_result *r = &args.results[i];
        struct servent *s = getservbyport(htons(r->port), "tcp");
        printf("%-5d %-30s %s\n", r->port, s ? s->s_name : "Unassigned", results_str[i]);
    }

    // Print Others table
    printf("\nClosed/Filtered/Unfiltered ports:\n");
    printf("Port  Service Name (if applicable)   Results\t\tConclusion\n");
    printf("-----------------------------------------------------------------------\n");
    for (int i = 0; i < args.port_count; i++)
    {
        if (is_open[i]) continue;
        t_result *r = &args.results[i];
        struct servent *s = getservbyport(htons(r->port), "tcp");

        // Determine conclusion
        const char *concl = "Filtered";
        int any_unfiltered = 0;
        int any_openfiltered = 0;
        int all_closed = 1;
        for (int a = 0; a < active_count; a++)
        {
            uint8_t st = r->scan_results[active_idxs[a]];
            if (st == STATUS_OPEN) { all_closed = 0; any_unfiltered = 0; concl = "Open"; break; }
            if (st == STATUS_UNFILTERED) any_unfiltered = 1;
            if (st == STATUS_OPEN_FILTERED) any_openfiltered = 1;
            if (st != STATUS_CLOSED) all_closed = 0;
        }
        if (strcmp(concl, "Open") != 0)
        {
            if (any_unfiltered) concl = "Unfiltered";
            else if (any_openfiltered) concl = "Open|Filtered";
            else if (all_closed) concl = "Closed";
            else concl = "Filtered";
        }

        printf("%-5d %-30s %s\t%s\n", r->port, s ? s->s_name : "Unassigned", results_str[i], concl);
    }

    // Free temporary storage
    for (int i = 0; i < args.port_count; i++) if (results_str[i]) free(results_str[i]);
    free(results_str);
    free(is_open);

    // Cleanup
    free(args.port_list);
    if (args.results)
        free(args.results);
    if (args.local_ip)
        free(args.local_ip);
    return (0);
}
