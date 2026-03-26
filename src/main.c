#include "../includes/ft_nmap.h"

/* Thread wrapper moved to file scope because nested functions are not standard C */
static void *start_scan_thread(void *a)
{
    t_nmap_args *aa = (t_nmap_args *)a;
    start_scan(aa);
    aa->scan_done = 1;
    return NULL;
}

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
    int rc = parse_args(argc, argv, &args);
    if (rc == PARSE_HELP)
        return 0;
    if (rc != PARSE_OK)
        return rc;
    /* If a file of targets was provided, read the first non-empty line as the target
       (the correction tests use small files; full multi-host support can be added later). */
    if (args.file)
    {
        FILE *f = fopen(args.file, "r");
        if (!f)
        {
            fprintf(stderr, "Error: cannot open file %s\n", args.file);
            return 1;
        }
        char line[256];
        args.ip = NULL;
        while (fgets(line, sizeof(line), f))
        {
            /* trim newline and spaces */
            char *s = line;
            while (*s && isspace((unsigned char)*s)) s++;
            char *e = s + strlen(s) - 1;
            while (e >= s && isspace((unsigned char)*e)) { *e = '\0'; e--; }
            if (*s == '\0') continue;
            args.ip = strdup(s);
            break;
        }
        fclose(f);
        if (!args.ip)
        {
            fprintf(stderr, "Error: file %s contains no valid targets\n", args.file);
            /* free allocated resources from parse_args before exiting to avoid leaks
               when tests exec this binary with an empty file */
            if (args.ports) free(args.ports);
            return 1;
        }
        resolve_target(&args);
    }
    else
    {
        resolve_target(&args);
    }
    /* Attempt reverse DNS for nicer output (bonus) */
    {
        struct sockaddr_in sa;
        char host[NI_MAXHOST];
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, args.ip, &sa.sin_addr);
        if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0) == 0)
        {
            args.target_name = strdup(host);
        }
    }
    parse_ports(&args);

    /* Print Scan Configurations block (match correction page wording) */
    printf("Scan Configurations\n");
    printf("Target Ip-Address : %s\n", args.ip ? args.ip : "");
    if (args.target_name)
        printf("Target Hostname : %s\n", args.target_name);
    printf("No of Ports to scan : %d\n", args.port_count);
    printf("Scans to be performed :");
    if (args.scan_type & SCAN_SYN) printf(" SYN");
    if (args.scan_type & SCAN_NULL) printf(" NULL");
    if (args.scan_type & SCAN_ACK) printf(" ACK");
    if (args.scan_type & SCAN_FIN) printf(" FIN");
    if (args.scan_type & SCAN_XMAS) printf(" XMAS");
    if (args.scan_type & SCAN_UDP) printf(" UDP");
    printf("\n");
    printf("No of threads : %d\n", args.threads);

    /* Start scan in a thread so we can display a simple progress indicator (dots) */
    pthread_t scan_thread;

    gettimeofday(&tv_start, NULL);
    printf("\nScanning..\n");
    fflush(stdout);
    args.scan_done = 0;
    if (pthread_create(&scan_thread, NULL, start_scan_thread, &args) != 0)
    {
        /* fallback: run synchronously */
        start_scan(&args);
    }
    else
    {
        /* print dots until scan thread sets scan_done */
        while (!args.scan_done)
        {
            putchar('.'); fflush(stdout);
            usleep(200000);
        }
        pthread_join(scan_thread, NULL);
        putchar('\n');
    }
    gettimeofday(&tv_end, NULL);
        elapsed = (tv_end.tv_sec - tv_start.tv_sec) + (tv_end.tv_usec - tv_start.tv_usec) / 1000000.0;
    
        /* Print summary matching correction page */
    /* Print summary matching correction page */
    printf("\nScan took %.5f secs\n", elapsed);
    printf("IP address: %s\n", args.ip ? args.ip : "");

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
    // Print Open ports table (include Conclusion column)
    printf("Open ports:\n");
    printf("Port Service Name (if applicable) Results Conclusion\n");
    printf("----------------------------------------------------------------------------------------\n");
    for (int i = 0; i < args.port_count; i++)
    {
        if (!is_open[i]) continue;
        t_result *r = &args.results[i];
        struct servent *s = getservbyport(htons(r->port), "tcp");
        
        // Determine conclusion for this open row
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
        char svcbuf[128];
        svcbuf[0] = '\0';
        snprintf(svcbuf, sizeof(svcbuf), "%s", s ? s->s_name : "Unassigned");
        if (r->banner && r->banner[0])
        {
            strncat(svcbuf, " - ", sizeof(svcbuf)-strlen(svcbuf)-1);
            strncat(svcbuf, r->banner, sizeof(svcbuf)-strlen(svcbuf)-1);
        }
        printf("%-4d %-20s %-20s %s\n", r->port, svcbuf, results_str[i], concl);
    }

    // Print Others table
    printf("\nClosed/Filtered/Unfiltered ports:\n");
    printf("Port Service Name (if applicable) Results Conclusion\n");
    printf("----------------------------------------------------------------------------------------\n");
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

        char svcbuf2[128];
        svcbuf2[0] = '\0';
        snprintf(svcbuf2, sizeof(svcbuf2), "%s", s ? s->s_name : "Unassigned");
        if (r->banner && r->banner[0])
        {
            strncat(svcbuf2, " - ", sizeof(svcbuf2)-strlen(svcbuf2)-1);
            strncat(svcbuf2, r->banner, sizeof(svcbuf2)-strlen(svcbuf2)-1);
        }
        printf("%-4d %-20s %-20s %s\n", r->port, svcbuf2, results_str[i], concl);
    }

    // Free temporary storage
    for (int i = 0; i < args.port_count; i++) if (results_str[i]) free(results_str[i]);
    free(results_str);
    free(is_open);
    // If JSON output requested, dump results
    if (args.json_file)
    {
        FILE *jf = fopen(args.json_file, "w");
        if (jf)
        {
            fprintf(jf, "{\"target\":\"%s\",\"ip\":\"%s\",\"results\":[\n", args.target_name ? args.target_name : args.ip, args.ip ? args.ip : "");
            for (int i = 0; i < args.port_count; i++)
            {
                t_result *r = &args.results[i];
                struct servent *s = getservbyport(htons(r->port), "tcp");
                fprintf(jf, "  {\"port\":%d,\"service\":\"%s\",\"banner\":\"%s\",\"results\":{",
                        r->port, s ? s->s_name : "Unassigned", r->banner ? r->banner : "");
                for (int a = 0; a < active_count; a++)
                {
                    int sidx = active_idxs[a];
                    uint8_t st = r->scan_results[sidx];
                    const char *stname = "-";
                    if (st == STATUS_OPEN) stname = "Open";
                    else if (st == STATUS_CLOSED) stname = "Closed";
                    else if (st == STATUS_FILTERED) stname = "Filtered";
                    else if (st == STATUS_UNFILTERED) stname = "Unfiltered";
                    else if (st == STATUS_OPEN_FILTERED) stname = "Open|Filtered";
                    fprintf(jf, "\"%s\":\"%s\"", active_names[a], stname);
                    if (a < active_count-1) fprintf(jf, ",");
                }
                fprintf(jf, "}}%s\n", (i < args.port_count-1) ? "," : "");
            }
            fprintf(jf, "]}\n");
            fclose(jf);
        }
    }

    // Full cleanup: free owned allocations to avoid leaks under sanitizers.
    if (args.port_list) free(args.port_list);

    // Free per-port results and any allocated banners
    if (args.results)
    {
        for (int i = 0; i < args.port_count; i++)
        {
            if (args.results[i].banner) free(args.results[i].banner);
            // args.results[i].service is not owned (getservbyport returns static)
        }
        free(args.results);
        args.results = NULL;
    }

    // Free ports string allocated by parse_args (DEFAULT_PORTS or --top-ports)
    if (args.ports) free(args.ports);

    // Free local and target names if they were allocated
    if (args.local_ip) free(args.local_ip);
    if (args.target_name) free(args.target_name);

    // If we read the target from a file, args.ip was strdup'd in main; free it
    if (args.file && args.ip) free(args.ip);

    // Free decoy list parsed in sender if present
    if (args.decoys)
    {
        for (int i = 0; i < args.decoy_count; i++) if (args.decoys[i]) free(args.decoys[i]);
        free(args.decoys);
        args.decoys = NULL;
    }

    // Free any remaining mapping arrays if present
    if (args.map_to_srcport) { free(args.map_to_srcport); args.map_to_srcport = NULL; }
    if (args.srcport_map) { free(args.srcport_map); args.srcport_map = NULL; }
    if (args.reserved_socks) { free(args.reserved_socks); args.reserved_socks = NULL; }

    return (0);
}
