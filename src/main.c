#include "../includes/ft_nmap.h"

int main(int argc, char **argv)
{
    t_nmap_args args;

    if (argc < 2)
    {
        print_help();
        return (1);
    }
    parse_args(argc, argv, &args);
    resolve_target(&args);
    parse_ports(&args);
    print_config(&args);

    // Initial dummy scan
    start_scan(&args);
    
    // Cleanup
    free(args.port_list);
    if (args.results)
        free(args.results);
    if (args.ip)
    {
        // If ip was strdup'd by resolve_target we own it; otherwise free(NULL) is safe
        // To be conservative we free only if it's not pointing into argv (heuristic omitted).
        /* Note: we intentionally do not free argv pointers here; resolving replaces args.ip with a strdup when needed. */
    }
    return (0);
}
