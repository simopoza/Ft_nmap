#include "../includes/ft_nmap.h"

/* Return a malloc'd IP string for given hostname or dotted IP, or NULL on failure.
   Caller must free the returned string. This function does not exit the process. */
char *resolve_target_str(const char *name)
{
    if (!name) return NULL;
    struct in_addr addr;
    if (inet_pton(AF_INET, name, &addr) == 1)
    {
        return strdup(name);
    }

    struct hostent *he = gethostbyname(name);
    if (!he) return NULL;
    char *ip_str = inet_ntoa(*(struct in_addr*)he->h_addr_list[0]);
    if (!ip_str) return NULL;
    return strdup(ip_str);
}

/* Backwards-compatible wrapper used by main code: resolves and updates args->ip in-place.
   On failure it will print an error and exit to preserve previous behavior. */
void resolve_target(t_nmap_args *args)
{
    if (!args || !args->ip) return;
    char *res = resolve_target_str(args->ip);
    if (!res)
    {
        fprintf(stderr, "Error: Could not resolve hostname '%s'\n", args->ip);
        exit(1);
    }
    /* replace args->ip with allocated string
       If args->ip was previously heap-allocated (e.g. when read from a file),
       free it to avoid leaking. When args->ip comes from argv (not owned) we
       must not free it; main sets args->file when reading from a file, so use
       that as an ownership indicator. */
    if (args->file && args->ip)
    {
        free(args->ip);
    }
    args->ip = res;
    printf("Resolved to %s\n", args->ip);
}
