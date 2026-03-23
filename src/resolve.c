#include "../includes/ft_nmap.h"

void resolve_target(t_nmap_args *args)
{
    struct in_addr addr;
    struct hostent *he;

    if (!args->ip)
        return;

    // Check if it's already a valid IP address
    if (inet_pton(AF_INET, args->ip, &addr) == 1)
        return;

    // If not, try to resolve hostname
    he = gethostbyname(args->ip);
    if (!he)
    {
        fprintf(stderr, "Error: Could not resolve hostname '%s': %s\n", args->ip, hstrerror(h_errno));
        exit(1);
    }

    // Use the first address found
    // inet_ntoa returns a statically allocated buffer, need to strdup
    char *ip_str = inet_ntoa(*(struct in_addr*)he->h_addr_list[0]);
    if (!ip_str)
    {
        fprintf(stderr, "Error: inet_ntoa failed\n");
        exit(1);
    }
    
    // Replace args->ip (which points to argv memory) with new allocated string
    // Note: We don't free the old args->ip because it points to stack/static memory from argv
    args->ip = strdup(ip_str);
    if (!args->ip)
    {
        perror("strdup");
        exit(1);
    }
    printf("Resolved to %s\n", args->ip);
}
