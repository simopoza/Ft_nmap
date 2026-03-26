#include "../includes/ft_nmap.h"

// Helper function to check if string contains only valid characters for port parsing
static bool is_valid_port_str(const char *str)
{
    while (*str)
    {
        if (!isdigit(*str) && *str != '-' && *str != ',')
            return false;
        str++;
    }
    return true;
}

static void add_port(uint16_t port, bool *seen, t_nmap_args *args)
{
    if (seen[port])
    {
        return;
    }
    if (args->port_count >= MAX_PORTS_TO_SCAN)
    {
        /* Reached configured maximum; ignore additional ports instead of exiting */
        fprintf(stderr, "Warning: Max ports to scan is %d. Ignoring additional ports.\n", MAX_PORTS_TO_SCAN);
        return;
    }
    seen[port] = true;
    args->port_list[args->port_count++] = port;
}

static void parse_range(char *str, bool *seen, t_nmap_args *args)
{
    char *dash = strchr(str, '-');
    if (dash)
    {
        *dash = '\0';
        // Handle empty or invalid range parts
        if (str[0] == '\0' || dash[1] == '\0')
        {
            fprintf(stderr, "Error: Invalid range format\n");
            exit(1);
        }
        int start = atoi(str);
        int end = atoi(dash + 1);
        
        if (start < 1 || start > 65535 || end < 1 || end > 65535 || start > end)
        {
            fprintf(stderr, "Error: Invalid port range %d-%d\n", start, end);
            exit(1);
        }
        for (int i = start; i <= end; i++)
        {
            add_port((uint16_t)i, seen, args);
        }
    }
    else
    {
        if (str[0] == '\0') return; // Skip empty tokens
        int port = atoi(str);
        if (port < 1 || port > 65535)
        {
            fprintf(stderr, "Error: Invalid port %d\n", port);
            exit(1);
        }
        add_port((uint16_t)port, seen, args);
    }
}

void parse_ports(t_nmap_args *args)
{
    if (!is_valid_port_str(args->ports))
    {
        fprintf(stderr, "Error: Invalid characters in port string '%s'\n", args->ports);
        exit(1);
    }

    // Allocate on heap to avoid large stack usage?  bool seen[65536] is 64KB, which is fine on stack.
    // But setting it to all false is needed.
    bool *seen = calloc(65536, sizeof(bool));
    if (!seen)
    {
        perror("calloc");
        exit(1);
    }

    args->port_list = malloc(sizeof(uint16_t) * MAX_PORTS_TO_SCAN);
    if (!args->port_list)
    {
        perror("malloc");
        free(seen);
        exit(1);
    }
    args->port_count = 0;

    char *copy = strdup(args->ports);
    if (!copy)
    {
        perror("strdup");
        free(seen);
        free(args->port_list);
        exit(1);
    }

    char *token = strtok(copy, ",");
    while (token)
    {
        parse_range(token, seen, args);
        token = strtok(NULL, ",");
    }
    free(copy);
    free(seen);

    if (args->port_count == 0)
    {
        fprintf(stderr, "Error: No valid ports found\n");
        exit(1);
    }
}

