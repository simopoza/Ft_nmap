#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../includes/ft_nmap.h"

int test_positive()
{
    t_nmap_args args;
    memset(&args, 0, sizeof(args));
    args.ports = strdup("22,80,443");
    parse_ports(&args);
    int ok = 1;
    if (args.port_count != 3) { fprintf(stderr, "FAIL: expected 3 ports got %d\n", args.port_count); ok = 0; }
    if (args.port_list[0] != 22 || args.port_list[1] != 80 || args.port_list[2] != 443)
    {
        fprintf(stderr, "FAIL: port list mismatch\n"); ok = 0;
    }
    free(args.port_list);
    free(args.ports);
    return ok;
}

int test_negative_invalid()
{
    pid_t pid = fork();
    if (pid == 0)
    {
        t_nmap_args args;
        memset(&args, 0, sizeof(args));
        args.ports = strdup("70000");
        parse_ports(&args);
        /* parse_ports should exit on invalid input; if we reach here, it's a fail */
        fprintf(stderr, "FAIL: parse_ports did not exit on invalid input\n");
        _exit(2);
    }
    else if (pid > 0)
    {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
            return 1;
        return 0;
    }
    return 0;
}

int main(void)
{
    int ok = 1;
    if (!test_positive()) { printf("FAIL: ports positive\n"); ok = 0; }
    else printf("PASS: ports positive\n");

    if (!test_negative_invalid()) { printf("FAIL: ports negative invalid\n"); ok = 0; }
    else printf("PASS: ports negative invalid\n");

    return ok ? 0 : 2;
}
