#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../includes/ft_nmap.h"

int main(void)
{
    t_nmap_args args;

    char *argv[] = { "ft_nmap", "--ip", "1.2.3.4", "--ports", "22,80", "--scan", "SYN,UDP", "--speedup", "3", NULL };
    int argc = 9;

    int rc = parse_args(argc, argv, &args);
    int ok = 1;
    if (rc != PARSE_OK)
    {
        fprintf(stderr, "FAIL: parse_args returned error %d\n", rc);
        return 2;
    }
    if (!args.ip || strcmp(args.ip, "1.2.3.4") != 0)
    {
        fprintf(stderr, "FAIL: ip mismatch\n");
        ok = 0;
    }
    if (args.threads != 3)
    {
        fprintf(stderr, "FAIL: threads expected 3 got %d\n", args.threads);
        ok = 0;
    }
    if (!args.ports || strcmp(args.ports, "22,80") != 0)
    {
        fprintf(stderr, "FAIL: ports expected '22,80' got '%s'\n", args.ports ? args.ports : "(null)");
        ok = 0;
    }
    if (!(args.scan_type & SCAN_SYN))
    {
        fprintf(stderr, "FAIL: SCAN_SYN not set\n");
        ok = 0;
    }
    if (!(args.scan_type & SCAN_UDP))
    {
        fprintf(stderr, "FAIL: SCAN_UDP not set\n");
        ok = 0;
    }

    /* cleanup */
    if (args.ports) free(args.ports);

    if (ok)
    {
        printf("PASS: args parsing test\n");
        return 0;
    }
    else
    {
        printf("FAIL: args parsing test\n");
        return 2;
    }
}
