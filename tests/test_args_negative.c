#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../includes/ft_nmap.h"

int main(void)
{
    /* Directly call parse_args and expect a non-zero error code */
    t_nmap_args args;
    char *argv[] = { "ft_nmap", "--ip", "1.2.3.4", "--scan", "UNKNOWN", NULL };
    int argc = 5;
    int rc = parse_args(argc, argv, &args);
    if (rc != PARSE_OK)
    {
        printf("PASS: args negative parsing test (rc=%d)\n", rc);
        return 0;
    }
    else
    {
        printf("FAIL: args negative parsing test (rc=%d)\n", rc);
        return 2;
    }
}
