#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../includes/ft_nmap.h"

int main(void)
{
    /* malformed port ranges like "10--20" should be rejected */
    pid_t pid = fork();
    if (pid == 0)
    {
        t_nmap_args args;
        memset(&args, 0, sizeof(args));
        args.ports = strdup("10--20");
        parse_ports(&args);
        fprintf(stderr, "FAIL: parse_ports did not exit on malformed range\n");
        _exit(2);
    }
    else if (pid > 0)
    {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        {
            printf("PASS: malformed ports rejected (child rc=%d)\n", WEXITSTATUS(status));
            return 0;
        }
        printf("FAIL: malformed ports test (child status=%d)\n", status);
        return 2;
    }
    return 2;
}