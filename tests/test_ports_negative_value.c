#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../includes/ft_nmap.h"

int main(void)
{
    /* parse_ports is expected to exit on invalid/negative port values; run in child */
    pid_t pid = fork();
    if (pid == 0)
    {
        t_nmap_args args;
        memset(&args, 0, sizeof(args));
        args.ports = strdup("-1,22");
        parse_ports(&args);
        /* If parse_ports returns, it's a failure for this test */
        fprintf(stderr, "FAIL: parse_ports did not exit on negative port input\n");
        _exit(2);
    }
    else if (pid > 0)
    {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        {
            printf("PASS: ports negative value rejected (child rc=%d)\n", WEXITSTATUS(status));
            return 0;
        }
        printf("FAIL: ports negative value test (child status=%d)\n", status);
        return 2;
    }
    fprintf(stderr, "FAIL: fork failed\n");
    return 2;
}