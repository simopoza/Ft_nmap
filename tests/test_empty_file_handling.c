#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "../includes/ft_nmap.h"

int main(void)
{
    char tmpl[] = "/tmp/ftnmap_empty.XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) { fprintf(stderr, "FAIL: mkstemp\n"); return 2; }
    /* leave file empty */
    close(fd);

    pid_t pid = fork();
    if (pid == 0)
    {
        /* Child: exec the main binary with the empty file; ensure it does not crash */
        execlp("./ft_nmap", "ft_nmap", "--file", tmpl, NULL);
        /* If exec fails */
        _exit(2);
    }
    else if (pid > 0)
    {
        int status;
        waitpid(pid, &status, 0);
        unlink(tmpl);
        if (WIFSIGNALED(status))
        {
            fprintf(stderr, "FAIL: ft_nmap crashed on empty file (signal=%d)\n", WTERMSIG(status));
            return 2;
        }
        /* Normal exit (even non-zero) is acceptable for this negative test as long as it's not a crash */
        printf("PASS: empty file handling (child status=%d)\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 0;
    }
    unlink(tmpl);
    fprintf(stderr, "FAIL: fork failed\n");
    return 2;
}