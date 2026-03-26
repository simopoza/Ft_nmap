#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "../includes/ft_nmap.h"

int main(void)
{
    char tmpl[] = "/tmp/ftnmap_targets.XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) { fprintf(stderr, "FAIL: mkstemp\n"); return 2; }
    const char *lines = "\n127.0.0.1\n\nlocalhost\n";
    write(fd, lines, strlen(lines));
    close(fd);

    pid_t pid = fork();
    if (pid == 0)
    {
        execlp("./ft_nmap", "ft_nmap", "--file", tmpl, "--ports", "1-5", NULL);
        _exit(2);
    }
    else if (pid > 0)
    {
        int status;
        waitpid(pid, &status, 0);
        unlink(tmpl);
        if (WIFSIGNALED(status))
        {
            fprintf(stderr, "FAIL: ft_nmap crashed on multiple-targets file (signal=%d)\n", WTERMSIG(status));
            return 2;
        }
        printf("PASS: multiple targets file handled (child status=%d)\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 0;
    }
    unlink(tmpl);
    fprintf(stderr, "FAIL: fork failed\n");
    return 2;
}