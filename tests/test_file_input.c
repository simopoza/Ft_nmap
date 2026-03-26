#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "../includes/ft_nmap.h"

int main(void)
{
    char tmpl[] = "/tmp/ftnmap_test_file.XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) { fprintf(stderr, "FAIL: mkstemp\n"); return 2; }
    const char *line = "127.0.0.1\n";
    write(fd, line, strlen(line));
    close(fd);

    t_nmap_args args;
    memset(&args, 0, sizeof(args));
    char *argv[] = { "ft_nmap", "--file", tmpl, NULL };
    int rc = parse_args(3, argv, &args);
    if (rc != PARSE_OK)
    {
        fprintf(stderr, "FAIL: parse_args failed with %d\n", rc);
        unlink(tmpl);
        return 2;
    }
    if (!args.file || strcmp(args.file, tmpl) != 0)
    {
        fprintf(stderr, "FAIL: file not set or mismatch (got '%s' expected '%s')\n", args.file ? args.file : "(null)", tmpl);
        if (args.file) free(args.file);
        unlink(tmpl);
        return 2;
    }

     /* args.file points into our argv/tmp buffer (not malloc'd here), so do not free it.
         Free args->ports which was strdup'd in parse_args. */
     if (args.ports) free(args.ports);
     unlink(tmpl);
    printf("PASS: file input parse test\n");
    return 0;
}
