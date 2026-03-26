#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../includes/ft_nmap.h"

int main(void)
{
    char *out = NULL;
    int ok = 1;

    out = resolve_target_str("127.0.0.1");
    if (!out) { fprintf(stderr, "FAIL: resolve 127.0.0.1 returned NULL\n"); ok = 0; }
    else
    {
        if (strcmp(out, "127.0.0.1") != 0) { fprintf(stderr, "FAIL: resolved != 127.0.0.1 (%s)\n", out); ok = 0; }
        free(out);
    }

    out = resolve_target_str("localhost");
    if (!out) { fprintf(stderr, "FAIL: resolve localhost returned NULL\n"); ok = 0; }
    else { free(out); }

    out = resolve_target_str("no-such-host-should-fail-xyz");
    if (out) { fprintf(stderr, "FAIL: resolve nonexistent returned a value (%s)\n", out); free(out); ok = 0; }
    else { /* expected */ }

    if (ok) { printf("PASS: resolve tests\n"); return 0; }
    else { printf("FAIL: resolve tests\n"); return 2; }
}
