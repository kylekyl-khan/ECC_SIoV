#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "siov_cli.h"

int siov_cli_parse(int argc, char **argv, siov_cli_opts_t *opts) {
    opts->count = 1;
    opts->verify = true;
    opts->trace = false;
    opts->batch = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            opts->count = (size_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--verify") == 0 && i + 1 < argc) {
            opts->verify = (strcmp(argv[++i], "on") == 0);
        } else if (strcmp(argv[i], "--trace") == 0 && i + 1 < argc) {
            opts->trace = (strcmp(argv[++i], "on") == 0);
        } else if (strcmp(argv[i], "--batch") == 0 && i + 1 < argc) {
            opts->batch = (strcmp(argv[++i], "on") == 0);
        } else {
            return -1;
        }
    }
    return 0;
}

void siov_cli_usage(const char *prog) {
    printf("Usage: %s --count N --verify on|off --trace on|off --batch on|off\n", prog);
}
