#ifndef SIOV_CLI_H
#define SIOV_CLI_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    size_t count;
    bool verify;
    bool trace;
    bool batch;
} siov_cli_opts_t;

int siov_cli_parse(int argc, char **argv, siov_cli_opts_t *opts);
void siov_cli_usage(const char *prog);

#endif /* SIOV_CLI_H */
