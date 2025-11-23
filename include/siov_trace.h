#ifndef SIOV_TRACE_H
#define SIOV_TRACE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "siov.h"

bool siov_trace_signature(const siov_signature_t *sig, const siov_params_t *params,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *ts, size_t ts_len, bool verbose);

#endif /* SIOV_TRACE_H */
