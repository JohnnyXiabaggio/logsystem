# Compliance Posture — logsystem (C implementation)

This document records how the C implementation satisfies the three
target standards and lists every documented deviation.

| Standard / Framework            | Coverage             |
|---------------------------------|----------------------|
| MISRA C:2012 (mandatory)        | Full                 |
| MISRA C:2012 (required)         | Full, deviations as noted below |
| IEC 61508 SIL-2 (coding rules)  | Full                 |
| CWE Top-25 (applicable items)   | Mitigated, see table |

---

## 1. Cybersecurity controls

| CWE   | Risk                                | Mitigation |
|-------|-------------------------------------|------------|
| 20    | Improper Input Validation           | All public APIs check NULL and ranges; URL port parsed by `strtol` and validated against [1..65535]. |
| 120   | Buffer Copy Without Checking Size   | Every `snprintf` checks the return value; every fixed buffer is sized by a compile-time constant; `json_escape` calculates exact per-character byte need before writing. |
| 134   | Uncontrolled Format String          | `-Wformat=2 -Wformat-security -Wformat-nonliteral` enforced under `-Werror`; every format string is a literal. |
| 190   | Integer Overflow / Wraparound       | Capacity macros guarded by `LOGSYS_STATIC_ASSERT`; backoff doubling checks `delay <= UINT32_MAX / 2U`; `snprintf` return widths cast only after `n >= 0` test. |
| 200   | Information Exposure                | `-k` argv slot is overwritten with `*` after copy so the bearer token does not appear in `/proc/<pid>/cmdline`. The env-var path is recommended. |
| 252   | Unchecked Return Value              | All `pthread_*`, `setsockopt`, `connect`, `send`, `recv`, `snprintf`, `clock_gettime` calls checked or explicitly `(void)` cast with rationale. |
| 311   | Missing Encryption of Sensitive Data| HTTPS available via `make USE_CURL=1`; plain HTTP is the default for development only and is documented as such. |
| 316   | Cleartext Storage of Sensitive Info | The bearer-token request header buffer is `memset(0)` before each function returns. Uploader and monitor key fields are wiped during `pipeline_destroy`. |
| 330   | Use of Insufficiently Random Values | UUIDs use `/dev/urandom`; a deterministic fallback runs only if `/dev/urandom` is unreachable, and the caller is notified via `LOGSYS_ERR_IO`. |
| 416   | Use After Free                      | No `free()` exists in the build; all memory is `.bss`-resident statics. |
| 476   | NULL Pointer Dereference            | Every API entry point validates pointer parameters before use; `_init` sets `initialised` flag, all operations check it. |
| 532   | Insertion of Sensitive Info into Log| The bearer token is never passed to `fprintf`; only the first 8 chars of batch UUIDs are emitted in diagnostics. |
| 732   | Incorrect Permission Assignment     | No file creation paths; only read-only `fopen("r")`. |
| 787   | Out-of-bounds Write                 | `-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, and `-Werror` cover compile- and run-time detection. Verified clean under AddressSanitizer + UBSan (`make DEBUG=1`). |

Hardening at link time: `-pie`, `-Wl,-z,relro`, `-Wl,-z,now`, `-Wl,-z,noexecstack`.

---

## 2. Functional Safety (IEC 61508 SIL-2 style)

| Property                              | Evidence |
|---------------------------------------|----------|
| No dynamic memory allocation          | Audit: `grep -rn 'malloc\|calloc\|realloc\|free\|strdup' src/` returns no hits in `src/`. Ring buffer, batch buffer, file-tail state and rolling windows are all `.bss` statics. |
| Deterministic memory footprint        | All sizes fixed at compile time via `RB_CAPACITY`, `UPLOADER_BATCH_MAX`, `COLLECTOR_MAX_FILES`, `MON_WIN_MAX`. `LOGSYS_STATIC_ASSERT` enforces sane bounds. |
| Bounded loops                         | Rolling-window eviction loops guarded by an explicit `guard = MON_WIN_MAX` counter; collector poll loop capped at `COLLECTOR_LINES_PER_CYCLE`; shutdown drain capped at 1024 iterations. |
| No recursion                          | Audit: call graph is iterative; no function calls itself directly or transitively. |
| All errors detected and reported      | Every public function returns `LogSysErr`; pipeline propagates `uploader_send` errors to stderr; counters in `Collector.lines_dropped`, `RingBuffer.dropped`, `Uploader.total_failed`. |
| Safe shutdown                         | `pipeline_run_until_signal` uses `sigaction` with empty mask and no `SA_RESTART`; `pipeline_stop` joins all threads with bounded final drain. |
| No undefined behavior                 | Verified clean under `-fsanitize=address,undefined`. |
| Worst-case execution time predictable | Single bounded retry loop per batch; per-event monitor loop bounded by `MON_WIN_MAX`. |

---

## 3. MISRA C:2012 conformance

### Mandatory rules — all satisfied

Rules 9.1, 12.5, 13.6, 17.3, 17.4, 17.6, 19.1, 21.13, 21.17, 21.18, 21.19, 21.20, 22.2, 22.4, 22.5, 22.6.

### Required-rule highlights

| Rule | Notes |
|------|-------|
| 1.3  | UB-free under sanitisers. |
| 8.2  | All function definitions and prototypes use named parameters. |
| 8.4  | Every external function has a declaration in its `.h`. |
| 8.7  | Internal helpers (`str_contains_icase`, `tail_open`, `tail_close`, `tail_poll`, `collector_thread`, `flush_thread`, `health_thread`, `sig_handler`, `is_retryable_status`, `sleep_ms`, `build_batch_json`, `parse_url`, `http_post_socket`, `post_alert`, `post_alert_http`, `mono_now`, `win_*`) are declared `static`. |
| 10.1–10.4 | Essential types respected: `uint32_t` for sizes/indices, `uint8_t` for tag count, `bool_t` for predicates, `int32_t` for error codes. |
| 11.3 | No object-pointer reinterpretation casts. |
| 14.4 | Controlling expressions use `bool_t` or explicit comparisons (`g_stop == 0`, `count > 0U`). |
| 15.5 | Single point of exit per function across all public APIs; the one `goto cleanup` in `main.c` is documented as a deviation (cleanup labels are explicitly permitted under typical MISRA deviation policies). |
| 16.4 | `sev_label` switch has a `default` clause. |
| 17.7 | All return values used or `(void)` cast with rationale. |
| 21.3 | No `malloc/calloc/realloc/free`. |
| 21.6 | `<stdio.h>` used for human-readable diagnostics only — documented deviation. |
| 21.7 | `atoi/atol/atof` replaced with `strtol/strtod` + endptr + range check. |

### Deviations (with justification)

| Rule | Where | Reason |
|------|-------|--------|
| 15.1 | `main.c` `goto cleanup` | Single-point cleanup pattern preferred over deep nesting; reviewed and documented. |
| 21.5 | `signal.h` use (`sigaction`) | Required for graceful SIGINT/SIGTERM shutdown on POSIX. |
| 21.6 | `<stdio.h>` (`fprintf` to stderr) | Required for operational diagnostics; no `printf`-family call uses user-controlled format strings. |
| 21.10| Time/date functions (`gmtime_r`, `clock_gettime`) | POSIX reentrant variants used; required for timestamping. |

---

## 4. Build & verification

```
# Production safety build (default)
make
#   -std=c99 -Werror -Wall -Wextra -Wpedantic
#   -Wshadow -Wundef -Wcast-align -Wcast-qual
#   -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes
#   -Wmissing-declarations -Wnested-externs -Wredundant-decls
#   -Wformat=2 -Wformat-security -Wformat-nonliteral
#   -Wnull-dereference -Wstack-protector
#   -fstack-protector-strong -fno-strict-aliasing -fno-common
#   -D_FORTIFY_SOURCE=2 -fPIE -O2
#   -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

# Debug + AddressSanitizer + UndefinedBehaviorSanitizer
make DEBUG=1

# HTTPS support via libcurl
make USE_CURL=1
```

Continuous-integration verification chain:
1. `make` — zero warnings under `-Werror`.
2. `make DEBUG=1 && echo … | ./logsystem -s -n` — clean run under ASan + UBSan.
3. (External) MISRA-checker integration recommended (e.g. cppcheck `--addon=misra`).
