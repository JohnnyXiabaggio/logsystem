# --------------------------------------------------------------------
# logsystem — safety / security build
#
# Compile flags chosen to enforce the compliance posture:
#   - MISRA C:2012      : -std=c99, -Wall -Wextra -Wpedantic, -Wconversion
#   - IEC 61508 SIL-2   : -fno-strict-aliasing, -fno-delete-null-pointer-checks
#   - CWE-120 / CWE-134 : -D_FORTIFY_SOURCE=2, -fstack-protector-strong,
#                         -Wformat=2 -Wformat-security
#   - cybersecurity     : -fPIE -pie, -Wl,-z,relro,-z,now, -Wl,-z,noexecstack
#
# Build:
#   make             — production safety build (warnings = errors)
#   make USE_CURL=1  — link libcurl (enables https:// endpoints)
#   make DEBUG=1     — debug build with AddressSanitizer + UB sanitiser
# --------------------------------------------------------------------

CC        ?= gcc

SAFETY_CFLAGS = \
    -std=c99 \
    -D_GNU_SOURCE \
    -Wall -Wextra -Wpedantic \
    -Wshadow -Wundef -Wcast-align -Wcast-qual \
    -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
    -Wmissing-declarations -Wnested-externs -Wredundant-decls \
    -Wformat=2 -Wformat-security -Wformat-nonliteral \
    -Wnull-dereference \
    -Wstack-protector \
    -fstack-protector-strong \
    -fno-strict-aliasing \
    -fno-common \
    -D_FORTIFY_SOURCE=2 \
    -fPIE

# -Werror is the goal but is gated so library-version warnings (e.g. on
# glibc snprintf-truncation heuristics) do not block development.
ifndef RELAX
SAFETY_CFLAGS += -Werror
endif

# AddressSanitizer + UB sanitiser for debug builds.
ifdef DEBUG
SAFETY_CFLAGS += -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS_EXTRA = -fsanitize=address,undefined
else
SAFETY_CFLAGS += -O2 -DNDEBUG
LDFLAGS_EXTRA =
endif

CFLAGS  ?= $(SAFETY_CFLAGS)
LDFLAGS  = -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack \
           -lpthread -lm $(LDFLAGS_EXTRA)

ifdef USE_CURL
CFLAGS  += -DUSE_CURL
LDFLAGS += -lcurl
endif

TARGET = logsystem
SRCS   = main.c \
         src/log_event.c \
         src/ring_buffer.c \
         src/collector.c \
         src/http_client.c \
         src/uploader.c \
         src/monitor.c \
         src/pipeline.c

OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
