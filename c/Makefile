CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -Wpedantic -O2 -D_GNU_SOURCE
LDFLAGS = -lpthread -lm

# To build with libcurl (enables HTTPS):
#   make USE_CURL=1
ifdef USE_CURL
CFLAGS  += -DUSE_CURL
LDFLAGS += -lcurl
endif

TARGET = logsystem
SRCS   = main.c \
         src/log_event.c \
         src/ring_buffer.c \
         src/collector.c \
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
