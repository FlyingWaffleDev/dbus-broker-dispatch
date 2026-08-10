#pragma once

#include "util.h"

#include <signal.h>
#include <stdint.h>

typedef struct EventLoop EventLoop;
typedef struct EventSource EventSource;
typedef bool (*EventFunc)(EventSource *source, uint32_t events, void *data, Error **error);

struct EventSource {
        EventLoop *loop;
        int fd;
        uint32_t events;
        EventFunc callback;
        void *data;
        bool registered;
};

struct EventLoop {
        int epoll_fd;
        bool running;
};

bool event_loop_init(EventLoop *loop, Error **error);
void event_loop_clear(EventLoop *loop);
bool event_source_add(EventLoop *loop, EventSource *source, int fd, uint32_t events, EventFunc callback, void *data,
                      Error **error);
bool event_source_update(EventSource *source, uint32_t events, Error **error);
void event_source_remove(EventSource *source);
bool event_loop_dispatch(EventLoop *loop, int timeout_ms, Error **error);
bool event_loop_run(EventLoop *loop, Error **error);
void event_loop_quit(EventLoop *loop);

int event_signal_fd(const int *signals, size_t n_signals, sigset_t *previous_mask, Error **error);
int event_timer_fd(Error **error);
bool event_timer_arm(int fd, uint64_t milliseconds, bool periodic, Error **error);
bool event_counter_consume(int fd, uint64_t *value, Error **error);
