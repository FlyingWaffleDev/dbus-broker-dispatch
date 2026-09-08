#define _GNU_SOURCE
#include "event.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

bool event_loop_init(EventLoop *loop, Error **error)
{
        *loop = (EventLoop){.epoll_fd = -1};
        loop->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (loop->epoll_fd < 0)
                return error_set_errno(error, errno, "Cannot create event loop");
        return true;
}

void event_loop_clear(EventLoop *loop)
{
        if (loop->epoll_fd >= 0)
                close(loop->epoll_fd);
        *loop = (EventLoop){.epoll_fd = -1};
}

bool event_source_add(EventLoop *loop, EventSource *source, int fd, uint32_t events, EventFunc callback, void *data,
                      Error **error)
{
        struct epoll_event event = {.events = events, .data.ptr = source};
        *source = (EventSource){.loop = loop, .fd = fd, .events = events, .callback = callback, .data = data};
        if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
                *source = (EventSource){.fd = -1};
                return error_set_errno(error, errno, "Cannot add event source");
        }
        source->registered = true;
        return true;
}

bool event_source_update(EventSource *source, uint32_t events, Error **error)
{
        struct epoll_event event = {.events = events, .data.ptr = source};
        if (!source->registered)
                return error_set(error, EINVAL, "Event source is not registered");
        if (epoll_ctl(source->loop->epoll_fd, EPOLL_CTL_MOD, source->fd, &event) < 0)
                return error_set_errno(error, errno, "Cannot update event source");
        source->events = events;
        return true;
}

void event_source_remove(EventSource *source)
{
        if (!source || !source->registered)
                return;
        epoll_ctl(source->loop->epoll_fd, EPOLL_CTL_DEL, source->fd, NULL);
        source->registered = false;
}

bool event_loop_dispatch(EventLoop *loop, int timeout_ms, Error **error)
{
        struct epoll_event events[32];
        int count;
        do
                count = epoll_wait(loop->epoll_fd, events, 32, timeout_ms);
        while (count < 0 && errno == EINTR);
        if (count < 0)
                return error_set_errno(error, errno, "Cannot wait for events");
        for (int i = 0; i < count; ++i) {
                EventSource *source = events[i].data.ptr;
                if (source->registered && !source->callback(source, events[i].events, source->data, error))
                        return false;
        }
        return true;
}

bool event_loop_run(EventLoop *loop, Error **error)
{
        loop->running = true;
        while (loop->running)
                if (!event_loop_dispatch(loop, -1, error))
                        return false;
        return true;
}

void event_loop_quit(EventLoop *loop)
{
        loop->running = false;
}

int event_signal_fd(const int *signals, size_t n_signals, sigset_t *previous_mask, Error **error)
{
        sigset_t mask, saved_mask;
        int fd;
        sigemptyset(&mask);
        for (size_t i = 0; i < n_signals; ++i)
                sigaddset(&mask, signals[i]);
        if (sigprocmask(SIG_BLOCK, &mask, &saved_mask) < 0) {
                error_set_errno(error, errno, "Cannot block event-loop signals");
                return -1;
        }
        if (previous_mask)
                *previous_mask = saved_mask;
        fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
        if (fd < 0) {
                int saved = errno;
                sigprocmask(SIG_SETMASK, &saved_mask, NULL);
                error_set_errno(error, saved, "Cannot create signal event source");
        }
        return fd;
}

int event_timer_fd(Error **error)
{
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
        if (fd < 0)
                error_set_errno(error, errno, "Cannot create timer event source");
        return fd;
}

bool event_timer_arm(int fd, uint64_t milliseconds, bool periodic, Error **error)
{
        struct itimerspec value = {0};
        value.it_value.tv_sec = (time_t)(milliseconds / 1000);
        value.it_value.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
        if (periodic)
                value.it_interval = value.it_value;
        if (timerfd_settime(fd, 0, &value, NULL) < 0)
                return error_set_errno(error, errno, "Cannot arm event timer");
        return true;
}

bool event_counter_consume(int fd, uint64_t *value, Error **error)
{
        ssize_t n;
        do
                n = read(fd, value, sizeof(*value));
        while (n < 0 && errno == EINTR);
        if (n == (ssize_t)sizeof(*value))
                return true;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                *value = 0;
                return true;
        }
        return error_set_errno(error, n < 0 ? errno : EIO, "Cannot consume event counter");
}
