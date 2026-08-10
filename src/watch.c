#define _GNU_SOURCE
#include "watch.h"
#include "event.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct WatchEntry {
        char *target;
        char *monitored;
        int descriptor;
} WatchEntry;

struct Watch {
        int inotify_fd;
        int timer_fd;
        WatchFunc callback;
        void *data;
        PtrVec targets;
        PtrVec entries;
};

static void entry_free(void *data)
{
        WatchEntry *entry = data;
        if (entry) {
                free(entry->target);
                free(entry->monitored);
                free(entry);
        }
}

static char *nearest_existing(const char *path)
{
        char *candidate = path_canonicalize(path, NULL);
        struct stat st;
        if (!candidate)
                return NULL;
        if (lstat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
                char *parent = path_dirname(candidate);
                free(candidate);
                return parent;
        }
        while (lstat(candidate, &st) < 0 && errno == ENOENT) {
                char *parent = path_dirname(candidate);
                if (!parent) {
                        free(candidate);
                        return NULL;
                }
                if (strcmp(parent, candidate) == 0) {
                        free(parent);
                        break;
                }
                free(candidate);
                candidate = parent;
        }
        return candidate;
}

static void remove_watches(Watch *watch)
{
        for (size_t i = 0; i < watch->entries.len; ++i) {
                WatchEntry *entry = watch->entries.items[i];
                bool first = true;
                for (size_t j = 0; j < i; ++j)
                        if (((WatchEntry *)watch->entries.items[j])->descriptor == entry->descriptor) {
                                first = false;
                                break;
                        }
                if (first && entry->descriptor >= 0)
                        inotify_rm_watch(watch->inotify_fd, entry->descriptor);
        }
        ptr_vec_clear(&watch->entries);
}

static void discard_entries(Watch *watch, PtrVec *entries)
{
        for (size_t i = 0; i < entries->len; ++i) {
                WatchEntry *entry = entries->items[i];
                bool first = true;
                for (size_t j = 0; j < i; ++j)
                        if (((WatchEntry *)entries->items[j])->descriptor == entry->descriptor) {
                                first = false;
                                break;
                        }
                if (first && entry->descriptor >= 0)
                        inotify_rm_watch(watch->inotify_fd, entry->descriptor);
        }
        ptr_vec_clear(entries);
}

static bool rebuild(Watch *watch, Error **error)
{
        PtrVec entries;
        remove_watches(watch);
        ptr_vec_init(&entries, entry_free);
        for (size_t i = 0; i < watch->targets.len; ++i) {
                WatchEntry *entry = calloc(1, sizeof(*entry));
                if (!entry)
                        goto memory;
                entry->descriptor = -1;
                entry->target = strdup(watch->targets.items[i]);
                entry->monitored = nearest_existing(entry->target);
                if (!entry->target || !entry->monitored) {
                        entry_free(entry);
                        goto memory;
                }
                entry->descriptor =
                        inotify_add_watch(watch->inotify_fd, entry->monitored,
                                          IN_ATTRIB | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_DELETE_SELF |
                                                  IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO);
                if (entry->descriptor < 0) {
                        int saved = errno;
                        error_set_errno(error, saved, "Cannot monitor %s", entry->target);
                        entry_free(entry);
                        discard_entries(watch, &entries);
                        return false;
                }
                if (!ptr_vec_push(&entries, entry)) {
                        entry_free(entry);
                        goto memory;
                }
        }
        watch->entries = entries;
        return true;
memory:
        discard_entries(watch, &entries);
        return error_set(error, ENOMEM, "Cannot allocate file watches");
}

Watch *watch_new(WatchFunc callback, void *data, Error **error)
{
        Watch *watch = calloc(1, sizeof(*watch));
        if (!watch) {
                error_set(error, ENOMEM, "Cannot allocate file watcher");
                return NULL;
        }
        watch->inotify_fd = -1;
        watch->timer_fd = -1;
        ptr_vec_init(&watch->targets, free);
        ptr_vec_init(&watch->entries, entry_free);
        watch->callback = callback;
        watch->data = data;
        watch->inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
        if (watch->inotify_fd < 0) {
                error_set_errno(error, errno, "Cannot create file watcher");
                watch_free(watch);
                return NULL;
        }
        watch->timer_fd = event_timer_fd(error);
        if (watch->timer_fd < 0) {
                watch_free(watch);
                return NULL;
        }
        return watch;
}

void watch_free(Watch *watch)
{
        if (!watch)
                return;
        remove_watches(watch);
        ptr_vec_clear(&watch->targets);
        if (watch->inotify_fd >= 0)
                close(watch->inotify_fd);
        if (watch->timer_fd >= 0)
                close(watch->timer_fd);
        free(watch);
}

bool watch_set_paths(Watch *watch, const PtrVec *paths, Error **error)
{
        PtrVec candidate;
        StrMap seen;
        ptr_vec_init(&candidate, free);
        str_map_init(&seen, NULL);
        for (size_t i = 0; i < paths->len; ++i) {
                const char *path = paths->items[i];
                char *canonical;
                if (!path_is_absolute(path) || str_map_contains(&seen, path))
                        continue;
                canonical = path_canonicalize(path, NULL);
                if (!canonical) {
                        ptr_vec_clear(&candidate);
                        str_map_clear(&seen);
                        return error_set(error, ENOMEM, "Cannot allocate file-watch paths");
                }
                if (!ptr_vec_push(&candidate, canonical)) {
                        free(canonical);
                        ptr_vec_clear(&candidate);
                        str_map_clear(&seen);
                        return error_set(error, ENOMEM, "Cannot allocate file-watch paths");
                }
                if (!str_map_set(&seen, path, NULL)) {
                        ptr_vec_clear(&candidate);
                        str_map_clear(&seen);
                        return error_set(error, ENOMEM, "Cannot allocate file-watch paths");
                }
        }
        str_map_clear(&seen);
        PtrVec previous = watch->targets;
        watch->targets = candidate;
        if (!rebuild(watch, error)) {
                ptr_vec_clear(&watch->targets);
                watch->targets = previous;
                rebuild(watch, NULL);
                return false;
        }
        ptr_vec_clear(&previous);
        return true;
}

int watch_inotify_fd(const Watch *watch)
{
        return watch->inotify_fd;
}
int watch_timer_fd(const Watch *watch)
{
        return watch->timer_fd;
}

bool watch_dispatch_inotify(Watch *watch, Error **error)
{
        char buffer[16 * (sizeof(struct inotify_event) + NAME_MAX + 1)];
        bool changed = false;
        for (;;) {
                ssize_t n = read(watch->inotify_fd, buffer, sizeof(buffer));
                if (n > 0) {
                        for (size_t offset = 0; offset < (size_t)n;) {
                                struct inotify_event *event = (struct inotify_event *)(buffer + offset);
                                if (event->mask &
                                    (IN_ATTRIB | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY |
                                     IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO | IN_Q_OVERFLOW | IN_IGNORED))
                                        changed = true;
                                offset += sizeof(*event) + event->len;
                        }
                        continue;
                }
                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                        break;
                return error_set_errno(error, n < 0 ? errno : EIO, "Cannot read file-watch events");
        }
        if (changed) {
                if (!rebuild(watch, error) || !event_timer_arm(watch->timer_fd, 200, false, error))
                        return false;
        }
        return true;
}

bool watch_dispatch_timer(Watch *watch, Error **error)
{
        uint64_t expirations;
        if (!event_counter_consume(watch->timer_fd, &expirations, error))
                return false;
        if (expirations && watch->callback)
                watch->callback(watch->data);
        return true;
}
