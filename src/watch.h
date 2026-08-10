#pragma once

#include "util.h"

typedef struct Watch Watch;
typedef void (*WatchFunc)(void *data);

Watch *watch_new(WatchFunc callback, void *data, Error **error);
void watch_free(Watch *watch);
bool watch_set_paths(Watch *watch, const PtrVec *paths, Error **error);
int watch_inotify_fd(const Watch *watch);
int watch_timer_fd(const Watch *watch);
bool watch_dispatch_inotify(Watch *watch, Error **error);
bool watch_dispatch_timer(Watch *watch, Error **error);
