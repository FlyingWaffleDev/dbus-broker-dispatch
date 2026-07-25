#pragma once

#include <gio/gio.h>

typedef struct FileWatch FileWatch;
typedef void (*FileWatchFunc)(gpointer data);

FileWatch *file_watch_new(FileWatchFunc callback, gpointer data);
gboolean file_watch_set_paths(FileWatch *watch, GPtrArray *paths, GError **error);
void file_watch_free(FileWatch *watch);
