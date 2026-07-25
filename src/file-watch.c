#include "file-watch.h"

#include <glib/gstdio.h>

typedef struct {
        FileWatch *owner;
        gchar *target;
        gchar *monitored;
        GFileMonitor *monitor;
} WatchEntry;

struct FileWatch {
        FileWatchFunc callback;
        gpointer data;
        GPtrArray *entries;
        guint debounce_source;
        gboolean replacing;
};

static void watch_entry_free(WatchEntry *entry)
{
        if (!entry)
                return;
        if (entry->monitor)
                g_file_monitor_cancel(entry->monitor);
        g_clear_object(&entry->monitor);
        g_free(entry->target);
        g_free(entry->monitored);
        g_free(entry);
}

static gboolean dispatch_reload(gpointer data)
{
        FileWatch *watch = data;
        watch->debounce_source = 0;
        watch->callback(watch->data);
        return G_SOURCE_REMOVE;
}

static gboolean paths_related(const gchar *target, const gchar *changed)
{
        gsize target_length = strlen(target);
        gsize changed_length = strlen(changed);
        return (g_str_has_prefix(changed, target) &&
                (changed[target_length] == '\0' || changed[target_length] == G_DIR_SEPARATOR)) ||
               (g_str_has_prefix(target, changed) &&
                (target[changed_length] == '\0' || target[changed_length] == G_DIR_SEPARATOR));
}

static void changed(GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event, gpointer data)
{
        WatchEntry *entry = data;
        gchar *path = g_file_get_path(file);
        gchar *other_path = other_file ? g_file_get_path(other_file) : NULL;
        (void)monitor;

        if (!entry->owner->replacing && event != G_FILE_MONITOR_EVENT_ATTRIBUTE_CHANGED &&
            ((path && paths_related(entry->target, path)) ||
             (other_path && paths_related(entry->target, other_path)))) {
                if (entry->owner->debounce_source)
                        g_source_remove(entry->owner->debounce_source);
                entry->owner->debounce_source = g_timeout_add(200, dispatch_reload, entry->owner);
        }
        g_free(path);
        g_free(other_path);
}

static gchar *nearest_existing_path(const gchar *path)
{
        gchar *candidate = g_canonicalize_filename(path, NULL);

        if (g_file_test(candidate, G_FILE_TEST_IS_REGULAR)) {
                gchar *parent = g_path_get_dirname(candidate);
                g_free(candidate);
                return parent;
        }
        while (!g_file_test(candidate, G_FILE_TEST_EXISTS)) {
                gchar *parent = g_path_get_dirname(candidate);
                if (g_str_equal(parent, candidate)) {
                        g_free(parent);
                        break;
                }
                g_free(candidate);
                candidate = parent;
        }
        return candidate;
}

FileWatch *file_watch_new(FileWatchFunc callback, gpointer data)
{
        FileWatch *watch = g_new0(FileWatch, 1);
        watch->callback = callback;
        watch->data = data;
        watch->entries = g_ptr_array_new_with_free_func((GDestroyNotify)watch_entry_free);
        return watch;
}

gboolean file_watch_set_paths(FileWatch *watch, GPtrArray *paths, GError **error)
{
        GPtrArray *candidate = g_ptr_array_new_with_free_func((GDestroyNotify)watch_entry_free);
        GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

        for (guint index = 0; index < paths->len; ++index) {
                const gchar *path = g_ptr_array_index(paths, index);
                WatchEntry *entry;
                GFile *file;
                GError *local_error = NULL;

                if (!path || !g_path_is_absolute(path) || g_hash_table_contains(seen, path))
                        continue;
                g_hash_table_add(seen, g_strdup(path));
                entry = g_new0(WatchEntry, 1);
                entry->owner = watch;
                entry->target = g_canonicalize_filename(path, NULL);
                entry->monitored = nearest_existing_path(entry->target);
                file = g_file_new_for_path(entry->monitored);
                if (g_file_test(entry->monitored, G_FILE_TEST_IS_DIR))
                        entry->monitor = g_file_monitor_directory(file, G_FILE_MONITOR_WATCH_MOVES, NULL,
                                                                  &local_error);
                else
                        entry->monitor = g_file_monitor_file(file, G_FILE_MONITOR_WATCH_MOVES, NULL, &local_error);
                g_object_unref(file);
                if (!entry->monitor) {
                        g_propagate_prefixed_error(error, local_error, "Cannot monitor %s: ", entry->target);
                        watch_entry_free(entry);
                        g_ptr_array_unref(candidate);
                        g_hash_table_unref(seen);
                        return FALSE;
                }
                g_signal_connect(entry->monitor, "changed", G_CALLBACK(changed), entry);
                g_ptr_array_add(candidate, entry);
        }
        g_hash_table_unref(seen);
        watch->replacing = TRUE;
        g_ptr_array_unref(watch->entries);
        watch->entries = candidate;
        watch->replacing = FALSE;
        return TRUE;
}

void file_watch_free(FileWatch *watch)
{
        if (!watch)
                return;
        if (watch->debounce_source)
                g_source_remove(watch->debounce_source);
        watch->replacing = TRUE;
        g_ptr_array_unref(watch->entries);
        g_free(watch);
}
