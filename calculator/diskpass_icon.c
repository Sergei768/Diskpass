/* SPDX-License-Identifier: GPL-3.0-or-later */
 
#define _POSIX_C_SOURCE 200809L
#include "diskpass_icon.h"
#include <glib/gstdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#ifdef GDK_WINDOWING_WAYLAND
#include <gdk/gdkwayland.h>
#endif

#define DESKTOP_GROUP "Desktop Entry"
#define ORIGINAL_ICON_KEY "X-App-OriginalIcon"
#define ORIGINAL_NAME_KEY "X-App-OriginalName"
#define ORIGINAL_LABELS_GROUP "X-App-OriginalLabels"
#define ORIGINAL_WMCLASS_KEY "X-App-OriginalWMClass"
#define ORIGINAL_NO_DISPLAY_KEY "X-App-OriginalNoDisplay"
#define GENERATED_OVERRIDE_KEY "X-App-GeneratedIconOverride"
#define LEGACY_ORIGINAL_ICON_KEY "X-DiskPass-OriginalIcon"
#define LEGACY_ORIGINAL_NO_DISPLAY_KEY "X-DiskPass-OriginalNoDisplay"
#define LEGACY_GENERATED_OVERRIDE_KEY "X-DiskPass-GeneratedIconOverride"

const char *diskpass_calculator_icon_name(void)
{
     


    static const char *const candidates[] = {
        "org.gnome.Calculator", "gnome-calculator", "accessories-calculator",
        "calculator", "accessories-calculator-symbolic", NULL
    };
    GtkIconTheme *theme = gtk_icon_theme_get_default();
    if (theme) {
        for (guint i = 0; candidates[i]; i++) {
            if (gtk_icon_theme_has_icon(theme, candidates[i]))
                return candidates[i];
        }
    }
     
    static char *fallback_path;
    if (!fallback_path) {
        static const char svg[] =
            "<svg xmlns='http://www.w3.org/2000/svg' width='256' height='256' viewBox='0 0 256 256'>"
            "<rect x='36' y='12' width='184' height='232' rx='24' fill='#454b55'/>"
            "<rect x='54' y='32' width='148' height='52' rx='8' fill='#c9e5cf'/>"
            "<g fill='#e6e9ed'><path d='M56 104h32v28H56z M112 104h32v28h-32z M168 104h32v28h-32z "
            "M56 150h32v28H56z M112 150h32v28h-32z M168 150h32v28h-32z "
            "M56 196h32v28H56z M112 196h32v28h-32z'/></g>"
            "<path d='M168 196h32v28h-32z' fill='#ed954b'/></svg>";
        char *dir = g_build_filename(g_get_user_data_dir(), "icons", NULL);
        char *path = g_build_filename(dir, "diskpass-calculator.svg", NULL);
        if (g_mkdir_with_parents(dir, 0755) == 0 &&
            g_file_set_contents(path, svg, sizeof(svg) - 1, NULL))
            fallback_path = path;
        else
            g_free(path);
        g_free(dir);
    }
    return fallback_path ? fallback_path : "accessories-calculator";
}

void diskpass_set_default_icon(gboolean calculator_mode)
{
    const char *icon = calculator_mode ? diskpass_calculator_icon_name() : "diskpass";
    if (g_path_is_absolute(icon)) {
        GdkPixbuf *pb = gdk_pixbuf_new_from_file_at_size(icon, 256, 256, NULL);
        if (pb) { gtk_window_set_default_icon(pb); g_object_unref(pb); }
    } else {
        gtk_window_set_default_icon_name(icon);
    }
}

void diskpass_set_window_icon(GtkWindow *window, gboolean calculator_mode)
{
    const char *icon = calculator_mode ? diskpass_calculator_icon_name() : "diskpass";
    if (g_path_is_absolute(icon)) {
        GdkPixbuf *pb = gdk_pixbuf_new_from_file_at_size(icon, 256, 256, NULL);
        if (pb) { gtk_window_set_icon(window, pb); g_object_unref(pb); }
    } else {
         
        gtk_window_set_icon(window, NULL);
        gtk_window_set_icon_name(window, icon);
    }
}

static void diskpass_window_realized(GtkWidget *widget, gpointer data)
{
    (void)data;
#ifdef GDK_WINDOWING_WAYLAND
#if GTK_CHECK_VERSION(3, 24, 0)
    GdkWindow *window = gtk_widget_get_window(widget);
    if (GDK_IS_WAYLAND_WINDOW(window))
        gdk_wayland_window_set_application_id(window, "diskpass");
#endif
#endif
    (void)widget;
}

void diskpass_bind_window_launcher(GtkWindow *window)
{
     

    G_GNUC_BEGIN_IGNORE_DEPRECATIONS
    gtk_window_set_wmclass(window, "diskpass", "DiskPass");
    G_GNUC_END_IGNORE_DEPRECATIONS
    g_signal_connect(window, "realize", G_CALLBACK(diskpass_window_realized), NULL);
}

static gboolean launcher_label_key(const char *key)
{
    return g_str_equal(key, "Name") || g_str_has_prefix(key, "Name[") ||
           g_str_equal(key, "GenericName") || g_str_has_prefix(key, "GenericName[") ||
           g_str_equal(key, "Comment") || g_str_has_prefix(key, "Comment[");
}

static void launcher_labels(GKeyFile *kf, gboolean calculator_mode)
{
    if (calculator_mode && !g_key_file_has_group(kf, ORIGINAL_LABELS_GROUP)) {
        gsize count = 0;
        char **keys = g_key_file_get_keys(kf, DESKTOP_GROUP, &count, NULL);
        for (gsize i = 0; i < count; i++) {
            if (!launcher_label_key(keys[i])) continue;
            char *value = g_key_file_get_value(kf, DESKTOP_GROUP, keys[i], NULL);
            g_key_file_set_value(kf, ORIGINAL_LABELS_GROUP, keys[i], value);
            g_free(value);
        }
        g_strfreev(keys);
         
        char *old = g_key_file_get_string(kf, DESKTOP_GROUP, ORIGINAL_NAME_KEY, NULL);
        if (old) {
            g_key_file_set_value(kf, ORIGINAL_LABELS_GROUP, "Name", old);
            g_free(old);
        }
    }
    if (!g_key_file_has_group(kf, ORIGINAL_LABELS_GROUP)) return;
    gsize count = 0;
    char **keys = g_key_file_get_keys(kf, DESKTOP_GROUP, &count, NULL);
    for (gsize i = 0; i < count; i++)
        if (launcher_label_key(keys[i]))
            g_key_file_remove_key(kf, DESKTOP_GROUP, keys[i], NULL);
    g_strfreev(keys);
    if (calculator_mode) {
        g_key_file_set_string(kf, DESKTOP_GROUP, "Name", "Calculator");
        g_key_file_set_locale_string(kf, DESKTOP_GROUP, "Name", "ru", "Калькулятор");
    } else {
        keys = g_key_file_get_keys(kf, ORIGINAL_LABELS_GROUP, &count, NULL);
        for (gsize i = 0; i < count; i++) {
            if (!launcher_label_key(keys[i])) continue;
            char *value = g_key_file_get_value(kf, ORIGINAL_LABELS_GROUP, keys[i], NULL);
            g_key_file_set_value(kf, DESKTOP_GROUP, keys[i], value);
            g_free(value);
        }
        g_strfreev(keys);
        g_key_file_remove_group(kf, ORIGINAL_LABELS_GROUP, NULL);
    }
}

 


static GKeyFile *load_system_launcher(void)
{
    const gchar *const *system_dirs = g_get_system_data_dirs();
    for (guint i = 0; system_dirs && system_dirs[i]; i++) {
        char *path = g_build_filename(system_dirs[i], "applications",
                                      "diskpass.desktop", NULL);
        GKeyFile *kf = g_key_file_new();
        gboolean ok = g_key_file_load_from_file(kf, path,
                G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS, NULL);
        g_free(path);
        if (ok) return kf;
        g_key_file_free(kf);
    }
    return NULL;
}

static gboolean launcher_is_valid(GKeyFile *kf)
{
    gchar *type = g_key_file_get_string(kf, DESKTOP_GROUP, "Type", NULL);
    gboolean ok = g_strcmp0(type, "Application") == 0 &&
                  g_key_file_has_key(kf, DESKTOP_GROUP, "Exec", NULL);
    g_free(type);
    return ok;
}

 

static gboolean unchanged_from_system(GKeyFile *local)
{
    GKeyFile *system = load_system_launcher();
    if (!system) return FALSE;
    g_key_file_remove_key(local, DESKTOP_GROUP, ORIGINAL_WMCLASS_KEY, NULL);
    g_key_file_remove_key(local, DESKTOP_GROUP, ORIGINAL_NAME_KEY, NULL);
    g_key_file_remove_key(local, DESKTOP_GROUP, ORIGINAL_ICON_KEY, NULL);
    g_key_file_remove_key(local, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL);
    g_key_file_remove_key(local, DESKTOP_GROUP, GENERATED_OVERRIDE_KEY, NULL);
     


    gsize local_groups = 0, system_groups = 0;
    char **groups = g_key_file_get_groups(local, &local_groups);
    char **other_groups = g_key_file_get_groups(system, &system_groups);
    gboolean same = local_groups == system_groups;
    for (gsize i = 0; same && i < local_groups; i++) {
        gsize count = 0, other_count = 0;
        char **keys = g_key_file_get_keys(local, groups[i], &count, NULL);
        char **other_keys = g_key_file_get_keys(system, groups[i], &other_count, NULL);
        same = count == other_count;
        for (gsize j = 0; same && j < count; j++) {
            char *value = g_key_file_get_value(local, groups[i], keys[j], NULL);
            char *other = g_key_file_get_value(system, groups[i], keys[j], NULL);
            same = g_strcmp0(value, other) == 0;
            g_free(value);
            g_free(other);
        }
        g_strfreev(keys);
        g_strfreev(other_keys);
    }
    g_strfreev(groups);
    g_strfreev(other_groups);
    g_key_file_free(system);
    return same;
}

static gboolean sync_launcher_path(const char *path, gboolean calculator_mode,
                                   gboolean allow_system_copy)
{
    char *dir = g_path_get_dirname(path);
    gboolean exists = g_file_test(path, G_FILE_TEST_EXISTS) ||
                      g_file_test(path, G_FILE_TEST_IS_SYMLINK);
    GKeyFile *kf = NULL;
    gboolean from_system = FALSE;
    gboolean ok = TRUE;
    mode_t file_mode = 0644;

    if (exists) {
        struct stat st;
         
        if (g_lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_uid != geteuid()) {
            ok = FALSE;
            goto done;
        }
        file_mode = st.st_mode & 0777;
        kf = g_key_file_new();
        if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_KEEP_COMMENTS |
                                       G_KEY_FILE_KEEP_TRANSLATIONS, NULL)) {
            ok = FALSE;
            goto done;
        }
    } else if (calculator_mode && allow_system_copy) {
        kf = load_system_launcher();
        if (!kf) goto done;  
        from_system = TRUE;
    } else {
        goto done;
    }
    if (!launcher_is_valid(kf)) { ok = FALSE; goto done; }

    if (calculator_mode) {
         
        const char *legacy_keys[][2] = {
            { LEGACY_ORIGINAL_ICON_KEY, ORIGINAL_ICON_KEY },
            { LEGACY_ORIGINAL_NO_DISPLAY_KEY, ORIGINAL_NO_DISPLAY_KEY },
            { LEGACY_GENERATED_OVERRIDE_KEY, GENERATED_OVERRIDE_KEY }
        };
        for (guint i = 0; i < G_N_ELEMENTS(legacy_keys); i++) {
            if (g_key_file_has_key(kf, DESKTOP_GROUP, legacy_keys[i][0], NULL) &&
                !g_key_file_has_key(kf, DESKTOP_GROUP, legacy_keys[i][1], NULL)) {
                char *v = g_key_file_get_value(kf, DESKTOP_GROUP, legacy_keys[i][0], NULL);
                if (v) g_key_file_set_value(kf, DESKTOP_GROUP, legacy_keys[i][1], v);
                g_free(v);
            }
            g_key_file_remove_key(kf, DESKTOP_GROUP, legacy_keys[i][0], NULL);
        }
        launcher_labels(kf, TRUE);
        if (!g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_WMCLASS_KEY, NULL)) {
            char *previous = g_key_file_get_value(kf, DESKTOP_GROUP, "StartupWMClass", NULL);
            g_key_file_set_string(kf, DESKTOP_GROUP, ORIGINAL_WMCLASS_KEY,
                                  previous ? previous : "__absent__");
            g_free(previous);
        }
        g_key_file_set_string(kf, DESKTOP_GROUP, "StartupWMClass", "DiskPass");
        if (!g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_ICON_KEY, NULL)) {
            char *old = g_key_file_get_string(kf, DESKTOP_GROUP, "Icon", NULL);
            g_key_file_set_string(kf, DESKTOP_GROUP, ORIGINAL_ICON_KEY,
                                  old && *old ? old : "diskpass");
            g_free(old);
        }
        if (!g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL)) {
             



            char *previous = g_key_file_get_value(kf, DESKTOP_GROUP, "NoDisplay", NULL);
            g_key_file_set_string(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY,
                                  previous ? previous : "__absent__");
            g_free(previous);
        }
        if (from_system)
            g_key_file_set_boolean(kf, DESKTOP_GROUP, GENERATED_OVERRIDE_KEY, TRUE);
        g_key_file_set_string(kf, DESKTOP_GROUP, "Icon",
                              diskpass_calculator_icon_name());
        if (g_getenv("DISKPASS_HIDE_LAUNCHER") != NULL) {
             



            g_key_file_set_boolean(kf, DESKTOP_GROUP, "NoDisplay", TRUE);
        } else {
             

            char *orig = g_key_file_get_string(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL);
            if (!orig || g_strcmp0(orig, "__absent__") == 0)
                g_key_file_remove_key(kf, DESKTOP_GROUP, "NoDisplay", NULL);
            else
                g_key_file_set_value(kf, DESKTOP_GROUP, "NoDisplay", orig);
            g_free(orig);
        }
    } else {
         
        if (g_key_file_has_key(kf, DESKTOP_GROUP, LEGACY_ORIGINAL_ICON_KEY, NULL) &&
            !g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_ICON_KEY, NULL)) {
            char *v = g_key_file_get_value(kf, DESKTOP_GROUP, LEGACY_ORIGINAL_ICON_KEY, NULL);
            if (v) g_key_file_set_value(kf, DESKTOP_GROUP, ORIGINAL_ICON_KEY, v);
            g_free(v);
        }
        if (g_key_file_has_key(kf, DESKTOP_GROUP, LEGACY_ORIGINAL_NO_DISPLAY_KEY, NULL) &&
            !g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL)) {
            char *v = g_key_file_get_value(kf, DESKTOP_GROUP, LEGACY_ORIGINAL_NO_DISPLAY_KEY, NULL);
            if (v) g_key_file_set_value(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, v);
            g_free(v);
        }
        if (g_key_file_has_key(kf, DESKTOP_GROUP, LEGACY_GENERATED_OVERRIDE_KEY, NULL) &&
            !g_key_file_has_key(kf, DESKTOP_GROUP, GENERATED_OVERRIDE_KEY, NULL)) {
            char *v = g_key_file_get_value(kf, DESKTOP_GROUP, LEGACY_GENERATED_OVERRIDE_KEY, NULL);
            if (v) g_key_file_set_value(kf, DESKTOP_GROUP, GENERATED_OVERRIDE_KEY, v);
            g_free(v);
        }
        g_key_file_remove_key(kf, DESKTOP_GROUP, LEGACY_ORIGINAL_ICON_KEY, NULL);
        g_key_file_remove_key(kf, DESKTOP_GROUP, LEGACY_ORIGINAL_NO_DISPLAY_KEY, NULL);
        g_key_file_remove_key(kf, DESKTOP_GROUP, LEGACY_GENERATED_OVERRIDE_KEY, NULL);
        gboolean our_icon = g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_ICON_KEY, NULL);
        gboolean our_name = g_key_file_has_group(kf, ORIGINAL_LABELS_GROUP) ||
                            g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_NAME_KEY, NULL);
        gboolean our_class = g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_WMCLASS_KEY, NULL);
        gboolean our_visibility = g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL);
        if (!our_icon && !our_name && !our_class && !our_visibility)
            goto done;  
        gboolean generated = g_key_file_get_boolean(kf, DESKTOP_GROUP,
                                                   GENERATED_OVERRIDE_KEY, NULL);
        if (g_key_file_has_group(kf, ORIGINAL_LABELS_GROUP)) {
            launcher_labels(kf, FALSE);
        } else if (our_name) {
            char *original_name = g_key_file_get_string(kf, DESKTOP_GROUP,
                                                       ORIGINAL_NAME_KEY, NULL);
            g_key_file_set_string(kf, DESKTOP_GROUP, "Name",
                                  original_name ? original_name : "DiskPass");
            g_free(original_name);
        }
        if (our_icon) {
            char *original = g_key_file_get_string(kf, DESKTOP_GROUP,
                                                   ORIGINAL_ICON_KEY, NULL);
            g_key_file_set_string(kf, DESKTOP_GROUP, "Icon",
                                  original && *original ? original : "diskpass");
            g_free(original);
        }
        if (our_class) {
            char *previous = g_key_file_get_string(kf, DESKTOP_GROUP, ORIGINAL_WMCLASS_KEY, NULL);
            if (g_strcmp0(previous, "__absent__") == 0)
                g_key_file_remove_key(kf, DESKTOP_GROUP, "StartupWMClass", NULL);
            else if (previous)
                g_key_file_set_value(kf, DESKTOP_GROUP, "StartupWMClass", previous);
            g_free(previous);
        }
        if (our_visibility) {
            char *previous = g_key_file_get_string(kf, DESKTOP_GROUP,
                                                    ORIGINAL_NO_DISPLAY_KEY, NULL);
            if (g_strcmp0(previous, "__absent__") == 0)
                g_key_file_remove_key(kf, DESKTOP_GROUP, "NoDisplay", NULL);
            else if (previous)
                g_key_file_set_value(kf, DESKTOP_GROUP, "NoDisplay", previous);
            g_free(previous);
        }
        if (generated && allow_system_copy && unchanged_from_system(kf)) {
            if (g_unlink(path) != 0) ok = FALSE;
            goto done;
        }
        g_key_file_remove_key(kf, DESKTOP_GROUP, ORIGINAL_ICON_KEY, NULL);
        g_key_file_remove_key(kf, DESKTOP_GROUP, ORIGINAL_NAME_KEY, NULL);
        g_key_file_remove_key(kf, DESKTOP_GROUP, ORIGINAL_WMCLASS_KEY, NULL);
        g_key_file_remove_key(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL);
        g_key_file_remove_key(kf, DESKTOP_GROUP, GENERATED_OVERRIDE_KEY, NULL);
    }

    if (g_mkdir_with_parents(dir, 0755) != 0) { ok = FALSE; goto done; }
    gsize len = 0;
    char *contents = g_key_file_to_data(kf, &len, NULL);
    ok = contents && g_file_set_contents(path, contents, (gssize)len, NULL);
    g_free(contents);
    if (ok) (void)g_chmod(path, file_mode);

done:
    if (kf) g_key_file_free(kf);
    g_free(dir);
    return ok;
}

gboolean diskpass_sync_launcher_icon(gboolean calculator_mode)
{
    char *path = g_build_filename(g_get_user_data_dir(), "applications", "diskpass.desktop", NULL);
    gboolean ok = sync_launcher_path(path, calculator_mode, TRUE);
    g_free(path);
     

    const char *desktop = g_get_user_special_dir(G_USER_DIRECTORY_DESKTOP);
    if (desktop) {
        const char *names[] = { "diskpass.desktop", "DiskPass.desktop" };
        for (guint i = 0; i < G_N_ELEMENTS(names); i++) {
            path = g_build_filename(desktop, names[i], NULL);
            if (!sync_launcher_path(path, calculator_mode, FALSE)) ok = FALSE;
            g_free(path);
        }
    }
    return ok;
}
