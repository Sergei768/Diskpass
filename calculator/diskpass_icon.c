/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Expose lstat() under strict -std=c11 before including GTK/GLib headers. */
#define _POSIX_C_SOURCE 200809L
#include "diskpass_icon.h"
#include <glib/gstdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#define DESKTOP_GROUP "Desktop Entry"
#define ORIGINAL_ICON_KEY "X-App-OriginalIcon"
#define ORIGINAL_NO_DISPLAY_KEY "X-App-OriginalNoDisplay"
#define GENERATED_OVERRIDE_KEY "X-App-GeneratedIconOverride"
#define LEGACY_ORIGINAL_ICON_KEY "X-DiskPass-OriginalIcon"
#define LEGACY_ORIGINAL_NO_DISPLAY_KEY "X-DiskPass-OriginalNoDisplay"
#define LEGACY_GENERATED_OVERRIDE_KEY "X-DiskPass-GeneratedIconOverride"

const char *diskpass_calculator_icon_name(void)
{
    /* First try the modern GNOME Calculator application icon. All lookups
     * are done against the current user's icon theme (including inheritance).
     * Older desktops often only ship the freedesktop icon name. */
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
    return "accessories-calculator";
}

/* We only touch a launcher with the standard diskpass.desktop ID. A package
 * launcher in /usr/share is copied to the XDG user application directory;
 * there is no need for root permissions. */
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

/* Preserve user customizations: only a generated override that still matches
 * its system counterpart (apart from our icon metadata) is removed. */
static gboolean unchanged_from_system(GKeyFile *local)
{
    GKeyFile *system = load_system_launcher();
    if (!system) return FALSE;
    g_key_file_remove_key(local, DESKTOP_GROUP, ORIGINAL_ICON_KEY, NULL);
    g_key_file_remove_key(local, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL);
    g_key_file_remove_key(local, DESKTOP_GROUP, GENERATED_OVERRIDE_KEY, NULL);
    gsize local_len = 0, system_len = 0;
    char *local_data = g_key_file_to_data(local, &local_len, NULL);
    char *system_data = g_key_file_to_data(system, &system_len, NULL);
    gboolean same = local_data && system_data &&
                    local_len == system_len &&
                    memcmp(local_data, system_data, local_len) == 0;
    g_free(local_data);
    g_free(system_data);
    g_key_file_free(system);
    return same;
}

gboolean diskpass_sync_launcher_icon(gboolean calculator_mode)
{
    char *dir = g_build_filename(g_get_user_data_dir(), "applications", NULL);
    char *path = g_build_filename(dir, "diskpass.desktop", NULL);
    gboolean exists = g_file_test(path, G_FILE_TEST_EXISTS) ||
                      g_file_test(path, G_FILE_TEST_IS_SYMLINK);
    GKeyFile *kf = NULL;
    gboolean from_system = FALSE;
    gboolean ok = TRUE;

    if (exists) {
        struct stat st;
        /* Don't rewrite symlinks or other users' files. */
        if (g_lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_uid != geteuid()) {
            ok = FALSE;
            goto done;
        }
        kf = g_key_file_new();
        if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_KEEP_COMMENTS |
                                       G_KEY_FILE_KEEP_TRANSLATIONS, NULL)) {
            ok = FALSE;
            goto done;
        }
    } else if (calculator_mode) {
        kf = load_system_launcher();
        if (!kf) goto done; /* No installed launcher; window icon still works. */
        from_system = TRUE;
    } else {
        goto done;
    }
    if (!launcher_is_valid(kf)) { ok = FALSE; goto done; }

    if (calculator_mode) {
        /* Migrate older generated metadata without discarding saved values. */
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
        if (!g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_ICON_KEY, NULL)) {
            char *old = g_key_file_get_string(kf, DESKTOP_GROUP, "Icon", NULL);
            g_key_file_set_string(kf, DESKTOP_GROUP, ORIGINAL_ICON_KEY,
                                  old && *old ? old : "diskpass");
            g_free(old);
        }
        if (!g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL)) {
            /* Keep the original launcher visibility exactly, including a
             * missing NoDisplay entry; do not override user preferences
             * permanently. This affects only the application launcher, not
             * the executable, the installed package or the filesystem. */
            char *previous = g_key_file_get_value(kf, DESKTOP_GROUP, "NoDisplay", NULL);
            g_key_file_set_string(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY,
                                  previous ? previous : "__absent__");
            g_free(previous);
        }
        if (from_system)
            g_key_file_set_boolean(kf, DESKTOP_GROUP, GENERATED_OVERRIDE_KEY, TRUE);
        g_key_file_set_string(kf, DESKTOP_GROUP, "Icon",
                              diskpass_calculator_icon_name());
        g_key_file_set_boolean(kf, DESKTOP_GROUP, "NoDisplay", TRUE);
    } else {
        /* Accept metadata created by older releases so restoration still works. */
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
        gboolean our_visibility = g_key_file_has_key(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL);
        if (!our_icon && !our_visibility)
            goto done; /* The launcher was not managed by this feature. */
        gboolean generated = g_key_file_get_boolean(kf, DESKTOP_GROUP,
                                                   GENERATED_OVERRIDE_KEY, NULL);
        if (our_icon) {
            char *original = g_key_file_get_string(kf, DESKTOP_GROUP,
                                                   ORIGINAL_ICON_KEY, NULL);
            g_key_file_set_string(kf, DESKTOP_GROUP, "Icon",
                                  original && *original ? original : "diskpass");
            g_free(original);
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
        if (generated && unchanged_from_system(kf)) {
            if (g_unlink(path) != 0) ok = FALSE;
            goto done;
        }
        g_key_file_remove_key(kf, DESKTOP_GROUP, ORIGINAL_ICON_KEY, NULL);
        g_key_file_remove_key(kf, DESKTOP_GROUP, ORIGINAL_NO_DISPLAY_KEY, NULL);
        g_key_file_remove_key(kf, DESKTOP_GROUP, GENERATED_OVERRIDE_KEY, NULL);
    }

    if (g_mkdir_with_parents(dir, 0755) != 0) { ok = FALSE; goto done; }
    gsize len = 0;
    char *contents = g_key_file_to_data(kf, &len, NULL);
    ok = contents && g_file_set_contents(path, contents, (gssize)len, NULL);
    g_free(contents);
    if (ok) (void)g_chmod(path, 0644);

done:
    if (kf) g_key_file_free(kf);
    g_free(path);
    g_free(dir);
    return ok;
}
