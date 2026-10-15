#define DISKPASS_HOST_BUILD 1
#include "diskpass.h"

#include "diskpass_i18n.c"
#include "diskpass_core.c"
#include "diskpass_crypto_tags.c"

typedef struct {
    GModule *module;
    char *path;
    char *id;
    char *name;
    char *version;
    DiskPassPluginShutdownFunc shutdown;
} DiskPassLoadedPlugin;

typedef struct {
    DiskPassLoadedPlugin *owner;
    char *action_id;
    char *label;
    DiskPassPluginActionCallback callback;
    gpointer user_data;
    GDestroyNotify destroy_notify;
} DiskPassPluginAction;

static GPtrArray *g_loaded_plugins = NULL;
static GPtrArray *g_plugin_actions = NULL;
static DiskPassLoadedPlugin *g_loading_plugin = NULL;
static GtkWindow *g_plugin_parent_window = NULL;

static const char *plugin_host_get_language(void) {
    return g_lang;
}

static gboolean plugin_text_ok(const char *s, gsize max_len) {
    if (!s || !*s || strlen(s) > max_len) return FALSE;
    return g_utf8_validate(s, -1, NULL);
}

static gboolean plugin_action_id_ok(const char *s) {
    if (!s || !*s || strlen(s) > 96) return FALSE;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (!(g_ascii_isalnum(*p) || *p == '_' || *p == '-' || *p == '.')) return FALSE;
    }
    return TRUE;
}

static gboolean plugin_host_register_action(
    const char *action_id,
    const char *label,
    DiskPassPluginActionCallback callback,
    gpointer user_data,
    GDestroyNotify destroy_notify)
{
    if (!g_loading_plugin || !g_plugin_actions || !callback ||
        !plugin_action_id_ok(action_id) || !plugin_text_ok(label, 256))
        return FALSE;

    for (guint i = 0; i < g_plugin_actions->len; i++) {
        DiskPassPluginAction *a = g_ptr_array_index(g_plugin_actions, i);
        if (a && a->owner == g_loading_plugin && strcmp(a->action_id, action_id) == 0)
            return FALSE;
    }

    DiskPassPluginAction *a = g_new0(DiskPassPluginAction, 1);
    if (!a) return FALSE;
    a->owner = g_loading_plugin;
    a->action_id = g_strdup(action_id);
    a->label = g_strdup(label);
    a->callback = callback;
    a->user_data = user_data;
    a->destroy_notify = destroy_notify;
    if (!a->action_id || !a->label) {
        g_free(a->action_id);
        g_free(a->label);
        g_free(a);
        return FALSE;
    }
    g_ptr_array_add(g_plugin_actions, a);
    return TRUE;
}

static void plugin_host_show_message(const char *title, const char *message) {
    if (!plugin_text_ok(title, 256) || !plugin_text_ok(message, 8192)) return;
    if (!g_plugin_parent_window) {
        fprintf(stderr, "DiskPass plugin: %s: %s\n", title, message);
        return;
    }
    GtkWidget *dlg = gtk_message_dialog_new(g_plugin_parent_window,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", message);
    gtk_window_set_title(GTK_WINDOW(dlg), title);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static char *plugin_host_dup_selected_disk_label(void) {
    return diskpass_ui_dup_selected_disk_label();
}

static void plugin_host_set_status(const char *text, guint timeout_ms) {
    if (text && (!g_utf8_validate(text, -1, NULL) || strlen(text) > 1024)) return;
    diskpass_ui_set_plugin_status(text, timeout_ms);
}

static const char *plugin_host_translate(const char *key) {
    return i18n(key);
}

static const DiskPassPluginHost PLUGIN_HOST = {
    .abi_version = DISKPASS_PLUGIN_ABI_VERSION,
    .app_version = "5",
    .get_language = plugin_host_get_language,
    .register_action = plugin_host_register_action,
    .show_message = plugin_host_show_message,
    .dup_selected_disk_label = plugin_host_dup_selected_disk_label,
    .set_status = plugin_host_set_status,
    .translate = plugin_host_translate,
};

static void plugin_action_free(DiskPassPluginAction *a) {
    if (!a) return;
    if (a->destroy_notify) a->destroy_notify(a->user_data);
    g_free(a->action_id);
    g_free(a->label);
    g_free(a);
}

static void loaded_plugin_free(DiskPassLoadedPlugin *p) {
    if (!p) return;
    if (p->module) g_module_close(p->module);
    g_free(p->path);
    g_free(p->id);
    g_free(p->name);
    g_free(p->version);
    g_free(p);
}

static char *diskpass_plugin_directory(void) {
    const char *home = g_get_home_dir();
    if (!home || !home[0]) return NULL;

    char *base = g_build_filename(home, ".diskpass", NULL);
    if (!base) return NULL;
    if (g_mkdir_with_parents(base, 0700) != 0) {
        g_free(base);
        return NULL;
    }
    struct stat st;
    if (g_lstat(base, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
        chmod(base, 0700) != 0) {
        g_free(base);
        return NULL;
    }
    char *dir = g_build_filename(base, "plugins", NULL);
    g_free(base);
    if (!dir) return NULL;
    if (g_mkdir_with_parents(dir, 0700) != 0 || g_lstat(dir, &st) != 0 ||
        !S_ISDIR(st.st_mode) || st.st_uid != getuid() || chmod(dir, 0700) != 0) {
        g_free(dir);
        return NULL;
    }
    return dir;
}

static gboolean plugin_file_is_safe(const char *path) {
    struct stat st;
    if (!path || g_lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) return FALSE;
    if (st.st_uid != getuid()) return FALSE;
    if (st.st_mode & (S_IWGRP | S_IWOTH)) return FALSE;
    if (st.st_size <= 0 || st.st_size > 64 * 1024 * 1024) return FALSE;
    return TRUE;
}

static char *plugin_id_from_path(const char *path) {
    char *base = g_path_get_basename(path);
    if (!base) return NULL;
    char *dot = strrchr(base, '.');
    if (dot && strcmp(dot, ".so") == 0) *dot = '\0';
    for (char *p = base; *p; p++) {
        if (!(g_ascii_isalnum((guchar)*p) || *p == '_' || *p == '-' || *p == '.')) *p = '_';
    }
    return base;
}

static void rollback_plugin_actions(guint start_index) {
    if (!g_plugin_actions) return;
    while (g_plugin_actions->len > start_index) {
        guint idx = g_plugin_actions->len - 1;
        DiskPassPluginAction *a = g_ptr_array_index(g_plugin_actions, idx);
        g_ptr_array_remove_index(g_plugin_actions, idx);
        plugin_action_free(a);
    }
}

static void diskpass_plugin_load_one(const char *path) {
    if (!plugin_file_is_safe(path)) {
        fprintf(stderr, "DiskPass: refusing unsafe plugin file: %s\n", path ? path : "(null)");
        return;
    }

    GModule *module = g_module_open(path, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
    if (!module) {
        fprintf(stderr, "DiskPass: cannot load plugin %s: %s\n", path, g_module_error());
        return;
    }

    gpointer init_symbol = NULL;
    DiskPassPluginInitFunc init_fn = NULL;
    if (!g_module_symbol(module, DISKPASS_PLUGIN_INIT_SYMBOL, &init_symbol) || !init_symbol) {
        fprintf(stderr, "DiskPass: plugin %s has no %s symbol\n", path, DISKPASS_PLUGIN_INIT_SYMBOL);
        g_module_close(module);
        return;
    }
    if (sizeof(init_fn) != sizeof(init_symbol)) {
        fprintf(stderr, "DiskPass: unsupported function-pointer ABI for plugin %s\n", path);
        g_module_close(module);
        return;
    }
    memcpy(&init_fn, &init_symbol, sizeof(init_fn));

    DiskPassLoadedPlugin *p = g_new0(DiskPassLoadedPlugin, 1);
    if (!p) {
        g_module_close(module);
        return;
    }
    p->module = module;
    p->path = g_strdup(path);
    p->id = plugin_id_from_path(path);
    p->name = g_strdup(p->id ? p->id : "plugin");
    p->version = g_strdup("");
    gpointer shutdown_symbol = NULL;
    if (g_module_symbol(module, DISKPASS_PLUGIN_SHUTDOWN_SYMBOL, &shutdown_symbol) && shutdown_symbol &&
        sizeof(p->shutdown) == sizeof(shutdown_symbol))
        memcpy(&p->shutdown, &shutdown_symbol, sizeof(p->shutdown));

    guint action_start = g_plugin_actions ? g_plugin_actions->len : 0;
    DiskPassPluginInfo info = { .abi_version = DISKPASS_PLUGIN_ABI_VERSION };
    GError *error = NULL;
    g_loading_plugin = p;
    gboolean ok = init_fn(&PLUGIN_HOST, &info, &error);
    g_loading_plugin = NULL;

    if (!ok || info.abi_version != DISKPASS_PLUGIN_ABI_VERSION) {
        fprintf(stderr, "DiskPass: plugin %s rejected: %s\n", path,
            error ? error->message : "initialization/ABI failure");
        g_clear_error(&error);
        rollback_plugin_actions(action_start);
        loaded_plugin_free(p);
        return;
    }
    g_clear_error(&error);

    if (info.id && plugin_action_id_ok(info.id)) {
        g_free(p->id); p->id = g_strdup(info.id);
    }
    if (info.name && plugin_text_ok(info.name, 128)) {
        g_free(p->name); p->name = g_strdup(info.name);
    }
    if (info.version && plugin_text_ok(info.version, 64)) {
        g_free(p->version); p->version = g_strdup(info.version);
    }
    g_ptr_array_add(g_loaded_plugins, p);
    fprintf(stderr, "DiskPass: loaded plugin %s%s%s\n",
        p->name ? p->name : p->id,
        (p->version && p->version[0]) ? " " : "",
        (p->version && p->version[0]) ? p->version : "");
}

void diskpass_plugins_init(void) {
    if (!g_loaded_plugins) g_loaded_plugins = g_ptr_array_new();
    if (!g_plugin_actions) g_plugin_actions = g_ptr_array_new();
}

void diskpass_plugins_set_parent(GtkWindow *window) {
    g_plugin_parent_window = window;
}

static gint plugin_path_compare(gconstpointer a, gconstpointer b) {
    const char *const *pa = a;
    const char *const *pb = b;
    return g_strcmp0(pa ? *pa : NULL, pb ? *pb : NULL);
}

void diskpass_plugins_load_all(void) {
    if (!g_loaded_plugins || !g_plugin_actions) diskpass_plugins_init();
    if (!g_module_supported()) {
        fprintf(stderr, "DiskPass: GModule is not supported on this platform\n");
        return;
    }
    if (g_getenv("DISKPASS_DISABLE_PLUGINS")) {
        fprintf(stderr, "DiskPass: plugins disabled by DISKPASS_DISABLE_PLUGINS\n");
        return;
    }

    char *dir = diskpass_plugin_directory();
    if (!dir) return;
    GDir *d = g_dir_open(dir, 0, NULL);
    if (!d) { g_free(dir); return; }

    GPtrArray *paths = g_ptr_array_new_with_free_func(g_free);
    const char *name;
    while ((name = g_dir_read_name(d)) != NULL) {
        if (!g_str_has_suffix(name, ".so")) continue;
        char *path = g_build_filename(dir, name, NULL);
        if (path) g_ptr_array_add(paths, path);
    }
    g_dir_close(d);
    g_free(dir);

    g_ptr_array_sort(paths, plugin_path_compare);
    for (guint i = 0; i < paths->len; i++)
        diskpass_plugin_load_one(g_ptr_array_index(paths, i));
    g_ptr_array_free(paths, TRUE);
}

static void on_open_plugin_directory(GtkMenuItem *item, gpointer user_data) {
    (void)item; (void)user_data;
    char *dir = diskpass_plugin_directory();
    if (!dir) return;
    GError *error = NULL;
    char *uri = g_filename_to_uri(dir, NULL, &error);
    if (!uri || !gtk_show_uri_on_window(g_plugin_parent_window, uri, GDK_CURRENT_TIME, &error)) {
        fprintf(stderr, "DiskPass: cannot open plugin directory: %s\n",
            error ? error->message : "unknown error");
    }
    g_clear_error(&error);
    g_free(uri);
    g_free(dir);
}

static void on_plugin_action_activate(GtkMenuItem *item, gpointer user_data) {
    (void)item;
    DiskPassPluginAction *a = user_data;
    if (a && a->callback) a->callback(a->user_data);
}

GtkWidget *diskpass_plugins_create_button(void) {
    GtkWidget *button = gtk_menu_button_new();
    GtkWidget *img = gtk_image_new_from_icon_name("application-x-addon-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_button_set_image(GTK_BUTTON(button), img);
    gtk_widget_set_tooltip_text(button, i18n("plugins"));

    GtkWidget *menu = gtk_menu_new();
    GtkWidget *folder_item = gtk_menu_item_new_with_label(i18n("plugins_open_folder"));
    g_signal_connect(folder_item, "activate", G_CALLBACK(on_open_plugin_directory), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), folder_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());

    if (!g_plugin_actions || g_plugin_actions->len == 0) {
        GtkWidget *item = gtk_menu_item_new_with_label(i18n("plugins_none_active"));
        gtk_widget_set_sensitive(item, FALSE);
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    } else {
        for (guint i = 0; i < g_plugin_actions->len; i++) {
            DiskPassPluginAction *a = g_ptr_array_index(g_plugin_actions, i);
            const char *owner = (a && a->owner && a->owner->name) ? a->owner->name : "Plugin";
            char *label = g_strdup_printf("%s — %s", owner, a && a->label ? a->label : "?");
            GtkWidget *item = gtk_menu_item_new_with_label(label ? label : "Plugin action");
            g_free(label);
            g_signal_connect(item, "activate", G_CALLBACK(on_plugin_action_activate), a);
            gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
        }
    }
    gtk_widget_show_all(menu);
    gtk_menu_button_set_popup(GTK_MENU_BUTTON(button), menu);
    return button;
}

void diskpass_plugins_shutdown(void) {
    g_plugin_parent_window = NULL;

    if (g_plugin_actions) {
        while (g_plugin_actions->len > 0) {
            guint idx = g_plugin_actions->len - 1;
            DiskPassPluginAction *a = g_ptr_array_index(g_plugin_actions, idx);
            g_ptr_array_remove_index(g_plugin_actions, idx);
            plugin_action_free(a);
        }
        g_ptr_array_free(g_plugin_actions, TRUE);
        g_plugin_actions = NULL;
    }

    if (g_loaded_plugins) {
        for (guint i = g_loaded_plugins->len; i > 0; i--) {
            DiskPassLoadedPlugin *p = g_ptr_array_index(g_loaded_plugins, i - 1);
            if (p && p->shutdown) p->shutdown();
        }
        while (g_loaded_plugins->len > 0) {
            guint idx = g_loaded_plugins->len - 1;
            DiskPassLoadedPlugin *p = g_ptr_array_index(g_loaded_plugins, idx);
            g_ptr_array_remove_index(g_loaded_plugins, idx);
            loaded_plugin_free(p);
        }
        g_ptr_array_free(g_loaded_plugins, TRUE);
        g_loaded_plugins = NULL;
    }
    g_loading_plugin = NULL;
}

#include "diskpass_ui.c"

int main(int argc, char **argv) {
    struct rlimit no_core = { 0, 0 };
    (void)setrlimit(RLIMIT_CORE, &no_core);
#ifdef __linux__
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    umask(0077);
    setlocale(LC_ALL, "");
    if (!g_get_charset(NULL)) {
        g_setenv("LANG", "C.UTF-8", TRUE);
        g_setenv("LC_ALL", "C.UTF-8", TRUE);
    }
    if (sodium_init() < 0) { fprintf(stderr, "FATAL: libsodium init failed\n"); return 1; }
    if (!gpgme_check_version("1.24.1")) { fprintf(stderr, "FATAL: GPGME >= 1.24.1 with Kyber support required\n"); return 1; }
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
    g_unix_signal_add(SIGINT, graceful_shutdown, NULL);
    g_unix_signal_add(SIGTERM, graceful_shutdown, NULL);
    gtk_init(&argc, &argv);
    i18n_init();
    diskpass_plugins_init();
    load_config();
    load_css();
    memset(&g_app, 0, sizeof(g_app));
    g_app.current_entry_idx = -1;
    g_app.toast_entry_idx = -1;
    char *icon_path = find_icon_path();
    if (icon_path) {
        icon_pb = gdk_pixbuf_new_from_file_at_size(icon_path, 256, 256, NULL);
        g_free(icon_path);
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "DiskPass");
    gtk_window_set_default_size(GTK_WINDOW(win), 1000, 660);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    if (icon_pb) gtk_window_set_icon(GTK_WINDOW(win), icon_pb);

    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), FALSE);
    gtk_header_bar_set_has_subtitle(GTK_HEADER_BAR(hb), FALSE);

    GtkWidget *title_lbl = gtk_label_new("DiskPass");
    gtk_widget_set_size_request(title_lbl, 160, -1);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "title");
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), title_lbl);

    GtkWidget *hb_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

    GtkWidget *btn_min = gtk_button_new_with_label("–");
    gtk_widget_set_tooltip_text(btn_min, i18n("minimize"));
    g_signal_connect(btn_min, "clicked", G_CALLBACK(on_minimize_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(hb_box), btn_min, FALSE, FALSE, 0);

    GtkWidget *btn_max = gtk_button_new_with_label("□");
    gtk_widget_set_tooltip_text(btn_max, i18n("maximize"));
    g_signal_connect(btn_max, "clicked", G_CALLBACK(on_maximize_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(hb_box), btn_max, FALSE, FALSE, 0);

    GtkWidget *btn_close = gtk_button_new_with_label("×");
    gtk_widget_set_tooltip_text(btn_close, i18n("close_window"));
    g_signal_connect(btn_close, "clicked", G_CALLBACK(on_close_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(hb_box), btn_close, FALSE, FALSE, 0);

    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), hb_box);
    gtk_window_set_titlebar(GTK_WINDOW(win), hb);

    g_signal_connect(win, "window-state-event",
        G_CALLBACK(on_window_state_changed), btn_max);

    g_app.window = GTK_WINDOW(win);
    diskpass_plugins_set_parent(g_app.window);
    diskpass_plugins_load_all();
    g_app.stack = GTK_STACK(gtk_stack_new());
    gtk_stack_set_transition_type(g_app.stack, GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_container_add(GTK_CONTAINER(win), GTK_WIDGET(g_app.stack));
    build_welcome();
    build_setup();
    build_unlock();
    build_main();
    setup_accelerators(win);
    setup_system_lock_monitor();
    gtk_stack_set_visible_child_name(g_app.stack, "welcome");
    gtk_widget_add_events(win,
        GDK_KEY_PRESS_MASK | GDK_POINTER_MOTION_MASK |
        GDK_BUTTON_PRESS_MASK | GDK_SCROLL_MASK);
    g_signal_connect(win, "key-press-event", G_CALLBACK(on_user_activity), NULL);
    g_signal_connect(win, "motion-notify-event", G_CALLBACK(on_user_activity), NULL);
    g_signal_connect(win, "button-press-event", G_CALLBACK(on_user_activity), NULL);
    g_signal_connect(win, "scroll-event", G_CALLBACK(on_user_activity), NULL);
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_widget_show_all(win);
    set_tree_visible(FALSE);
    set_notes_visible(FALSE);
    gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);
    g_app.connection_timer_id = g_timeout_add_seconds(5, connection_check_cb, NULL);
    gtk_main();
    cleanup_system_lock_monitor();
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    if (g_app.autolock_timer_id) g_source_remove(g_app.autolock_timer_id);
    if (g_app.connection_timer_id) g_source_remove(g_app.connection_timer_id);
    if (g_toast_timer_id) g_source_remove(g_toast_timer_id);
    if (g_plugin_status_timer_id) g_source_remove(g_plugin_status_timer_id);
    if (g_known_uuids) g_hash_table_destroy(g_known_uuids);
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
    free(g_app.current_file);
    free(g_app.expected_fp);
    free(g_tree_filter_needle);
    g_tree_filter_needle = NULL;
    if (g_app.tree_store) g_object_unref(g_app.tree_store);
    if (icon_pb) g_object_unref(icon_pb);
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    diskpass_plugins_shutdown();
    i18n_shutdown();
    return 0;
}
