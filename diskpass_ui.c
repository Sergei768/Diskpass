#include "diskpass.h"

typedef struct {
    GtkWindow *window;
    GtkStack *stack;
    GtkWidget *welcome_title, *welcome_desc, *lbl_lang_welcome;
    GtkWidget *btn_open, *btn_create, *lang_combo_welcome;
    GtkWidget *setup_title, *lbl_setup_file, *lbl_setup_key, *lbl_setup_lang;
    GtkWidget *setup_file_label, *key_combo, *lang_combo, *setup_err;
    GtkWidget *btn_setup_back, *btn_setup_create;
    GtkWidget *unlock_title, *lbl_unlock_file, *lbl_unlock_key;
    GtkWidget *unlock_file_label, *unlock_key_combo, *unlock_err;
    GtkWidget *btn_unlock_back, *btn_unlock;
    GtkWidget *search;
    GtkListBox *listbox;
    GtkWidget *detail_box, *lbl_main, *grid, *notes_text;
    GtkWidget *btn_copy_label, *btn_copy_pass;
    GtkWidget *btn_lock, *btn_add, *btn_edit, *btn_del, *btn_sch;
    GtkWidget *btn_snapshot, *btn_find, *btn_batch;
    GtkWidget *btn_refresh, *btn_smart, *btn_rekey, *btn_plugins;
    GtkWidget *btn_create_key_setup, *btn_create_key_unlock, *btn_create_key_main;
    GtkWidget *security_badge;
    GtkWidget *plugin_status;
    GtkWidget *notes_lbl;
    GtkWidget *notes_sep;
    GtkWidget *tree_view;
    GtkTreeStore *tree_store;
    GtkWidget *tree_summary;
    GtkWidget *tree_filter;
    GtkWidget *tree_expand_btn;
    GtkWidget *tree_collapse_btn;
    GtkWidget *tree_sw;
    GtkWidget *toast_revealer;
    GtkWidget *toast_label;
    int        toast_entry_idx;
    db_manager_t *db;
    char *current_file;
    char *expected_fp;
    guint clipboard_timer_id;
    guint autolock_timer_id;
    guint connection_timer_id;
    GDBusConnection *session_bus;
    GDBusConnection *system_bus;
    guint screensaver_sub_id;
    guint gnome_screensaver_sub_id;
    guint sleep_sub_id;
    guint session_lock_sub_id;
    char *logind_session_path;
    int current_entry_idx;
} AppData;

static AppData g_app;
static GdkPixbuf *icon_pb;
static volatile sig_atomic_t g_shutdown_requested = 0;
static guint g_toast_timer_id = 0;
static guint g_plugin_status_timer_id = 0;
static GHashTable *g_known_uuids = NULL;
static gboolean g_uuids_initialized = FALSE;
static gboolean g_batch_running = FALSE;
static gboolean g_autolock_pending = FALSE;

static char *config_path(void) {
    const char *home = g_get_home_dir();
    if (!home || !home[0]) return NULL;

    char *dir = g_build_filename(home, ".diskpass", NULL);
    if (!dir) return NULL;
    if (g_mkdir_with_parents(dir, 0700) != 0) {
        g_free(dir);
        return NULL;
    }
    struct stat st;
    if (g_lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
        chmod(dir, 0700) != 0) {
        g_free(dir);
        return NULL;
    }

    char *path = g_build_filename(dir, "config", NULL);
    if (!path) {
        g_free(dir);
        return NULL;
    }

    if (g_lstat(path, &st) != 0 && errno == ENOENT) {
        char *old_path = g_build_filename(g_get_user_config_dir(), "diskpass", "config", NULL);
        int in_fd = old_path ? open(old_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
        if (in_fd >= 0) {
            struct stat old_st;
            gboolean ok = fstat(in_fd, &old_st) == 0 && S_ISREG(old_st.st_mode) &&
                old_st.st_uid == getuid() && !(old_st.st_mode & (S_IWGRP | S_IWOTH)) &&
                old_st.st_size >= 0 && old_st.st_size <= 1024 * 1024;
            size_t len = ok ? (size_t)old_st.st_size : 0;
            char *buf = ok ? g_malloc(len ? len : 1) : NULL;
            if (ok && !buf) ok = FALSE;
            size_t off = 0;
            while (ok && off < len) {
                ssize_t n = read(in_fd, buf + off, len - off);
                if (n > 0) off += (size_t)n;
                else if (n < 0 && errno == EINTR) continue;
                else { ok = FALSE; break; }
            }
            close(in_fd);
            if (ok) {
                int out_fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
                if (out_fd >= 0) {
                    gboolean wrote = fchmod(out_fd, 0600) == 0 &&
                        write_all_fd(out_fd, buf, len) == 0 && fsync(out_fd) == 0;
                    if (close(out_fd) != 0) wrote = FALSE;
                    if (!wrote) unlink(path);
                }
            }
            if (buf) { sodium_memzero(buf, len); g_free(buf); }
        }
        g_free(old_path);
    }

    g_free(dir);
    return path;
}

static void save_config(void) {
    char *path = config_path();
    if (!path) return;
    GKeyFile *kf = g_key_file_new();
    g_key_file_set_string(kf, "main", "lang", g_lang);
    if (g_app.current_file)
        g_key_file_set_string(kf, "main", "last_db", g_app.current_file);
    gsize len = 0;
    char *data = g_key_file_to_data(kf, &len, NULL);
    if (data) {
        char *tmp_path = g_strdup_printf("%s.tmp.XXXXXX", path);
        int fd = tmp_path ? g_mkstemp_full(tmp_path, O_WRONLY | O_CLOEXEC, 0600) : -1;
        gboolean ok = FALSE;
        if (fd >= 0) {
            if (fchmod(fd, 0600) == 0 && write_all_fd(fd, data, (size_t)len) == 0 && fsync(fd) == 0)
                ok = TRUE;
            if (close(fd) != 0) ok = FALSE;
            if (ok && rename(tmp_path, path) != 0) ok = FALSE;
            if (!ok && tmp_path) unlink(tmp_path);
            if (ok) {
                char *dir = g_path_get_dirname(path);
                if (dir) {
                    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                    if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
                    g_free(dir);
                }
            }
        }
        g_free(tmp_path);
        g_free(data);
    }
    g_key_file_free(kf);
    g_free(path);
}

static void load_config(void) {
    char *path = config_path();
    if (!path) return;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { g_free(path); return; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) || st.st_size < 0 || st.st_size > 1024 * 1024) {
        close(fd); g_free(path); return;
    }
    gsize len = (gsize)st.st_size;
    char *data = g_malloc(len + 1);
    if (!data) { close(fd); g_free(path); return; }
    gsize off = 0;
    gboolean ok = TRUE;
    while (off < len) {
        ssize_t n = read(fd, data + off, len - off);
        if (n > 0) off += (gsize)n;
        else if (n < 0 && errno == EINTR) continue;
        else { ok = FALSE; break; }
    }
    close(fd);
    data[len] = '\0';
    GKeyFile *kf = g_key_file_new();
    if (ok && g_utf8_validate(data, (gssize)len, NULL) &&
        g_key_file_load_from_data(kf, data, len, G_KEY_FILE_NONE, NULL)) {
        char *lang = g_key_file_get_string(kf, "main", "lang", NULL);
        if (lang && i18n_language_exists(lang)) i18n_set_language(lang);
        g_free(lang);
    }
    sodium_memzero(data, len);
    g_free(data);
    g_key_file_unref(kf);
    g_free(path);
}

static char *find_icon_path(void) {
    char *home_icon = g_build_filename(g_get_home_dir(), ".diskpass", "disk-icon.png", NULL);
    if (home_icon && g_file_test(home_icon, G_FILE_TEST_IS_REGULAR)) return home_icon;
    g_free(home_icon);
    char *p1 = g_build_filename(g_get_user_data_dir(), "diskpass", "disk-icon.png", NULL);
    if (g_file_test(p1, G_FILE_TEST_EXISTS)) return p1;
    g_free(p1);
    char *p2 = g_build_filename("/usr/local/share/diskpass", "disk-icon.png", NULL);
    if (g_file_test(p2, G_FILE_TEST_EXISTS)) return p2;
    g_free(p2);
    char *p3 = g_build_filename("/usr/share/diskpass", "disk-icon.png", NULL);
    if (g_file_test(p3, G_FILE_TEST_EXISTS)) return p3;
    g_free(p3);
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        char *dir = g_path_get_dirname(exe_path);
        char *p4 = g_build_filename(dir, "disk-icon.png", NULL);
        g_free(dir);
        if (g_file_test(p4, G_FILE_TEST_EXISTS)) return p4;
        g_free(p4);
    }
    if (g_file_test("disk-icon.png", G_FILE_TEST_EXISTS)) return g_strdup("disk-icon.png");
    return NULL;
}

static GdkPixbuf *load_icon(int size) {
    if (icon_pb) return gdk_pixbuf_scale_simple(icon_pb, size, size, GDK_INTERP_BILINEAR);
    return NULL;
}

static GtkWidget *make_icon_img(int size) {
    GdkPixbuf *pb = load_icon(size);
    if (pb) {
        GtkWidget *img = gtk_image_new_from_pixbuf(pb);
        g_object_unref(pb);
        return img;
    }
    return gtk_image_new_from_icon_name("drive-harddisk-symbolic", GTK_ICON_SIZE_BUTTON);
}

static gboolean clipboard_clear_timer(gpointer user_data) {
    (void)user_data;
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    g_app.clipboard_timer_id = 0;
    return G_SOURCE_REMOVE;
}

static void clipboard_copy_secure(const char *text) {
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, text, -1);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    g_app.clipboard_timer_id = g_timeout_add_seconds(30, clipboard_clear_timer, NULL);
}

static void on_gen_password(GtkButton *b, gpointer d) {
    (void)b;
    char *pw = generate_password(24);
    gtk_entry_set_text(GTK_ENTRY(d), pw);
    sec_strfree(pw);
}

static void on_back_to_welcome(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    gtk_stack_set_visible_child_name(g_app.stack, "welcome");
}

static void on_minimize_clicked(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    gtk_window_iconify(GTK_WINDOW(g_app.window));
}

static void on_maximize_clicked(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    GtkWindow *win = GTK_WINDOW(g_app.window);
    if (gtk_window_is_maximized(win)) gtk_window_unmaximize(win);
    else gtk_window_maximize(win);
}

static void on_close_clicked(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    gtk_window_close(GTK_WINDOW(g_app.window));
}

static gboolean on_window_state_changed(GtkWidget *w, GdkEventWindowState *ev,
    gpointer user_data)
{
    (void)w;
    GtkButton *btn = GTK_BUTTON(user_data);
    if (ev->new_window_state & GDK_WINDOW_STATE_MAXIMIZED)
        gtk_button_set_label(btn, "❐");
    else
        gtk_button_set_label(btn, "□");
    return FALSE;
}

static void install_dialog_title(GtkWindow *win, const char *text) {
    gtk_window_set_title(win, text);
    GtkWidget *hb = NULL;
    if (GTK_IS_DIALOG(win))
        hb = gtk_dialog_get_header_bar(GTK_DIALOG(win));
    if (!GTK_IS_HEADER_BAR(hb))
        hb = gtk_window_get_titlebar(win);
    if (!GTK_IS_HEADER_BAR(hb)) {
        hb = gtk_header_bar_new();
        gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
        gtk_window_set_titlebar(win, hb);
    }
    GtkWidget *lbl = gtk_label_new(text);
    gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_NONE);
    gtk_widget_set_size_request(lbl, 420, -1);
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), lbl);
    gtk_widget_show_all(hb);
}

static void update_security_badge(void);

static void update_ui_text(void) {
    if (g_app.welcome_title) gtk_label_set_text(GTK_LABEL(g_app.welcome_title), "DiskPass");
    if (g_app.welcome_desc) gtk_label_set_text(GTK_LABEL(g_app.welcome_desc), i18n("app_desc"));
    if (g_app.btn_open) gtk_button_set_label(GTK_BUTTON(g_app.btn_open), i18n("open_db"));
    if (g_app.btn_create) gtk_button_set_label(GTK_BUTTON(g_app.btn_create), i18n("create_db"));
    if (g_app.lbl_lang_welcome) gtk_label_set_text(GTK_LABEL(g_app.lbl_lang_welcome), i18n("language"));
    if (g_app.setup_title) gtk_label_set_text(GTK_LABEL(g_app.setup_title), i18n("setup_title"));
    if (g_app.lbl_setup_file) gtk_label_set_text(GTK_LABEL(g_app.lbl_setup_file), i18n("db_file"));
    if (g_app.lbl_setup_key) gtk_label_set_text(GTK_LABEL(g_app.lbl_setup_key), i18n("pgp_key"));
    if (g_app.lbl_setup_lang) gtk_label_set_text(GTK_LABEL(g_app.lbl_setup_lang), i18n("language"));
    if (g_app.btn_setup_back) gtk_button_set_label(GTK_BUTTON(g_app.btn_setup_back), i18n("back"));
    if (g_app.btn_setup_create) gtk_button_set_label(GTK_BUTTON(g_app.btn_setup_create), i18n("create_btn"));
    if (g_app.unlock_title) gtk_label_set_text(GTK_LABEL(g_app.unlock_title), i18n("locked_title"));
    if (g_app.lbl_unlock_file) gtk_label_set_text(GTK_LABEL(g_app.lbl_unlock_file), i18n("file"));
    if (g_app.lbl_unlock_key) gtk_label_set_text(GTK_LABEL(g_app.lbl_unlock_key), i18n("pgp_key"));
    if (g_app.btn_unlock_back) gtk_button_set_label(GTK_BUTTON(g_app.btn_unlock_back), i18n("back"));
    if (g_app.btn_unlock) gtk_button_set_label(GTK_BUTTON(g_app.btn_unlock), i18n("unlock_btn"));
    if (g_app.btn_lock) gtk_widget_set_tooltip_text(g_app.btn_lock, i18n("lock_db"));
    if (g_app.btn_add) gtk_widget_set_tooltip_text(g_app.btn_add, i18n("add_entry"));
    if (g_app.btn_edit) gtk_widget_set_tooltip_text(g_app.btn_edit, i18n("edit_entry"));
    if (g_app.btn_del) gtk_widget_set_tooltip_text(g_app.btn_del, i18n("del_entry"));
    if (g_app.btn_sch) gtk_widget_set_tooltip_text(g_app.btn_sch, i18n("show_schema"));
    if (g_app.btn_snapshot) gtk_widget_set_tooltip_text(g_app.btn_snapshot, i18n("snapshot_btn"));
    if (g_app.btn_find) gtk_widget_set_tooltip_text(g_app.btn_find, i18n("find_btn"));
    if (g_app.btn_batch) gtk_widget_set_tooltip_text(g_app.btn_batch, i18n("batch_reindex"));
    if (g_app.btn_refresh) gtk_widget_set_tooltip_text(g_app.btn_refresh, i18n("refresh_connections"));
    if (g_app.btn_smart) gtk_widget_set_tooltip_text(g_app.btn_smart, i18n("smart_refresh"));
    if (g_app.btn_rekey) gtk_widget_set_tooltip_text(g_app.btn_rekey, i18n("change_key"));
    if (g_app.btn_create_key_setup) gtk_widget_set_tooltip_text(g_app.btn_create_key_setup, i18n("create_key"));
    if (g_app.btn_create_key_unlock) gtk_widget_set_tooltip_text(g_app.btn_create_key_unlock, i18n("create_key"));
    if (g_app.btn_create_key_main) gtk_widget_set_tooltip_text(g_app.btn_create_key_main, i18n("create_key"));
    if (g_app.btn_plugins) gtk_widget_set_tooltip_text(g_app.btn_plugins, i18n("plugins"));
    update_security_badge();
    if (g_app.search) gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.search), i18n("search"));
    if (g_app.tree_filter) gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.tree_filter), i18n("search"));
    if (g_app.lbl_main) gtk_label_set_text(GTK_LABEL(g_app.lbl_main), i18n("select_entry"));
    if (g_app.btn_copy_label) gtk_button_set_label(GTK_BUTTON(g_app.btn_copy_label), i18n("copy_label"));
    if (g_app.btn_copy_pass) gtk_button_set_label(GTK_BUTTON(g_app.btn_copy_pass), i18n("copy_pass"));
    if (g_app.notes_lbl) gtk_label_set_text(GTK_LABEL(g_app.notes_lbl), i18n("notes"));
}

static void refresh_entry_list(void) {
    if (!g_app.db) return;
    GList *children = gtk_container_get_children(GTK_CONTAINER(g_app.listbox));
    for (GList *l = children; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);
    for (int i = 0; i < g_app.db->entry_count; i++) {
        db_entry_t *e = &g_app.db->entries[i];
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        gtk_widget_set_margin_top(box, 6); gtk_widget_set_margin_bottom(box, 6);
        gtk_widget_set_margin_start(box, 10); gtk_widget_set_margin_end(box, 10);
        char *tip = build_label_tooltip(g_app.db, e->label);
        gboolean has_alias = e->alias && e->alias[0];

        GtkWidget *title_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        if (e->uuid && e->uuid[0]) {
            gboolean conn = uuid_is_connected(e->uuid);
            GtkWidget *dot = gtk_label_new(conn ? "●" : "○");
            gtk_style_context_add_class(gtk_widget_get_style_context(dot),
                conn ? "connected-dot" : "disconnected-dot");
            gtk_box_pack_start(GTK_BOX(title_row), dot, FALSE, FALSE, 0);
        }

        GtkWidget *lbl = gtk_label_new(has_alias ? e->alias : e->label);
        gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "row-title");
        gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
        gtk_box_pack_start(GTK_BOX(title_row), lbl, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(box), title_row, FALSE, TRUE, 0);

        if (has_alias) {
            GtkWidget *tag_lbl = gtk_label_new(e->label);
            gtk_style_context_add_class(gtk_widget_get_style_context(tag_lbl), "dim-label");
            gtk_label_set_xalign(GTK_LABEL(tag_lbl), 0.0);
            gtk_label_set_ellipsize(GTK_LABEL(tag_lbl), PANGO_ELLIPSIZE_END);
            gtk_widget_set_tooltip_text(tag_lbl, tip);
            gtk_box_pack_start(GTK_BOX(box), tag_lbl, FALSE, TRUE, 0);
        } else {
            gtk_widget_set_tooltip_text(lbl, tip);
        }
        g_free(tip);

        GtkWidget *sub = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        GtkWidget *l1 = gtk_label_new(e->type ? e->type : "");
        GtkWidget *l2 = gtk_label_new(e->size ? e->size : "");
        GtkWidget *l3 = gtk_label_new(e->cipher ? e->cipher : "");
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_style_context_add_class(gtk_widget_get_style_context(l2), "dim-label");
        gtk_style_context_add_class(gtk_widget_get_style_context(l3), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_xalign(GTK_LABEL(l3), 0.0);
        gtk_box_pack_start(GTK_BOX(sub), l1, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(sub), l2, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(sub), l3, FALSE, FALSE, 0);

        if (e->last_snapshot > 0) {
            char *rel = g_strdup_printf("%lld", (long long)((time(NULL) - e->last_snapshot) / 86400));
            char *formatted = g_strdup_printf("%s %s", rel, i18n("days_ago"));
            GtkWidget *rl = gtk_label_new(formatted);
            gtk_style_context_add_class(gtk_widget_get_style_context(rl), "dim-label");
            gtk_box_pack_end(GTK_BOX(sub), rl, FALSE, FALSE, 0);
            g_free(rel);
            g_free(formatted);
        }

        if (e->files && e->files[0]) {
            char fc[32];
            snprintf(fc, sizeof(fc), "%d", count_lines(e->files));
            GtkWidget *fl = gtk_label_new(fc);
            gtk_style_context_add_class(gtk_widget_get_style_context(fl), "row-count");
            gtk_box_pack_end(GTK_BOX(sub), fl, FALSE, FALSE, 0);
        }
        gtk_box_pack_start(GTK_BOX(box), sub, FALSE, FALSE, 0);
        gtk_container_add(GTK_CONTAINER(row), box);
        g_object_set_data(G_OBJECT(row), "entry_idx", GINT_TO_POINTER(i));
        gtk_list_box_insert(g_app.listbox, row, -1);
    }
    gtk_widget_show_all(GTK_WIDGET(g_app.listbox));
}

static void set_tree_visible(gboolean visible) {
    if (visible) {
        gtk_widget_show(g_app.tree_summary);
        gtk_widget_show(g_app.tree_expand_btn);
        gtk_widget_show(g_app.tree_collapse_btn);
        gtk_widget_show(g_app.tree_filter);
        if (g_app.tree_view) gtk_widget_show(g_app.tree_view);
        gtk_widget_show(g_app.tree_sw);
    } else {
        gtk_widget_hide(g_app.tree_summary);
        gtk_widget_hide(g_app.tree_filter);
        gtk_widget_hide(g_app.tree_expand_btn);
        gtk_widget_hide(g_app.tree_collapse_btn);
        gtk_widget_hide(g_app.tree_sw);
    }
}

static void set_notes_visible(gboolean visible) {
    if (visible) {
        gtk_widget_show(g_app.notes_sep);
        gtk_widget_show(g_app.notes_lbl);
        gtk_widget_show(g_app.notes_text);
    } else {
        gtk_widget_hide(g_app.notes_sep);
        gtk_widget_hide(g_app.notes_lbl);
        gtk_widget_hide(g_app.notes_text);
    }
}

static void clear_details(void) {
    gtk_label_set_text(GTK_LABEL(g_app.lbl_main), i18n("select_entry"));
    GList *children = gtk_container_get_children(GTK_CONTAINER(g_app.grid));
    for (GList *l = children; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);
    gtk_label_set_text(GTK_LABEL(g_app.notes_text), "");
    gtk_widget_set_sensitive(g_app.btn_copy_label, FALSE);
    gtk_widget_set_sensitive(g_app.btn_copy_pass, FALSE);

    if (g_app.tree_store) gtk_tree_store_clear(g_app.tree_store);
    set_tree_visible(FALSE);
    set_notes_visible(FALSE);
}

static void tree_icon_func(GtkTreeViewColumn *col, GtkCellRenderer *rend,
    GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
    (void)col; (void)data;
    gboolean is_dir = FALSE;
    gtk_tree_model_get(model, iter, 1, &is_dir, -1);
    g_object_set(rend, "icon-name",
        is_dir ? "folder" : "text-x-generic", NULL);
}

static void on_tree_row_activated(GtkTreeView *tv, GtkTreePath *path,
    GtkTreeViewColumn *col, gpointer user_data)
{
    (void)tv; (void)col; (void)user_data;
    if (gtk_tree_view_row_expanded(GTK_TREE_VIEW(g_app.tree_view), path))
        gtk_tree_view_collapse_row(GTK_TREE_VIEW(g_app.tree_view), path);
    else
        gtk_tree_view_expand_row(GTK_TREE_VIEW(g_app.tree_view), path, FALSE);
}

static char *g_tree_filter_needle = NULL;

static gboolean tree_filter_func(GtkTreeModel *model, GtkTreeIter *iter, gpointer data) {
    (void)data;
    if (!g_tree_filter_needle || !g_tree_filter_needle[0]) return TRUE;

    char *name = NULL;
    gtk_tree_model_get(model, iter, 0, &name, -1);
    gboolean match = FALSE;
    if (name) {
        char *low = g_ascii_strdown(name, -1);
        match = (strstr(low, g_tree_filter_needle) != NULL);
        g_free(low);
        g_free(name);
    }
    if (match) return TRUE;

    GtkTreeIter child;
    if (gtk_tree_model_iter_children(model, &child, iter)) {
        do {
            if (tree_filter_func(model, &child, data)) return TRUE;
        } while (gtk_tree_model_iter_next(model, &child));
    }
    return FALSE;
}

static void on_tree_filter_changed(GtkSearchEntry *e, gpointer u) {
    (void)u;
    const char *txt = gtk_entry_get_text(GTK_ENTRY(e));

    free(g_tree_filter_needle);
    g_tree_filter_needle = (txt && txt[0]) ? g_ascii_strdown(txt, -1) : NULL;

    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(g_app.tree_view));
    if (GTK_IS_TREE_MODEL_FILTER(model))
        gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(model));
    if (txt && txt[0])
        gtk_tree_view_expand_all(GTK_TREE_VIEW(g_app.tree_view));
}

static void on_tree_expand_all(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    gtk_tree_view_expand_all(GTK_TREE_VIEW(g_app.tree_view));
}

static void on_tree_collapse_all(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    gtk_tree_view_collapse_all(GTK_TREE_VIEW(g_app.tree_view));
}

static char *tree_build_path(GtkTreeModel *model, GtkTreeIter *iter) {
    GtkTreeIter cur = *iter;
    GString *s = g_string_new(NULL);
    while (1) {
        char *name = NULL;
        gtk_tree_model_get(model, &cur, 0, &name, -1);
        if (!name) break;
        g_string_prepend(s, name);
        g_free(name);
        GtkTreeIter parent;
        if (!gtk_tree_model_iter_parent(model, &parent, &cur)) break;
        g_string_prepend_c(s, '/');
        cur = parent;
    }
    return g_string_free(s, FALSE);
}

static void on_tree_copy_path(GtkMenuItem *item, gpointer u) {
    (void)item; (void)u;
    char *p = g_object_get_data(G_OBJECT(item), "path");
    if (p) clipboard_copy_secure(p);
}

static void on_tree_copy_name(GtkMenuItem *item, gpointer u) {
    (void)item; (void)u;
    char *p = g_object_get_data(G_OBJECT(item), "name");
    if (p) clipboard_copy_secure(p);
}

static gboolean on_tree_button_press(GtkWidget *tv, GdkEventButton *ev, gpointer u) {
    (void)u;
    if (ev->button != 3) return FALSE;

    GtkTreePath *path = NULL;
    if (!gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(tv),
            (int)ev->x, (int)ev->y, &path, NULL, NULL, NULL))
        return FALSE;

    GtkTreeIter iter;
    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(tv));
    if (!gtk_tree_model_get_iter(model, &iter, path)) {
        gtk_tree_path_free(path);
        return FALSE;
    }

    char *name = NULL;
    gtk_tree_model_get(model, &iter, 0, &name, -1);
    char *full = tree_build_path(model, &iter);

    GtkWidget *menu = gtk_menu_new();
    g_signal_connect_swapped(menu, "selection-done", G_CALLBACK(gtk_widget_destroy), menu);

    GtkWidget *mi1 = gtk_menu_item_new_with_label(i18n("copy_path"));
    g_object_set_data_full(G_OBJECT(mi1), "path", full, g_free);
    g_signal_connect(mi1, "activate", G_CALLBACK(on_tree_copy_path), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi1);

    GtkWidget *mi2 = gtk_menu_item_new_with_label(i18n("copy_name"));
    g_object_set_data_full(G_OBJECT(mi2), "name", name, g_free);
    g_signal_connect(mi2, "activate", G_CALLBACK(on_tree_copy_name), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi2);

    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent*)ev);

    gtk_tree_path_free(path);
    return TRUE;
}

static void build_file_tree(const char *files) {
    if (!g_app.tree_store) return;
    gtk_tree_store_clear(g_app.tree_store);
    if (!files || !files[0]) return;
    fs_node_t *root = fs_build_tree(files);
    fs_to_store(root, g_app.tree_store, NULL);
    fs_node_free(root);

    if (gtk_tree_model_iter_n_children(GTK_TREE_MODEL(g_app.tree_store), NULL) <= 100) {
        GtkTreePath *p = gtk_tree_path_new_first();
        gtk_tree_view_expand_row(GTK_TREE_VIEW(g_app.tree_view), p, FALSE);
        gtk_tree_path_free(p);
    }
}

static char *format_relative_time(long long ts) {
    if (ts <= 0) return g_strdup("");
    time_t now = time(NULL);
    long long diff = (long long)now - ts;
    if (diff < 0) diff = 0;
    long long days = diff / 86400;
    if (days == 0) return g_strdup(i18n("today"));
    if (days == 1) return g_strdup(i18n("yesterday"));
    if (days < 30) return g_strdup_printf("%lld %s", days, i18n("days_ago"));

    time_t t = (time_t)ts;
    struct tm tmv;
    localtime_r(&t, &tmv);
    char buf[32];
    strftime(buf, sizeof(buf), "%d.%m.%Y", &tmv);
    return g_strdup(buf);
}

static void show_smart_grid(GtkGrid *grid, int *row, const char *smart_json) {
    cJSON *root = cJSON_Parse(smart_json);
    if (!root) return;
    int r = *row;

    cJSON *health    = cJSON_GetObjectItem(root, "health");
    cJSON *model     = cJSON_GetObjectItem(root, "model");
    cJSON *serial    = cJSON_GetObjectItem(root, "serial");
    cJSON *firmware  = cJSON_GetObjectItem(root, "firmware");
    cJSON *capacity  = cJSON_GetObjectItem(root, "capacity");
    cJSON *temp      = cJSON_GetObjectItem(root, "temperature");
    cJSON *hours     = cJSON_GetObjectItem(root, "hours");
    cJSON *cycles    = cJSON_GetObjectItem(root, "power_cycles");
    cJSON *realloc_d = cJSON_GetObjectItem(root, "reallocated");
    cJSON *wear      = cJSON_GetObjectItem(root, "wear");
    cJSON *crc       = cJSON_GetObjectItem(root, "crc_errors");
    cJSON *media_err = cJSON_GetObjectItem(root, "media_errors");
    cJSON *unsafe_sd = cJSON_GetObjectItem(root, "unsafe_shutdowns");
    cJSON *spare     = cJSON_GetObjectItem(root, "available_spare");
    cJSON *critical  = cJSON_GetObjectItem(root, "critical_warning");

    if (health && cJSON_IsString(health)) {
        GtkWidget *l1 = gtk_label_new("SMART");
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, r, 1, 1);

        GtkWidget *l2 = gtk_label_new(health->valuestring);
        gtk_style_context_add_class(gtk_widget_get_style_context(l2),
            strcmp(health->valuestring, "PASSED") == 0 ? "smart-ok" : "smart-bad");
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_grid_attach(grid, l2, 1, r, 1, 1);
        r++;
    }

    #define ADD_SMART_FIELD(label_key, node) do { \
        if ((node) && cJSON_IsString(node)) { \
            GtkWidget *a = gtk_label_new(i18n(label_key)); \
            gtk_style_context_add_class(gtk_widget_get_style_context(a), "dim-label"); \
            gtk_label_set_xalign(GTK_LABEL(a), 0.0); \
            gtk_grid_attach(grid, a, 0, r, 1, 1); \
            GtkWidget *b = gtk_label_new((node)->valuestring); \
            gtk_label_set_xalign(GTK_LABEL(b), 0.0); \
            gtk_label_set_ellipsize(GTK_LABEL(b), PANGO_ELLIPSIZE_END); \
            gtk_widget_set_hexpand(b, TRUE); \
            gtk_grid_attach(grid, b, 1, r, 1, 1); \
            r++; \
        } \
    } while (0)

    ADD_SMART_FIELD("smart_model",            model);
    ADD_SMART_FIELD("smart_serial",           serial);
    ADD_SMART_FIELD("smart_firmware",         firmware);
    ADD_SMART_FIELD("smart_capacity",         capacity);
    ADD_SMART_FIELD("smart_temp",             temp);
    ADD_SMART_FIELD("smart_hours",            hours);
    ADD_SMART_FIELD("smart_cycles",           cycles);
    ADD_SMART_FIELD("smart_realloc",          realloc_d);
    ADD_SMART_FIELD("smart_wear",             wear);
    ADD_SMART_FIELD("smart_crc",              crc);
    ADD_SMART_FIELD("smart_media_errors",     media_err);
    ADD_SMART_FIELD("smart_unsafe_shutdowns", unsafe_sd);
    ADD_SMART_FIELD("smart_spare",            spare);
    ADD_SMART_FIELD("smart_critical",         critical);

    #undef ADD_SMART_FIELD

    db_json_zero_strings(root);
    cJSON_Delete(root);
    *row = r;
}

static void show_entry_details(int idx) {
    clear_details();
    if (!g_app.db || idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];
    gboolean has_alias = e->alias && e->alias[0];
    gtk_label_set_text(GTK_LABEL(g_app.lbl_main), has_alias ? e->alias : (e->label ? e->label : ""));
    char *tip = build_label_tooltip(g_app.db, e->label);
    gtk_widget_set_tooltip_text(g_app.lbl_main, tip);
    g_free(tip);
    gtk_widget_set_sensitive(g_app.btn_copy_label, TRUE);
    gtk_widget_set_sensitive(g_app.btn_copy_pass, e->dpass != NULL);

    parsed_block_t blocks[SCHEMA_COUNT];
    int block_count = 0;
    char err_buf[256] = "";
    if (db_parse_label(g_app.db, e->label, blocks, &block_count, err_buf, sizeof(err_buf)) != 0) {
        gtk_label_set_text(GTK_LABEL(g_app.lbl_main), err_buf);
        return;
    }
    GtkGrid *grid = GTK_GRID(g_app.grid);
    int row = 0;

    if (has_alias) {
        GtkWidget *l1 = gtk_label_new(i18n("label"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);

        GtkWidget *vrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        GtkWidget *vlbl = make_visual_label(g_app.db, e->label);
        if (vlbl) {
            gtk_box_pack_start(GTK_BOX(vrow), vlbl, FALSE, FALSE, 0);
            char *tip2 = build_label_tooltip(g_app.db, e->label);
            gtk_widget_set_tooltip_text(vrow, tip2);
            g_free(tip2);
        } else {
            GtkWidget *l2 = gtk_label_new(e->label);
            gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
            gtk_box_pack_start(GTK_BOX(vrow), l2, FALSE, FALSE, 0);
        }

        gtk_widget_set_hexpand(vrow, TRUE);
        gtk_grid_attach(grid, vrow, 1, row, 1, 1);
        row++;
    }

    for (int i = 0; i < block_count; i++) {
        char header[64];
        snprintf(header, sizeof(header), "%d · %s", i+1, i18n(blocks[i].part_name));
        GtkWidget *l1 = gtk_label_new(header);
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        char val_text[128];
        if (strcmp(blocks[i].part_name, "type") == 0 ||
            strcmp(blocks[i].part_name, "size") == 0 ||
            strcmp(blocks[i].part_name, "cipher") == 0)
            snprintf(val_text, sizeof(val_text), "%s (%s)", blocks[i].val, blocks[i].decoded);
        else
            snprintf(val_text, sizeof(val_text), "%s", blocks[i].decoded);
        GtkWidget *l2 = gtk_label_new(val_text);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(l2, TRUE);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }

    if (e->tag_full && e->tag_full[0]) {
        GtkWidget *l1 = gtk_label_new(i18n("full_tag"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        GtkWidget *l2 = gtk_label_new(e->tag_full);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(l2, TRUE);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }

    if (e->dpass) {
        GtkWidget *l1 = gtk_label_new(i18n("password"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        GtkWidget *l2 = gtk_label_new("••••••••••••");
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }

    if (e->uuid && e->uuid[0]) {
        GtkWidget *l1 = gtk_label_new(i18n("uuid"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);

        char buf[512];
        gboolean conn = uuid_is_connected(e->uuid);
        snprintf(buf, sizeof(buf), "%s · %s",
            e->uuid, conn ? i18n("connected_yes") : i18n("connected_no"));
        GtkWidget *l2 = gtk_label_new(buf);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_MIDDLE);
        gtk_widget_set_hexpand(l2, TRUE);
        if (conn)
            gtk_style_context_add_class(gtk_widget_get_style_context(l2), "connected-dot");
        else
            gtk_style_context_add_class(gtk_widget_get_style_context(l2), "dim-label");
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }

    if (e->last_snapshot > 0) {
        GtkWidget *l1 = gtk_label_new(i18n("last_snapshot"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        char *rel = format_relative_time(e->last_snapshot);
        GtkWidget *l2 = gtk_label_new(rel);
        g_free(rel);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }

    if (e->smart && e->smart[0]) {
        show_smart_grid(grid, &row, e->smart);
    }

    if (e->files && e->files[0]) {
        int fc = count_lines(e->files);
        long long total = total_bytes_in_files(e->files);
        char *ts = format_bytes(total);
        char hdr[200];
        snprintf(hdr, sizeof(hdr), "%s · %d · %s", i18n("files_on_disk"), fc, ts);
        g_free(ts);
        gtk_label_set_text(GTK_LABEL(g_app.tree_summary), hdr);
        build_file_tree(e->files);
        set_tree_visible(TRUE);
    } else {
        gtk_label_set_text(GTK_LABEL(g_app.tree_summary), i18n("no_index_yet"));
        gtk_widget_show(g_app.tree_summary);
        gtk_widget_hide(g_app.tree_expand_btn);
        gtk_widget_hide(g_app.tree_collapse_btn);
        gtk_widget_hide(g_app.tree_filter);
        gtk_widget_hide(g_app.tree_sw);
        if (g_app.tree_store) gtk_tree_store_clear(g_app.tree_store);
    }

    if (e->notes && e->notes[0]) {
        gtk_label_set_text(GTK_LABEL(g_app.notes_text), e->notes);
        set_notes_visible(TRUE);
    } else {
        set_notes_visible(FALSE);
    }

    gtk_widget_show_all(GTK_WIDGET(grid));
}

static void on_row_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data) {
    (void)box; (void)user_data;
    if (!row) {
        if (g_app.current_entry_idx != -1) {
            g_app.current_entry_idx = -1;
            clear_details();
        }
        return;
    }
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx == g_app.current_entry_idx) return;
    g_app.current_entry_idx = idx;
    show_entry_details(idx);
}

static gboolean filter_func(GtkListBoxRow *row, gpointer user_data) {
    (void)user_data;
    const char *query = gtk_entry_get_text(GTK_ENTRY(g_app.search));
    if (!query[0]) return TRUE;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (!g_app.db || idx < 0 || idx >= g_app.db->entry_count) return TRUE;
    db_entry_t *e = &g_app.db->entries[idx];
    char searchable[512];
    snprintf(searchable, sizeof(searchable), "%s %s %s %s %s %s %s",
        e->label?e->label:"", e->type?e->type:"", e->size?e->size:"",
        e->content_tag?e->content_tag:"", e->cipher?e->cipher:"", e->dsalt?e->dsalt:"",
        e->alias?e->alias:"");
    char lq[64]; strncpy(lq, query, sizeof(lq)-1); lq[sizeof(lq)-1]='\0';
    for (char *p = lq; *p; p++) *p = tolower((unsigned char)*p);
    char ls[512]; strncpy(ls, searchable, sizeof(ls)-1); ls[sizeof(ls)-1]='\0';
    for (char *p = ls; *p; p++) *p = tolower((unsigned char)*p);
    return strstr(ls, lq) != NULL;
}

static void on_search_changed(GtkSearchEntry *entry, gpointer user_data) {
    (void)entry; (void)user_data;
    gtk_list_box_invalidate_filter(g_app.listbox);
}

static void copy_selected_entry_field(gboolean password) {
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row || !g_app.db) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];
    const char *v = password ? e->dpass : e->label;
    if (v) clipboard_copy_secure(v);
}

static void on_copy_label_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    copy_selected_entry_field(FALSE);
}

static void on_copy_pass_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    copy_selected_entry_field(TRUE);
}

static void show_toast(const char *text, int duration_ms, int entry_idx);
static void show_save_error(const char *err);
static void reset_autolock(void);
static void on_lock_clicked(GtkButton *btn, gpointer user_data);
static void update_db_write_controls(void);
static void update_security_badge(void);
static void on_create_gpg_key_clicked(GtkButton *btn, gpointer user_data);
static void populate_gpg_keys(GtkComboBoxText *combo, int secret_only, GtkWidget *err_label);

static gboolean has_visible_modal_window(void) {
    GList *wins = gtk_window_list_toplevels();
    gboolean found = FALSE;
    for (GList *l = wins; l; l = l->next) {
        if (GTK_IS_WINDOW(l->data) && gtk_widget_get_visible(GTK_WIDGET(l->data)) &&
            gtk_window_get_modal(GTK_WINDOW(l->data))) {
            found = TRUE;
            break;
        }
    }
    g_list_free(wins);
    return found;
}

static void on_lock_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    g_autolock_pending = FALSE;
    if (g_app.autolock_timer_id) {
        g_source_remove(g_app.autolock_timer_id);
        g_app.autolock_timer_id = 0;
    }
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    free(g_app.current_file); g_app.current_file = NULL;
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    g_app.current_entry_idx = -1;
    clear_details();
    refresh_entry_list();
    if (g_known_uuids) g_hash_table_remove_all(g_known_uuids);
    g_uuids_initialized = FALSE;
    if (g_toast_timer_id) { g_source_remove(g_toast_timer_id); g_toast_timer_id = 0; }
    if (g_app.toast_revealer)
        gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.clipboard_timer_id) {
        g_source_remove(g_app.clipboard_timer_id);
        g_app.clipboard_timer_id = 0;
    }
    update_security_badge();
    gtk_stack_set_visible_child_name(g_app.stack, "welcome");
}

static gboolean autolock_cb(gpointer user_data) {
    (void)user_data;
    g_app.autolock_timer_id = 0;
    if (g_batch_running || has_visible_modal_window()) {
        g_autolock_pending = TRUE;
        g_app.autolock_timer_id = g_timeout_add_seconds(1, autolock_cb, NULL);
        return G_SOURCE_REMOVE;
    }
    g_autolock_pending = FALSE;
    if (g_app.db) on_lock_clicked(NULL, NULL);
    return G_SOURCE_REMOVE;
}

static void reset_autolock(void) {
    if (g_app.autolock_timer_id) g_source_remove(g_app.autolock_timer_id);
    g_app.autolock_timer_id = 0;
    if (g_app.db)
        g_app.autolock_timer_id =
            g_timeout_add_seconds(AUTOLOCK_SECONDS, autolock_cb, NULL);
}

static gboolean on_user_activity(GtkWidget *w, GdkEvent *ev, gpointer u) {
    (void)w; (void)ev; (void)u;
    reset_autolock();
    return FALSE;
}

static void request_system_security_lock(void) {
    if (!g_app.db) return;
    if (g_batch_running || has_visible_modal_window()) {
        g_autolock_pending = TRUE;
        if (!g_app.autolock_timer_id)
            g_app.autolock_timer_id = g_timeout_add_seconds(1, autolock_cb, NULL);
        return;
    }
    on_lock_clicked(NULL, NULL);
}

static void on_screensaver_signal(GDBusConnection *connection, const gchar *sender_name,
    const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
    GVariant *parameters, gpointer user_data)
{
    (void)connection; (void)sender_name; (void)object_path;
    (void)interface_name; (void)signal_name; (void)user_data;
    gboolean active = FALSE;
    if (parameters && g_variant_is_of_type(parameters, G_VARIANT_TYPE("(b)"))) {
        g_variant_get(parameters, "(b)", &active);
        if (active) request_system_security_lock();
    }
}

static void on_prepare_for_sleep_signal(GDBusConnection *connection, const gchar *sender_name,
    const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
    GVariant *parameters, gpointer user_data)
{
    (void)connection; (void)sender_name; (void)object_path;
    (void)interface_name; (void)signal_name; (void)user_data;
    gboolean sleeping = FALSE;
    if (parameters && g_variant_is_of_type(parameters, G_VARIANT_TYPE("(b)"))) {
        g_variant_get(parameters, "(b)", &sleeping);
        if (sleeping) request_system_security_lock();
    }
}

static void on_logind_session_lock_signal(GDBusConnection *connection, const gchar *sender_name,
    const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
    GVariant *parameters, gpointer user_data)
{
    (void)connection; (void)sender_name; (void)object_path; (void)interface_name;
    (void)signal_name; (void)parameters; (void)user_data;
    request_system_security_lock();
}

static void setup_system_lock_monitor(void) {
    GError *err = NULL;
    g_app.session_bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &err);
    if (err) { g_error_free(err); err = NULL; }
    if (g_app.session_bus) {
        g_app.screensaver_sub_id = g_dbus_connection_signal_subscribe(
            g_app.session_bus, "org.freedesktop.ScreenSaver", "org.freedesktop.ScreenSaver", "ActiveChanged",
            "/org/freedesktop/ScreenSaver", NULL, G_DBUS_SIGNAL_FLAGS_NONE,
            on_screensaver_signal, NULL, NULL);
        g_app.gnome_screensaver_sub_id = g_dbus_connection_signal_subscribe(
            g_app.session_bus, "org.gnome.ScreenSaver", "org.gnome.ScreenSaver", "ActiveChanged",
            "/org/gnome/ScreenSaver", NULL, G_DBUS_SIGNAL_FLAGS_NONE,
            on_screensaver_signal, NULL, NULL);
    }

    g_app.system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (err) { g_error_free(err); err = NULL; }
    if (g_app.system_bus) {
        g_app.sleep_sub_id = g_dbus_connection_signal_subscribe(
            g_app.system_bus, "org.freedesktop.login1", "org.freedesktop.login1.Manager",
            "PrepareForSleep", "/org/freedesktop/login1", NULL, G_DBUS_SIGNAL_FLAGS_NONE,
            on_prepare_for_sleep_signal, NULL, NULL);

        GVariant *reply = g_dbus_connection_call_sync(g_app.system_bus,
            "org.freedesktop.login1", "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager", "GetSessionByPID",
            g_variant_new("(u)", (guint32)getpid()), G_VARIANT_TYPE("(o)"),
            G_DBUS_CALL_FLAGS_NONE, 2000, NULL, &err);
        if (reply) {
            const gchar *path = NULL;
            g_variant_get(reply, "(&o)", &path);
            if (path) g_app.logind_session_path = g_strdup(path);
            g_variant_unref(reply);
        }
        if (err) { g_error_free(err); err = NULL; }
        if (g_app.logind_session_path) {
            g_app.session_lock_sub_id = g_dbus_connection_signal_subscribe(
                g_app.system_bus, "org.freedesktop.login1", "org.freedesktop.login1.Session",
                "Lock", g_app.logind_session_path, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
                on_logind_session_lock_signal, NULL, NULL);
        }
    }
}

static void cleanup_system_lock_monitor(void) {
    if (g_app.session_bus) {
        if (g_app.screensaver_sub_id)
            g_dbus_connection_signal_unsubscribe(g_app.session_bus, g_app.screensaver_sub_id);
        if (g_app.gnome_screensaver_sub_id)
            g_dbus_connection_signal_unsubscribe(g_app.session_bus, g_app.gnome_screensaver_sub_id);
    }
    if (g_app.system_bus) {
        if (g_app.sleep_sub_id)
            g_dbus_connection_signal_unsubscribe(g_app.system_bus, g_app.sleep_sub_id);
        if (g_app.session_lock_sub_id)
            g_dbus_connection_signal_unsubscribe(g_app.system_bus, g_app.session_lock_sub_id);
    }
    g_clear_object(&g_app.session_bus);
    g_clear_object(&g_app.system_bus);
    g_clear_pointer(&g_app.logind_session_path, g_free);
    g_app.screensaver_sub_id = 0;
    g_app.gnome_screensaver_sub_id = 0;
    g_app.sleep_sub_id = 0;
    g_app.session_lock_sub_id = 0;
}

static void update_security_badge(void) {
    if (!g_app.security_badge) return;
    GtkStyleContext *ctx = gtk_widget_get_style_context(g_app.security_badge);
    gtk_style_context_remove_class(ctx, "security-pqc");
    gtk_style_context_remove_class(ctx, "security-classic");
    gtk_style_context_remove_class(ctx, "security-locked");

    if (!g_app.db || !g_app.db->recipient) {
        gtk_label_set_text(GTK_LABEL(g_app.security_badge), i18n("security_locked"));
        gtk_style_context_add_class(ctx, "security-locked");
        return;
    }
    if (db_recipient_has_pqc(g_app.db)) {
        gtk_label_set_text(GTK_LABEL(g_app.security_badge), i18n("security_pqc"));
        gtk_style_context_add_class(ctx, "security-pqc");
    } else {
        gtk_label_set_text(GTK_LABEL(g_app.security_badge), i18n("security_classic"));
        gtk_style_context_add_class(ctx, "security-classic");
    }
}

static gboolean key_text_is_safe(const char *s, size_t max_len) {
    if (!s) return TRUE;
    size_t n = strlen(s);
    if (n > max_len) return FALSE;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\r' || c == '\n' || c == 0x7f || c < 0x20) return FALSE;
    }
    return TRUE;
}

static void refresh_visible_key_lists(void) {
    if (!g_app.db || !g_app.db->gpg_ctx) return;
    if (g_app.key_combo && g_app.setup_err)
        populate_gpg_keys(GTK_COMBO_BOX_TEXT(g_app.key_combo), 1, g_app.setup_err);
    if (g_app.unlock_key_combo && g_app.unlock_err)
        populate_gpg_keys(GTK_COMBO_BOX_TEXT(g_app.unlock_key_combo), 1, g_app.unlock_err);
}

static void on_create_gpg_key_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;

    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("create_key_title"), g_app.window,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("create"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 520, 330);
    install_dialog_title(GTK_WINDOW(dlg), i18n("create_key_title"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 18);
    gtk_box_set_spacing(GTK_BOX(content), 12);

    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_style_context_add_class(gtk_widget_get_style_context(card), "key-card");
    gtk_box_pack_start(GTK_BOX(content), card, TRUE, TRUE, 0);

    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 12);
    gtk_grid_set_row_spacing(grid, 10);
    gtk_box_pack_start(GTK_BOX(card), GTK_WIDGET(grid), FALSE, FALSE, 0);

    GtkWidget *name_e = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(name_e), 128);
    GtkWidget *email_e = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(email_e), 254);
    gtk_entry_set_input_purpose(GTK_ENTRY(email_e), GTK_INPUT_PURPOSE_EMAIL);

    GtkWidget *type_cb = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_cb), "pqc", i18n("key_type_pqc"));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(type_cb), "default", i18n("key_type_classic"));
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(type_cb), "pqc");

    GtkWidget *exp_cb = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(exp_cb), "1y", i18n("key_expiry_1y"));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(exp_cb), "2y", i18n("key_expiry_2y"));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(exp_cb), "5y", i18n("key_expiry_5y"));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(exp_cb), "never", i18n("key_expiry_never"));
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(exp_cb), "2y");

    GtkWidget *labels[] = {
        gtk_label_new(i18n("key_name")), gtk_label_new(i18n("key_email")),
        gtk_label_new(i18n("key_type")), gtk_label_new(i18n("key_expiry"))
    };
    GtkWidget *values[] = { name_e, email_e, type_cb, exp_cb };
    for (int i = 0; i < 4; i++) {
        gtk_label_set_xalign(GTK_LABEL(labels[i]), 1.0);
        gtk_grid_attach(grid, labels[i], 0, i, 1, 1);
        gtk_widget_set_hexpand(values[i], TRUE);
        gtk_grid_attach(grid, values[i], 1, i, 1, 1);
    }

    GtkWidget *note = gtk_label_new(i18n("key_pinentry_note"));
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(note), "dim-label");
    gtk_box_pack_start(GTK_BOX(card), note, FALSE, FALSE, 0);

    GtkWidget *err_lbl = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(err_lbl), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(err_lbl), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(err_lbl), "error");
    gtk_box_pack_start(GTK_BOX(content), err_lbl, FALSE, FALSE, 0);

    gtk_widget_show_all(dlg);
    gtk_widget_grab_focus(name_e);

    while (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *name = gtk_entry_get_text(GTK_ENTRY(name_e));
        const char *email = gtk_entry_get_text(GTK_ENTRY(email_e));
        const char *algo = gtk_combo_box_get_active_id(GTK_COMBO_BOX(type_cb));
        const char *expire = gtk_combo_box_get_active_id(GTK_COMBO_BOX(exp_cb));

        if (!name || !name[0]) {
            gtk_label_set_text(GTK_LABEL(err_lbl), i18n("key_name_required"));
            continue;
        }
        if (!key_text_is_safe(name, 128) || !key_text_is_safe(email, 254)) {
            gtk_label_set_text(GTK_LABEL(err_lbl), i18n("key_create_failed"));
            continue;
        }
        if (!algo) algo = "pqc";
        if (!expire) expire = "2y";

        char *uid = (email && email[0])
            ? g_strdup_printf("%s <%s>", name, email)
            : g_strdup(name);
        if (!uid) {
            gtk_label_set_text(GTK_LABEL(err_lbl), i18n("key_create_failed"));
            continue;
        }

        const char *gpg_path = gpg_openpgp_engine_path();
        if (!gpg_path) {
            g_free(uid);
            gtk_label_set_text(GTK_LABEL(err_lbl), i18n("gpg_engine_missing"));
            continue;
        }

        const gchar *argv[] = {
            gpg_path,
            "--no-options",
            "--batch",
            "--pinentry-mode", "ask",
            "--quick-generate-key", uid, algo, "default", expire,
            NULL
        };
        GError *spawn_err = NULL;
        GSubprocess *proc = g_subprocess_newv(argv,
            G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
            &spawn_err);
        if (!proc) {
            char *msg = g_strdup_printf("%s: %s", i18n("key_create_failed"),
                spawn_err ? spawn_err->message : "unknown error");
            gtk_label_set_text(GTK_LABEL(err_lbl), msg);
            g_free(msg);
            if (spawn_err) g_error_free(spawn_err);
            g_free(uid);
            continue;
        }

        gchar *out_text = NULL, *err_text = NULL;
        gboolean communicated = g_subprocess_communicate_utf8(proc, NULL, NULL,
            &out_text, &err_text, &spawn_err);
        gboolean ok = communicated && g_subprocess_get_successful(proc);
        if (!ok) {
            const char *detail = (err_text && err_text[0]) ? err_text :
                (spawn_err ? spawn_err->message : "GnuPG returned an error");
            char *msg = g_strdup_printf("%s: %.700s", i18n("key_create_failed"), detail);
            gtk_label_set_text(GTK_LABEL(err_lbl), msg);
            g_free(msg);
            g_free(out_text);
            g_free(err_text);
            if (spawn_err) g_error_free(spawn_err);
            g_object_unref(proc);
            g_free(uid);
            continue;
        }

        g_free(out_text);
        g_free(err_text);
        if (spawn_err) g_error_free(spawn_err);
        g_object_unref(proc);
        g_free(uid);

        refresh_visible_key_lists();
        gtk_widget_destroy(dlg);
        GtkWidget *info = gtk_message_dialog_new(g_app.window,
            GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", i18n("key_created"));
        gtk_dialog_run(GTK_DIALOG(info));
        gtk_widget_destroy(info);
        return;
    }
    gtk_widget_destroy(dlg);
}

static void populate_gpg_keys(GtkComboBoxText *combo, int secret_only, GtkWidget *err_label) {
    gtk_combo_box_text_remove_all(combo);
    if (!g_app.db) return;
    int count = 0;
    gpg_key_info_t *keys = gpg_list_keys(g_app.db->gpg_ctx, secret_only, &count);
    if (!keys || count == 0) { gtk_label_set_text(GTK_LABEL(err_label), i18n("no_keys")); gpg_free_key_list(keys, count); return; }
    int active = 0;
    for (int i = 0; i < count; i++) {
        const char *mark = keys[i].has_pqc ? "[PQC / ML-KEM]" : i18n("no_quantum_mark");
        char *display = g_strdup_printf("%s %s", mark, keys[i].uid);
        gtk_combo_box_text_append(combo, keys[i].fingerprint, display);
        g_free(display);
        if (g_app.expected_fp && strcmp(keys[i].fingerprint, g_app.expected_fp) == 0) active = i;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), active);
    gtk_label_set_text(GTK_LABEL(err_label), "");
    gpg_free_key_list(keys, count);
}

static void on_change_key_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;

    int count = 0;
    gpg_key_info_t *keys = gpg_list_keys(g_app.db->gpg_ctx, 1, &count);
    if (!keys || count == 0) {
        show_save_error(i18n("no_keys"));
        gpg_free_key_list(keys, count);
        return;
    }

    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("change_key_title"), g_app.window,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("save"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 560, 220);
    install_dialog_title(GTK_WINDOW(dlg), i18n("change_key_title"));
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 10);

    GtkWidget *cur_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(cur_box), gtk_label_new(i18n("change_key_current")), FALSE, FALSE, 0);
    GtkWidget *cur = gtk_label_new(g_app.db->recipient ? g_app.db->recipient : "?");
    gtk_label_set_ellipsize(GTK_LABEL(cur), PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_set_hexpand(cur, TRUE);
    gtk_label_set_xalign(GTK_LABEL(cur), 0.0);
    gtk_box_pack_start(GTK_BOX(cur_box), cur, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(content), cur_box, FALSE, FALSE, 0);

    GtkWidget *new_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(new_box), gtk_label_new(i18n("change_key_new")), FALSE, FALSE, 0);
    GtkWidget *combo = gtk_combo_box_text_new();
    gtk_widget_set_hexpand(combo, TRUE);
    int active = 0;
    for (int i = 0; i < count; i++) {
        const char *mark = keys[i].has_pqc ? "[PQC / ML-KEM]" : i18n("no_quantum_mark");
        char *display = g_strdup_printf("%s %s", mark, keys[i].uid);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), keys[i].fingerprint, display);
        g_free(display);
        if (g_app.db->recipient && g_ascii_strcasecmp(keys[i].fingerprint, g_app.db->recipient) == 0)
            active = i;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), active);
    gtk_box_pack_start(GTK_BOX(new_box), combo, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(content), new_box, FALSE, FALSE, 0);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const gchar *selected = gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
        if (selected && (!g_app.db->recipient || g_ascii_strcasecmp(selected, g_app.db->recipient) != 0)) {
            char *new_fp = xstrdup(selected);
            gpgme_key_t pub = NULL, sec = NULL;
            gpgme_error_t pe = gpgme_get_key(g_app.db->gpg_ctx, new_fp, &pub, 0);
            gpgme_error_t se = gpgme_get_key(g_app.db->gpg_ctx, new_fp, &sec, 1);
            gboolean valid = pe == GPG_ERR_NO_ERROR && se == GPG_ERR_NO_ERROR && pub && sec &&
                !pub->revoked && !pub->expired && !pub->disabled && !pub->invalid && pub->can_encrypt &&
                !sec->revoked && !sec->expired && !sec->disabled && !sec->invalid && sec->can_sign;
            if (pub) gpgme_key_release(pub);
            if (sec) gpgme_key_release(sec);
            if (!valid) {
                secure_free_string(&new_fp);
                show_save_error(i18n("selected_key_invalid"));
            } else {
                char *old_fp = g_app.db->recipient;
                g_app.db->recipient = new_fp;
                char err[256] = "";
                if (db_save(g_app.db, err, sizeof(err)) != 0) {
                    secure_free_string(&g_app.db->recipient);
                    g_app.db->recipient = old_fp;
                    show_save_error(err);
                } else {
                    secure_free_string(&old_fp);
                    secure_free_string(&g_app.expected_fp);
                    g_app.expected_fp = xstrdup(g_app.db->recipient);
                    const char *status = db_recipient_has_pqc(g_app.db)
                        ? i18n("rekey_pqc_done")
                        : i18n("rekey_classic_done");
                    update_security_badge();
                    show_toast(status, 10000, -1);
                }
            }
        }
    }
    gtk_widget_destroy(dlg);
    gpg_free_key_list(keys, count);
}

static void on_open_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    GtkWidget *dlg = gtk_file_chooser_dialog_new(i18n("open_db"), g_app.window, GTK_FILE_CHOOSER_ACTION_OPEN,
        i18n("cancel"), GTK_RESPONSE_CANCEL, i18n("open_db"), GTK_RESPONSE_OK, NULL);
    GtkFileFilter *f = gtk_file_filter_new();
    gtk_file_filter_set_name(f, "DiskPass (*.dpdb)");
    gtk_file_filter_add_pattern(f, "*.dpdb");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), f);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        free(g_app.current_file);
        gchar *chosen_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        g_app.current_file = xstrdup(chosen_path);
        g_free(chosen_path);
        char info[256];
        snprintf(info, sizeof(info), "%s %s", i18n("file"), g_app.current_file);
        gtk_label_set_text(GTK_LABEL(g_app.unlock_file_label), info);
        free(g_app.expected_fp); g_app.expected_fp = NULL;
        int hfd = open(g_app.current_file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (hfd >= 0) {
            struct stat hst;
            if (fstat(hfd, &hst) == 0 && S_ISREG(hst.st_mode) && hst.st_size > 0 &&
                (uint64_t)hst.st_size <= (uint64_t)DB_MAX_FILE_BYTES) {
                FILE *fp = fdopen(hfd, "r");
                if (fp) {
                    char line[256];
                    if (fgets(line, sizeof(line), fp)) {
                        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
                        char *cr = strchr(line, '\r'); if (cr) *cr = '\0';
                        if (strlen(line) == 32 || strlen(line) == 40 || strlen(line) == 64)
                            g_app.expected_fp = xstrdup(line);
                    }
                    fclose(fp);
                } else close(hfd);
            } else close(hfd);
        }
        if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
        g_app.db = calloc(1, sizeof(db_manager_t));
        if (!g_app.db) { gtk_widget_destroy(dlg); return; }
        db_manager_init(g_app.db);
        if (ensure_db_gpg(g_app.db) != 0) {
            db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL;
        } else {
            populate_gpg_keys(GTK_COMBO_BOX_TEXT(g_app.unlock_key_combo), 1, g_app.unlock_err);
            gtk_stack_set_visible_child_name(g_app.stack, "unlock");
        }
    }
    gtk_widget_destroy(dlg);
}

static void on_create_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    GtkWidget *dlg = gtk_file_chooser_dialog_new(i18n("create_db"), g_app.window, GTK_FILE_CHOOSER_ACTION_SAVE,
        i18n("cancel"), GTK_RESPONSE_CANCEL, i18n("create_btn"), GTK_RESPONSE_OK, NULL);
    GtkFileFilter *f = gtk_file_filter_new();
    gtk_file_filter_set_name(f, "DiskPass (*.dpdb)");
    gtk_file_filter_add_pattern(f, "*.dpdb");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), f);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        free(g_app.current_file);
        gchar *chosen_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        g_app.current_file = xstrdup(chosen_path);
        g_free(chosen_path);
        if (!g_str_has_suffix(g_app.current_file, ".dpdb")) {
            char *tmp = g_strconcat(g_app.current_file, ".dpdb", NULL);
            free(g_app.current_file);
            g_app.current_file = xstrdup(tmp);
            g_free(tmp);
        }
        gtk_label_set_text(GTK_LABEL(g_app.setup_file_label), g_app.current_file);
        gtk_label_set_text(GTK_LABEL(g_app.setup_err), "");
        if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
        g_app.db = calloc(1, sizeof(db_manager_t));
        if (!g_app.db) { gtk_widget_destroy(dlg); return; }
        db_manager_init(g_app.db);
        if (ensure_db_gpg(g_app.db) != 0) {
            db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL;
        } else {
            populate_gpg_keys(GTK_COMBO_BOX_TEXT(g_app.key_combo), 1, g_app.setup_err);
            gtk_stack_set_visible_child_name(g_app.stack, "setup");
        }
    }
    gtk_widget_destroy(dlg);
}

static void on_setup_create_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.current_file) return;
    gchar *recipient = (gchar*)gtk_combo_box_get_active_id(GTK_COMBO_BOX(g_app.key_combo));
    if (!recipient) { gtk_label_set_text(GTK_LABEL(g_app.setup_err), i18n("pgp_key")); return; }
    char err_buf[256] = "";
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    g_app.db = db_manager_create(g_app.current_file, recipient, g_lang, err_buf, sizeof(err_buf));
    if (!g_app.db) { gtk_label_set_text(GTK_LABEL(g_app.setup_err), err_buf); return; }
    update_ui_text();
    g_app.current_entry_idx = -1;
    if (g_known_uuids) g_hash_table_remove_all(g_known_uuids);
    g_uuids_initialized = FALSE;
    save_config();
    reset_autolock();
    gtk_stack_set_visible_child_name(g_app.stack, "main");
    refresh_entry_list();
    update_db_write_controls();
}

static void on_unlock_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.current_file) return;
    gchar *selected_fp = (gchar*)gtk_combo_box_get_active_id(GTK_COMBO_BOX(g_app.unlock_key_combo));
    if (!selected_fp) { gtk_label_set_text(GTK_LABEL(g_app.unlock_err), i18n("pgp_key")); return; }
    char err_buf[256] = "";
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    g_app.db = db_manager_open(g_app.current_file, selected_fp, err_buf, sizeof(err_buf));
    if (!g_app.db) { gtk_label_set_text(GTK_LABEL(g_app.unlock_err), err_buf); return; }
    update_ui_text();
    g_app.current_entry_idx = -1;
    if (g_known_uuids) g_hash_table_remove_all(g_known_uuids);
    g_uuids_initialized = FALSE;
    save_config();
    reset_autolock();
    gtk_stack_set_visible_child_name(g_app.stack, "main");
    refresh_entry_list();
    update_db_write_controls();
    if (!g_app.db->is_pqc_encrypted) {
        if (db_recipient_has_pqc(g_app.db)) {
            show_toast(i18n("legacy_upgrade_msg"), 12000, -1);
        } else {
            show_toast(i18n("legacy_classic_msg"), 15000, -1);
        }
    }
}

static void on_delete_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    char msg[256];
    snprintf(msg, sizeof(msg), "%s %s?", i18n("delete_msg"), g_app.db->entries[idx].label);
    GtkWidget *dlg = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s", msg);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_YES) {
        char err_buf[256] = "";
        if (db_remove_entry(g_app.db, g_app.db->entries[idx].label, err_buf, sizeof(err_buf)) != 0) {
            GtkWidget *edlg = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
                GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s: %s", i18n("save_error"), err_buf);
            gtk_dialog_run(GTK_DIALOG(edlg));
            gtk_widget_destroy(edlg);
        }
        g_app.current_entry_idx = -1;
        refresh_entry_list();
        clear_details();
    }
    gtk_widget_destroy(dlg);
}

static void on_add_type_changed(GtkComboBoxText *combo, gpointer user_data) {
    GtkComboBoxText *vsz = GTK_COMBO_BOX_TEXT(user_data);
    gchar *type_val = gtk_combo_box_text_get_active_text(combo);
    gtk_combo_box_text_remove_all(vsz);
    if (type_val) {
        const char **sizes = get_sizes_for_type(type_val);
        for (int i = 0; sizes[i]; i++) gtk_combo_box_text_append_text(vsz, sizes[i]);
        g_free(type_val);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(vsz), 0);
}

static void on_toggle_password_visibility(GtkEntry *entry, GtkEntryIconPosition pos, GdkEvent *event, gpointer user_data) {
    (void)pos; (void)event; (void)user_data;
    gboolean visible = gtk_entry_get_visibility(entry);
    gtk_entry_set_visibility(entry, !visible);
    gtk_entry_set_icon_from_icon_name(entry, GTK_ENTRY_ICON_SECONDARY,
        !visible ? "eye-open-symbolic" : "eye-not-looking-symbolic");
}

static GtkWidget *make_password_field(GtkWidget **out_entry) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(entry), '*');
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(entry),
        GTK_ENTRY_ICON_SECONDARY, "eye-not-looking-symbolic");
    gtk_entry_set_icon_activatable(GTK_ENTRY(entry), GTK_ENTRY_ICON_SECONDARY, TRUE);
    gtk_entry_set_icon_tooltip_text(GTK_ENTRY(entry),
        GTK_ENTRY_ICON_SECONDARY, "Toggle visibility");
    g_signal_connect(entry, "icon-press",
        G_CALLBACK(on_toggle_password_visibility), NULL);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_box_pack_start(GTK_BOX(box), entry, TRUE, TRUE, 0);

    GtkWidget *btn = gtk_button_new_from_icon_name("view-refresh", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(btn, i18n("generate"));
    gtk_box_pack_start(GTK_BOX(box), btn, FALSE, FALSE, 0);
    g_signal_connect(btn, "clicked", G_CALLBACK(on_gen_password), entry);

    *out_entry = entry;
    return box;
}

static void show_save_error(const char *err) {
    GtkWidget *dlg = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
        GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
        "%s: %s", i18n("save_error"), err ? err : "?");
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static void update_db_write_controls(void) {
    gboolean writable = (g_app.db != NULL);
    if (g_app.btn_add) gtk_widget_set_sensitive(g_app.btn_add, writable);
    if (g_app.btn_edit) gtk_widget_set_sensitive(g_app.btn_edit, writable);
    if (g_app.btn_del) gtk_widget_set_sensitive(g_app.btn_del, writable);
    if (g_app.btn_snapshot) gtk_widget_set_sensitive(g_app.btn_snapshot, writable);
    if (g_app.btn_batch) gtk_widget_set_sensitive(g_app.btn_batch, writable);
}

typedef struct {
    GtkWidget *radio_auto;
    GtkWidget *radio_manual;
    GtkWidget *disk_combo;
    GtkWidget *refresh_btn;
    GtkWidget *type_combo;
    GtkWidget *size_combo;
    GtkWidget *uuid_label;
    disk_info_t *disks;
    int disk_count;
} add_ctx_t;

static void populate_disk_combo(add_ctx_t *ctx) {
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(ctx->disk_combo));
    free_disk_list(ctx->disks, ctx->disk_count);
    ctx->disks = NULL;
    ctx->disk_count = 0;

    ctx->disks = list_disks(&ctx->disk_count);
    if (ctx->disk_count == 0) {
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(ctx->disk_combo),
            NULL, i18n("no_connected_disks"));
        gtk_combo_box_set_active(GTK_COMBO_BOX(ctx->disk_combo), 0);
        gtk_widget_set_sensitive(ctx->disk_combo, FALSE);
        return;
    }

    gtk_widget_set_sensitive(ctx->disk_combo, TRUE);
    for (int i = 0; i < ctx->disk_count; i++) {
        disk_info_t *d = &ctx->disks[i];
        char label[512];
        const char *nm = d->label ? d->label : (d->model ? d->model : "");
        snprintf(label, sizeof(label), "%s · %s · %s",
            d->device ? d->device : "?",
            nm[0] ? nm : "?",
            d->fstype ? d->fstype : "?");
        char id[64];
        snprintf(id, sizeof(id), "%d", i);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(ctx->disk_combo), id, label);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(ctx->disk_combo), 0);
}

static void on_disk_combo_changed(GtkComboBox *cb, gpointer user_data) {
    add_ctx_t *ctx = user_data;
    const char *id = gtk_combo_box_get_active_id(cb);
    if (!id) return;
    int idx = atoi(id);
    if (idx < 0 || idx >= ctx->disk_count) return;
    disk_info_t *d = &ctx->disks[idx];

    if (ctx->uuid_label) {
        char buf[600];
        snprintf(buf, sizeof(buf), "UUID: %s", d->uuid ? d->uuid : "?");
        gtk_label_set_text(GTK_LABEL(ctx->uuid_label), buf);
    }

    const char *guess_type = transport_to_type(d->transport);
    if (guess_type) {
        GtkTreeModel *model = gtk_combo_box_get_model(GTK_COMBO_BOX(ctx->type_combo));
        GtkTreeIter it;
        int i = 0;
        if (gtk_tree_model_get_iter_first(model, &it)) {
            do {
                char *txt = NULL;
                gtk_tree_model_get(model, &it, 0, &txt, -1);
                if (txt && strcmp(txt, guess_type) == 0) {
                    gtk_combo_box_set_active(GTK_COMBO_BOX(ctx->type_combo), i);
                    g_free(txt);
                    break;
                }
                g_free(txt);
                i++;
            } while (gtk_tree_model_iter_next(model, &it));
        }
    }

    gchar *cur_type = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(ctx->type_combo));
    const char **sizes = get_sizes_for_type(cur_type ? cur_type : "OTHER");
    if (cur_type) g_free(cur_type);

    int n = 0;
    while (sizes[n]) n++;
    if (n > 0) {
        int si = closest_size_index_in(sizes, n, d->size_bytes);
        gtk_combo_box_set_active(GTK_COMBO_BOX(ctx->size_combo), si);
    }
}

static void on_disk_refresh(GtkButton *b, gpointer user_data) {
    (void)b;
    populate_disk_combo((add_ctx_t *)user_data);
}

static void on_add_mode_changed(GtkToggleButton *btn, gpointer user_data) {
    add_ctx_t *ctx = user_data;
    if (!gtk_toggle_button_get_active(btn)) return;
    gboolean auto_mode = (btn == GTK_TOGGLE_BUTTON(ctx->radio_auto));
    gtk_widget_set_sensitive(ctx->disk_combo, auto_mode);
    gtk_widget_set_sensitive(ctx->refresh_btn, auto_mode);
    gtk_widget_set_sensitive(ctx->size_combo, !auto_mode);
    if (auto_mode)
        on_disk_combo_changed(GTK_COMBO_BOX(ctx->disk_combo), ctx);
}

static void on_add_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;

    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("add_entry"), g_app.window,
        GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("create"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 520, 600);
    install_dialog_title(GTK_WINDOW(dlg), i18n("add_entry"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 12);

    add_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    GtkWidget *mode_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    ctx.radio_auto = gtk_radio_button_new_with_label(NULL, i18n("add_auto"));
    ctx.radio_manual = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(ctx.radio_auto), i18n("add_manual"));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ctx.radio_auto), TRUE);
    gtk_box_pack_start(GTK_BOX(mode_box), ctx.radio_auto, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mode_box), ctx.radio_manual, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(content), mode_box, FALSE, FALSE, 0);

    GtkWidget *disk_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    ctx.disk_combo = gtk_combo_box_text_new();
    gtk_widget_set_hexpand(ctx.disk_combo, TRUE);
    gtk_box_pack_start(GTK_BOX(disk_row), ctx.disk_combo, TRUE, TRUE, 0);

    ctx.refresh_btn = gtk_button_new_from_icon_name("view-refresh-symbolic",
        GTK_ICON_SIZE_BUTTON);
    gtk_box_pack_start(GTK_BOX(disk_row), ctx.refresh_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(content), disk_row, FALSE, FALSE, 0);

    ctx.uuid_label = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx.uuid_label), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(ctx.uuid_label), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(ctx.uuid_label), PANGO_ELLIPSIZE_MIDDLE);
    gtk_box_pack_start(GTK_BOX(content), ctx.uuid_label, FALSE, FALSE, 0);

    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 12);
    gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_hexpand(GTK_WIDGET(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(grid), TRUE, TRUE, 0);

    int row = 0;
    gtk_grid_attach(grid, gtk_label_new(i18n("alias")), 0, row, 1, 1);
    GtkWidget *valias = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(valias), i18n("alias_placeholder"));
    gtk_widget_set_hexpand(valias, TRUE);
    gtk_grid_attach(grid, valias, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("media_type")), 0, row, 1, 1);
    ctx.type_combo = gtk_combo_box_text_new();
    for (int i = 0; i < TYPE_MAP_N; i++)
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ctx.type_combo), TYPE_MAP[i].name);
    gtk_combo_box_set_active(GTK_COMBO_BOX(ctx.type_combo), 0);
    gtk_widget_set_hexpand(ctx.type_combo, TRUE);
    gtk_grid_attach(grid, ctx.type_combo, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("size")), 0, row, 1, 1);
    ctx.size_combo = gtk_combo_box_text_new();
    gtk_widget_set_hexpand(ctx.size_combo, TRUE);
    gtk_grid_attach(grid, ctx.size_combo, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("cipher")), 0, row, 1, 1);
    GtkWidget *vci = gtk_combo_box_text_new();
    for (int i = 0; i < CIPHER_MAP_N; i++)
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(vci), CIPHER_MAP[i].name);
    gtk_combo_box_set_active(GTK_COMBO_BOX(vci), 0);
    gtk_widget_set_hexpand(vci, TRUE);
    gtk_grid_attach(grid, vci, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("password")), 0, row, 1, 1);
    GtkWidget *vdp = NULL;
    GtkWidget *ph = make_password_field(&vdp);
    gtk_grid_attach(grid, ph, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("tag_min")), 0, row, 1, 1);
    GtkWidget *vt = gtk_entry_new(); gtk_widget_set_hexpand(vt, TRUE);
    gtk_grid_attach(grid, vt, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("salt")), 0, row, 1, 1);
    char *salt_str = generate_salt(2);
    GtkWidget *vd = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(vd), salt_str);
    gtk_editable_set_editable(GTK_EDITABLE(vd), FALSE);
    gtk_widget_set_hexpand(vd, TRUE);
    gtk_grid_attach(grid, vd, 1, row++, 1, 1);
    free(salt_str);

    gtk_grid_attach(grid, gtk_label_new(i18n("notes")), 0, row, 1, 1);
    GtkWidget *nt = gtk_text_view_new(); gtk_widget_set_size_request(nt, -1, 60);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw), nt); gtk_widget_set_hexpand(sw, TRUE);
    gtk_grid_attach(grid, sw, 1, row++, 1, 1);

    const char **sizes = get_sizes_for_type(TYPE_MAP[0].name);
    for (int i = 0; sizes[i]; i++)
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ctx.size_combo), sizes[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(ctx.size_combo), 0);

    g_signal_connect(ctx.type_combo, "changed", G_CALLBACK(on_add_type_changed), ctx.size_combo);
    g_signal_connect(ctx.radio_auto, "toggled", G_CALLBACK(on_add_mode_changed), &ctx);
    g_signal_connect(ctx.radio_manual, "toggled", G_CALLBACK(on_add_mode_changed), &ctx);
    g_signal_connect(ctx.disk_combo, "changed", G_CALLBACK(on_disk_combo_changed), &ctx);
    g_signal_connect(ctx.refresh_btn, "clicked", G_CALLBACK(on_disk_refresh), &ctx);

    populate_disk_combo(&ctx);
    on_add_mode_changed(GTK_TOGGLE_BUTTON(ctx.radio_auto), &ctx);

    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *tag_str = gtk_entry_get_text(GTK_ENTRY(vt));
        if (strlen(tag_str) < 2) {
            if (vdp) gtk_entry_set_text(GTK_ENTRY(vdp), "");
            gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt)), "", 0);
            gtk_widget_destroy(dlg);
            free_disk_list(ctx.disks, ctx.disk_count);
            return;
        }
        char tag_val[3] = {
            toupper((unsigned char)tag_str[0]),
            toupper((unsigned char)tag_str[1]),
            '\0'
        };
        gchar *type_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(ctx.type_combo));
        gchar *size_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(ctx.size_combo));
        gchar *cipher_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(vci));
        const char *dpass_val = gtk_entry_get_text(GTK_ENTRY(vdp));
        const char *dsalt_val = gtk_entry_get_text(GTK_ENTRY(vd));
        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt));
        GtkTextIter start, end;
        gtk_text_buffer_get_start_iter(buf, &start);
        gtk_text_buffer_get_end_iter(buf, &end);
        char *notes_val = gtk_text_buffer_get_text(buf, &start, &end, FALSE);
        const char *actual_dpass = (strcmp(cipher_val, "NONE") == 0) ? "" : dpass_val;
        const char *alias_val = gtk_entry_get_text(GTK_ENTRY(valias));

        const char *uuid_to_save = NULL;
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ctx.radio_auto)) &&
            ctx.disk_count > 0) {
            const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(ctx.disk_combo));
            if (id) {
                int di = atoi(id);
                if (di >= 0 && di < ctx.disk_count)
                    uuid_to_save = ctx.disks[di].uuid;
            }
        }

        char err_buf[256] = "";
        char *label = db_encode_label(g_app.db, type_val, size_val, tag_val, cipher_val, dsalt_val);

        if (db_add_entry(g_app.db, type_val, size_val, cipher_val, tag_val,
                dsalt_val, tag_str, actual_dpass, notes_val, alias_val,
                uuid_to_save, err_buf, sizeof(err_buf)) == 0) {
            clipboard_copy_secure(label);
            refresh_entry_list();
        } else {
            show_save_error(err_buf);
        }

        free(label);
        secure_g_free_string(&notes_val);
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt)), "", 0);
        g_free(type_val);
        g_free(size_val);
        g_free(cipher_val);
    }

    if (vdp) gtk_entry_set_text(GTK_ENTRY(vdp), "");
    gtk_widget_destroy(dlg);
    free_disk_list(ctx.disks, ctx.disk_count);
}

static void on_edit_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];
    char *entry_label = xstrdup(e->label);
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("edit_entry"), g_app.window, GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL, i18n("save"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 460, 360);
    install_dialog_title(GTK_WINDOW(dlg), i18n("edit_entry"));
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 12);
    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 12); gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_hexpand(GTK_WIDGET(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(grid), TRUE, TRUE, 0);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new(i18n("alias")), 0, 0, 1, 1);
    GtkWidget *valias = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(valias), i18n("alias_placeholder"));
    if (e->alias) gtk_entry_set_text(GTK_ENTRY(valias), e->alias);
    gtk_widget_set_hexpand(valias, TRUE);
    gtk_grid_attach(GTK_GRID(grid), valias, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new(i18n("label")), 0, 1, 1, 1);
    GtkWidget *lbl = gtk_label_new(e->label);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(lbl, TRUE);
    gtk_grid_attach(GTK_GRID(grid), lbl, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new(i18n("password")), 0, 2, 1, 1);
    GtkWidget *vdp = NULL;
    GtkWidget *ph = make_password_field(&vdp);
    if (e->dpass) gtk_entry_set_text(GTK_ENTRY(vdp), e->dpass);
    gtk_grid_attach(GTK_GRID(grid), ph, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new(i18n("notes")), 0, 3, 1, 1);
    GtkWidget *nt = gtk_text_view_new(); gtk_widget_set_size_request(nt, -1, 60);
    if (e->notes) gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt)), e->notes, -1);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw), nt); gtk_widget_set_hexpand(sw, TRUE);
    gtk_grid_attach(GTK_GRID(grid), sw, 1, 3, 1, 1);
    if (e->cipher && strcmp(e->cipher, "NONE") == 0) gtk_widget_hide(ph);
    gtk_widget_show_all(dlg);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *new_dpass = gtk_entry_get_text(GTK_ENTRY(vdp));
        const char *new_alias = gtk_entry_get_text(GTK_ENTRY(valias));
        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt));
        GtkTextIter start, end;
        gtk_text_buffer_get_start_iter(buf, &start); gtk_text_buffer_get_end_iter(buf, &end);
        char *new_notes = gtk_text_buffer_get_text(buf, &start, &end, FALSE);
        char err_buf[256] = "";
        if (!g_app.db || db_update_entry(g_app.db, entry_label, new_dpass, new_notes, new_alias, err_buf, sizeof(err_buf)) != 0) {
            show_save_error(err_buf);
        } else {
            g_app.current_entry_idx = -1;
            refresh_entry_list();
            GtkListBoxRow *new_row = gtk_list_box_get_row_at_index(g_app.listbox, idx);
            if (new_row) gtk_list_box_select_row(g_app.listbox, new_row);
            show_entry_details(idx);
        }
        secure_g_free_string(&new_notes);
    }
    if (vdp) gtk_entry_set_text(GTK_ENTRY(vdp), "");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt)), "", 0);
    gtk_widget_destroy(dlg);
    secure_free_string(&entry_label);
}

static void on_schema_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("schema_title"), g_app.window, GTK_DIALOG_MODAL, i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 460, 440);
    install_dialog_title(GTK_WINDOW(dlg), i18n("schema_title"));
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 15);
    GtkWidget *vis_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_halign(vis_box, GTK_ALIGN_CENTER);
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        const char *p = g_app.db->schema_order[i];
        int vl = 0;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], p) == 0) { vl = PART_LENGTHS[j]; break; }
        GtkWidget *block_wrap = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        GtkWidget *str_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        char val_str[8]; memset(val_str, 'X', vl); val_str[vl] = '\0';
        GtkWidget *val_lbl = gtk_label_new(val_str);
        gtk_style_context_add_class(gtk_widget_get_style_context(val_lbl), "schema-val");
        gtk_box_pack_start(GTK_BOX(str_box), val_lbl, FALSE, FALSE, 0);
        GtkWidget *salt_lbl = gtk_label_new("Y");
        gtk_style_context_add_class(gtk_widget_get_style_context(salt_lbl), "schema-salt");
        gtk_box_pack_start(GTK_BOX(str_box), salt_lbl, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(block_wrap), str_box, FALSE, FALSE, 0);
        char desc[64]; snprintf(desc, sizeof(desc), "%s\n(%d+1)", i18n(p), vl);
        GtkWidget *name_lbl = gtk_label_new(desc);
        gtk_style_context_add_class(gtk_widget_get_style_context(name_lbl), "dim-label");
        gtk_box_pack_start(GTK_BOX(block_wrap), name_lbl, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(vis_box), block_wrap, FALSE, FALSE, 0);
        if (i < SCHEMA_COUNT - 1) {
            GtkWidget *dash = gtk_label_new("-");
            gtk_style_context_add_class(gtk_widget_get_style_context(dash), "schema-dash");
            gtk_box_pack_start(GTK_BOX(vis_box), dash, FALSE, FALSE, 0);
        }
    }
    gtk_box_pack_start(GTK_BOX(content), vis_box, FALSE, FALSE, 0);
    GtkGrid *bgrid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(bgrid, 12); gtk_grid_set_row_spacing(bgrid, 8);
    gtk_widget_set_margin_start(GTK_WIDGET(bgrid), 20); gtk_widget_set_margin_top(GTK_WIDGET(bgrid), 10);
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        const char *p = g_app.db->schema_order[i];
        int vl = 0;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], p) == 0) { vl = PART_LENGTHS[j]; break; }
        char btxt[32]; snprintf(btxt, sizeof(btxt), "%d", i+1);
        GtkWidget *bl = gtk_label_new(btxt);
        gtk_style_context_add_class(gtk_widget_get_style_context(bl), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(bl), 0.0);
        gtk_grid_attach(bgrid, bl, 0, i, 1, 1);
        char dtxt[64]; snprintf(dtxt, sizeof(dtxt), "-> %s (%s: %d, %s: 1)", i18n(p), i18n("val"), vl, i18n("chk"));
        GtkWidget *dl = gtk_label_new(dtxt);
        gtk_label_set_xalign(GTK_LABEL(dl), 0.0);
        gtk_grid_attach(bgrid, dl, 1, i, 1, 1);
    }
    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(bgrid), FALSE, FALSE, 0);
    GtkWidget *footer = gtk_label_new(i18n("schema_footer"));
    gtk_style_context_add_class(gtk_widget_get_style_context(footer), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(footer), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(footer), TRUE);
    gtk_widget_set_margin_top(footer, 10);
    gtk_box_pack_start(GTK_BOX(content), footer, FALSE, FALSE, 0);
    GtkWidget *size_hint_exp = gtk_expander_new(i18n("size_hint_title"));
    gtk_widget_set_margin_top(size_hint_exp, 8);
    GtkWidget *hint_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(hint_scroll, -1, 160);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(hint_scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    GtkGrid *hgrid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(hgrid, 14);
    gtk_grid_set_row_spacing(hgrid, 3);
    gtk_widget_set_margin_start(GTK_WIDGET(hgrid), 8);
    gtk_widget_set_margin_top(GTK_WIDGET(hgrid), 6);
    gtk_widget_set_margin_bottom(GTK_WIDGET(hgrid), 6);
    for (int i = 0; i < SIZE_MAP_N; i++) {
        GtkWidget *code_lbl = gtk_label_new(SIZE_MAP[i].code);
        gtk_style_context_add_class(gtk_widget_get_style_context(code_lbl), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(code_lbl), 0.0);
        gtk_grid_attach(hgrid, code_lbl, 0, i, 1, 1);
        GtkWidget *name_lbl2 = gtk_label_new(SIZE_MAP[i].name);
        gtk_label_set_xalign(GTK_LABEL(name_lbl2), 0.0);
        gtk_grid_attach(hgrid, name_lbl2, 1, i, 1, 1);
    }
    gtk_container_add(GTK_CONTAINER(hint_scroll), GTK_WIDGET(hgrid));
    gtk_container_add(GTK_CONTAINER(size_hint_exp), hint_scroll);
    gtk_box_pack_start(GTK_BOX(content), size_hint_exp, FALSE, FALSE, 0);
    gtk_widget_show_all(dlg);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static void on_attach_snapshot_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];
    char *entry_label = xstrdup(e->label);

    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        i18n("snapshot_title"), g_app.window, GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("scan"), GTK_RESPONSE_OK, NULL);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        gchar *folder = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));

        GtkWidget *wait = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
            GTK_MESSAGE_INFO, GTK_BUTTONS_NONE, "%s", i18n("scanning"));
        gtk_widget_show_all(wait);
        while (gtk_events_pending()) gtk_main_iteration();

        char *files = scan_directory_recursive(folder);
        char *smart_json = collect_smart_data(folder);
        gtk_widget_destroy(wait);

        char err_buf[256] = "";
        if (g_app.db && db_set_entry_snapshot(g_app.db, entry_label, files, smart_json, err_buf, sizeof(err_buf)) == 0) {
            char msg[512];
            char health_buf[32] = "";
            if (smart_json) {
                cJSON *s = cJSON_Parse(smart_json);
                if (s) {
                    cJSON *h = cJSON_GetObjectItem(s, "health");
                    if (h && cJSON_IsString(h))
                        snprintf(health_buf, sizeof(health_buf), "%s", h->valuestring);
                    cJSON_Delete(s);
                }
            }
            if (health_buf[0])
                snprintf(msg, sizeof(msg), "%s: %d · SMART %s",
                    i18n("indexed_files"), count_lines(files), health_buf);
            else
                snprintf(msg, sizeof(msg), "%s: %d · %s",
                    i18n("indexed_files"), count_lines(files),
                    i18n("smart_unavailable"));

            e = (g_app.db && idx >= 0 && idx < g_app.db->entry_count) ? &g_app.db->entries[idx] : NULL;
            if (e && (!e->uuid || !e->uuid[0])) {
                char *detected = get_uuid_for_path(folder);
                if (detected && detected[0]) {
                    char *old_uuid = e->uuid;
                    e->uuid = xstrdup(detected);
                    if (db_save(g_app.db, err_buf, sizeof(err_buf)) != 0) {
                        secure_free_string(&e->uuid);
                        e->uuid = old_uuid;
                        show_save_error(err_buf);
                    } else {
                        secure_free_string(&old_uuid);
                    }
                }
                secure_free_string(&detected);
            }

            GtkWidget *info = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
                GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", msg);
            gtk_dialog_run(GTK_DIALOG(info));
            gtk_widget_destroy(info);
        } else {
            show_save_error(err_buf);
        }
        secure_g_free_string(&files);
        secure_free_string(&smart_json);
        g_free(folder);
        g_app.current_entry_idx = -1;
        refresh_entry_list();
        GtkListBoxRow *new_row = gtk_list_box_get_row_at_index(g_app.listbox, idx);
        if (new_row) gtk_list_box_select_row(g_app.listbox, new_row);
    }
    gtk_widget_destroy(dlg);
    secure_free_string(&entry_label);
}

static gboolean block_close(GtkWidget *w, GdkEvent *e, gpointer u) {
    (void)w; (void)e; (void)u;
    return TRUE;
}

static void on_batch_reindex_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;

    int total_done = 0;
    int total_skip = 0;
    int total_err = 0;

    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("batch_title"),
        g_app.window, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 460, 200);
    install_dialog_title(GTK_WINDOW(dlg), i18n("batch_title"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 12);

    GtkWidget *prog = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(prog), TRUE);
    gtk_box_pack_start(GTK_BOX(content), prog, FALSE, FALSE, 0);

    GtkWidget *lbl = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
    gtk_box_pack_start(GTK_BOX(content), lbl, FALSE, FALSE, 0);

    gtk_widget_show_all(dlg);

    gulong block_close_handler_id =
        g_signal_connect(dlg, "delete-event", G_CALLBACK(block_close), NULL);

    int total = 0;
    for (int i = 0; i < g_app.db->entry_count; i++)
        if (g_app.db->entries[i].uuid && g_app.db->entries[i].uuid[0]) total++;

    if (total == 0) {
        gtk_label_set_text(GTK_LABEL(lbl), i18n("no_connected"));
        if (block_close_handler_id) {
            g_signal_handler_disconnect(dlg, block_close_handler_id);
            block_close_handler_id = 0;
        }
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        return;
    }

    g_batch_running = TRUE;
    reset_autolock();

    int nd = 0;
    disk_info_t *disks = list_disks(&nd);

    int step = 0;
    for (int i = 0; i < g_app.db->entry_count; i++) {
        db_entry_t *e = &g_app.db->entries[i];
        if (!e->uuid || !e->uuid[0]) continue;

        step++;
        double frac = (double)(step - 1) / (double)total;
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(prog), frac);
        char pbuf[64];
        snprintf(pbuf, sizeof(pbuf), i18n("batch_progress"), step, total);
        gtk_progress_bar_set_text(GTK_PROGRESS_BAR(prog), pbuf);
        gtk_label_set_text(GTK_LABEL(lbl),
            (e->alias && e->alias[0]) ? e->alias : e->label);
        while (gtk_events_pending()) gtk_main_iteration();

        const char *mp = NULL;
        for (int k = 0; k < nd; k++) {
            if (disks[k].uuid && strcmp(disks[k].uuid, e->uuid) == 0 &&
                disks[k].mountpoint) {
                mp = disks[k].mountpoint;
                break;
            }
        }

        if (!mp) { total_skip++; continue; }

        char *files = scan_directory_recursive(mp);
        char *smart = collect_smart_data(mp);
        char err[256] = "";
        if (db_set_entry_snapshot(g_app.db, e->label, files, smart, err, sizeof(err)) == 0)
            total_done++;
        else
            total_err++;
        secure_g_free_string(&files);
        secure_free_string(&smart);
    }

    free_disk_list(disks, nd);
    g_batch_running = FALSE;
    if (g_autolock_pending) {
        g_autolock_pending = FALSE;
        gtk_widget_destroy(dlg);
        if (g_app.db) on_lock_clicked(NULL, NULL);
        return;
    }

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(prog), 1.0);
    char done[128];
    snprintf(done, sizeof(done), i18n("batch_done"), total_done, total_skip, total_err);
    gtk_label_set_text(GTK_LABEL(lbl), done);

    g_app.current_entry_idx = -1;
    refresh_entry_list();

    if (block_close_handler_id) {
        g_signal_handler_disconnect(dlg, block_close_handler_id);
        block_close_handler_id = 0;
    }
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static void check_new_disks(void);

static void on_refresh_smart_clicked(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    if (!g_app.db) return;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) {
        show_save_error(i18n("select_entry"));
        return;
    }
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];
    if (!e->uuid || !e->uuid[0]) {
        show_save_error(i18n("smart_no_device"));
        return;
    }

    int nd = 0;
    disk_info_t *disks = list_disks(&nd);
    const char *mp = NULL;
    for (int i = 0; i < nd; i++) {
        if (disks[i].uuid && disks[i].mountpoint && strcmp(disks[i].uuid, e->uuid) == 0) {
            mp = disks[i].mountpoint;
            break;
        }
    }
    if (!mp) {
        free_disk_list(disks, nd);
        show_save_error(i18n("smart_no_device"));
        return;
    }

    GtkWidget *wait = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
        GTK_MESSAGE_INFO, GTK_BUTTONS_NONE, "%s", i18n("scanning"));
    gtk_widget_show_all(wait);
    while (gtk_events_pending()) gtk_main_iteration();
    char *smart = collect_smart_data(mp);
    gtk_widget_destroy(wait);
    free_disk_list(disks, nd);

    if (!smart) {
        show_save_error(i18n("smart_unavailable"));
        return;
    }
    char label_copy[128];
    snprintf(label_copy, sizeof(label_copy), "%s", e->label ? e->label : "");
    char err[256] = "";
    if (db_set_entry_smart(g_app.db, label_copy, smart, err, sizeof(err)) != 0) {
        secure_free_string(&smart);
        show_save_error(err);
        return;
    }
    secure_free_string(&smart);
    g_app.current_entry_idx = idx;
    show_entry_details(idx);
    show_toast(i18n("smart_refresh_done"), 5000, idx);
}

static void on_refresh_connections_clicked(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    if (!g_app.db) return;
    int save_idx = g_app.current_entry_idx;
    check_new_disks();
    g_app.current_entry_idx = -1;
    refresh_entry_list();
    if (save_idx >= 0 && save_idx < g_app.db->entry_count) {
        GtkListBoxRow *row = gtk_list_box_get_row_at_index(g_app.listbox, save_idx);
        if (row) gtk_list_box_select_row(g_app.listbox, row);
    }
}

static void on_menu_copy_activate(GtkMenuItem *item, gpointer user_data) {
    (void)user_data;
    const char *text = g_object_get_data(G_OBJECT(item), "text");
    if (text) clipboard_copy_secure(text);
}

static gboolean on_search_file_click(GtkWidget *row, GdkEventButton *ev, gpointer user_data) {
    (void)user_data;
    if (ev->button != 3) return FALSE;
    const char *path = g_object_get_data(G_OBJECT(row), "full_path");
    if (!path) return FALSE;

    GtkWidget *menu = gtk_menu_new();
    g_signal_connect_swapped(menu, "selection-done", G_CALLBACK(gtk_widget_destroy), menu);
    GtkWidget *mi1 = gtk_menu_item_new_with_label(i18n("copy_path"));
    g_object_set_data_full(G_OBJECT(mi1), "text", g_strdup(path), g_free);
    g_signal_connect(mi1, "activate", G_CALLBACK(on_menu_copy_activate), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi1);

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    GtkWidget *mi2 = gtk_menu_item_new_with_label(i18n("copy_name"));
    g_object_set_data_full(G_OBJECT(mi2), "text", g_strdup(base), g_free);
    g_signal_connect(mi2, "activate", G_CALLBACK(on_menu_copy_activate), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi2);

    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent*)ev);
    return TRUE;
}

static void free_str_list(gpointer p) {
    GList *l = p;
    for (GList *i = l; i; i = i->next) secure_g_free_cb(i->data);
    g_list_free(l);
}

static GHashTable *build_cross_disk_index(db_manager_t *db) {
    GHashTable *h = g_hash_table_new_full(g_str_hash, g_str_equal,
        secure_g_free_cb, free_str_list);
    for (int i = 0; i < db->entry_count; i++) {
        db_entry_t *e = &db->entries[i];
        if (!e->files || !e->files[0]) continue;
        const char *disp = (e->alias && e->alias[0]) ? e->alias : e->label;
        size_t copy_len = strlen(e->files) + 1;
        char *copy = strdup(e->files);
        if (!copy) continue;
        char *save = NULL;
        for (char *ln = strtok_r(copy, "\n", &save); ln;
             ln = strtok_r(NULL, "\n", &save)) {
            char *tab = strchr(ln, '\t');
            if (tab) *tab = '\0';
            if (!ln[0]) continue;
            GList *lst = g_hash_table_lookup(h, ln);
            gboolean dup = FALSE;
            for (GList *q = lst; q; q = q->next)
                if (strcmp((char *)q->data, disp) == 0) { dup = TRUE; break; }
            if (dup) continue;
            if (lst) {
                lst = g_list_append(lst, g_strdup(disp));
            } else {
                lst = g_list_append(NULL, g_strdup(disp));
                g_hash_table_insert(h, g_strdup(ln), lst);
            }
        }
        sodium_memzero(copy, copy_len);
        free(copy);
    }
    return h;
}

static void on_filter_chip_clicked(GtkToggleButton *btn, gpointer user_data);
static gboolean on_filter_chip_press(GtkWidget *w, GdkEventButton *e, gpointer u);
static void on_filter_add_clicked(GtkButton *b, gpointer u);
static void rebuild_filt_box(GtkBox *fb, GtkSearchEntry *se, db_manager_t *db);

static gboolean ascii_contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle) return FALSE;
    if (!*needle) return TRUE;
    size_t nlen = strlen(needle);
    for (const unsigned char *h = (const unsigned char *)haystack; *h; h++) {
        size_t i = 0;
        while (i < nlen && h[i] &&
               g_ascii_tolower(h[i]) == g_ascii_tolower((guchar)needle[i]))
            i++;
        if (i == nlen) return TRUE;
    }
    return FALSE;
}

static gboolean path_matches_ext_filter(const char *path, const char *filter) {
    if (!filter || !filter[0]) return TRUE;
    if (!path) return FALSE;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    const char *dot = strrchr(base, '.');
    if (!dot || !dot[1]) return FALSE;
    const char *ext = dot + 1;
    size_t ext_len = strlen(ext);

    const char *p = filter;
    while (*p) {
        while (*p == ',' || g_ascii_isspace((guchar)*p)) p++;
        const char *begin = p;
        while (*p && *p != ',') p++;
        const char *finish = p;
        while (finish > begin && g_ascii_isspace((guchar)finish[-1])) finish--;
        size_t len = (size_t)(finish - begin);
        if (len == ext_len && g_ascii_strncasecmp(begin, ext, len) == 0)
            return TRUE;
        if (*p == ',') p++;
    }
    return FALSE;
}

static void on_find_changed_now(GtkSearchEntry *se) {
    GtkListBox *lb = GTK_LIST_BOX(g_object_get_data(G_OBJECT(se), "listbox"));
    db_manager_t *db = g_object_get_data(G_OBJECT(se), "db");
    GtkWidget *status = g_object_get_data(G_OBJECT(se), "status");
    if (!lb || !db) return;

    int fidx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(se), "filter_idx"));
    const char *ext_filter = NULL;
    if (fidx >= 0 && fidx < db->filter_count)
        ext_filter = db->filters[fidx].exts;

    GList *ch = gtk_container_get_children(GTK_CONTAINER(lb));
    for (GList *l = ch; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(ch);

    const char *q = gtk_entry_get_text(GTK_ENTRY(se));
    if (!q[0] && !ext_filter) {
        if (status) {
            int indexed = 0;
            for (int i = 0; i < db->entry_count; i++)
                if (db->entries[i].files && db->entries[i].files[0]) indexed++;
            char buf[128];
            snprintf(buf, sizeof(buf), "%d %s", indexed, i18n("disks_with_index"));
            gtk_label_set_text(GTK_LABEL(status), buf);
        }
        gtk_widget_show_all(GTK_WIDGET(lb));
        return;
    }

    GHashTable *cross_index = NULL;
    if (q[0]) {
        cross_index = g_object_get_data(G_OBJECT(se), "cross_index_cache");
        if (!cross_index) {
            cross_index = build_cross_disk_index(db);
            if (cross_index)
                g_object_set_data_full(G_OBJECT(se), "cross_index_cache", cross_index,
                    (GDestroyNotify)g_hash_table_destroy);
        }
    }

    int total_files = 0;
    int total_disks = 0;
    const int per_disk_limit = 200;

    for (int i = 0; i < db->entry_count; i++) {
        db_entry_t *e = &db->entries[i];
        if (!e->files || !e->files[0]) continue;

        size_t copy_len = strlen(e->files) + 1;
        char *copy = strdup(e->files);
        if (!copy) continue;

        GPtrArray *paths = g_ptr_array_new_with_free_func(secure_g_free_cb);
        GArray *sizes = g_array_sized_new(FALSE, FALSE, sizeof(long long), per_disk_limit);
        int match_count = 0;

        char *save = NULL;
        for (char *line = strtok_r(copy, "\n", &save); line;
             line = strtok_r(NULL, "\n", &save)) {
            if (!line[0]) continue;
            long long sz = -1;
            char *tab = strchr(line, '\t');
            if (tab) { *tab = '\0'; sz = atoll(tab + 1); }

            if (q[0] && !ascii_contains_ci(line, q)) continue;
            if (ext_filter && !path_matches_ext_filter(line, ext_filter)) continue;

            match_count++;
            if ((int)paths->len < per_disk_limit) {
                g_ptr_array_add(paths, g_strdup(line));
                g_array_append_val(sizes, sz);
            }
        }
        sodium_memzero(copy, copy_len);
        free(copy);

        if (match_count == 0) {
            g_ptr_array_free(paths, TRUE);
            g_array_free(sizes, TRUE);
            continue;
        }

        total_disks++;
        total_files += match_count;

        const char *disp = (e->alias && e->alias[0]) ? e->alias : e->label;

        GtkWidget *hrow = gtk_list_box_row_new();
        gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(hrow), FALSE);
        gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(hrow), FALSE);
        gtk_style_context_add_class(gtk_widget_get_style_context(GTK_WIDGET(hrow)), "search-disk-header");

        GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_set_margin_top(hbox, 10);
        gtk_widget_set_margin_bottom(hbox, 6);
        gtk_widget_set_margin_start(hbox, 12);
        gtk_widget_set_margin_end(hbox, 12);

        GtkWidget *hname = gtk_label_new(disp);
        gtk_style_context_add_class(gtk_widget_get_style_context(hname), "disk-header-name");
        gtk_label_set_xalign(GTK_LABEL(hname), 0.0);
        gtk_box_pack_start(GTK_BOX(hbox), hname, FALSE, FALSE, 0);

        char summary[128];
        snprintf(summary, sizeof(summary), "%s · %s · %s",
            e->type ? e->type : "?",
            e->size ? e->size : "?",
            e->cipher ? e->cipher : "?");
        GtkWidget *hsum = gtk_label_new(summary);
        gtk_style_context_add_class(gtk_widget_get_style_context(hsum), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(hsum), 0.0);
        gtk_box_pack_start(GTK_BOX(hbox), hsum, TRUE, TRUE, 0);

        char cntbuf[48];
        snprintf(cntbuf, sizeof(cntbuf), "%d", match_count);
        GtkWidget *hcnt = gtk_label_new(cntbuf);
        gtk_style_context_add_class(gtk_widget_get_style_context(hcnt), "disk-header-count");
        gtk_box_pack_end(GTK_BOX(hbox), hcnt, FALSE, FALSE, 0);

        gtk_container_add(GTK_CONTAINER(hrow), hbox);
        g_object_set_data(G_OBJECT(hrow), "entry_idx", GINT_TO_POINTER(i));
        gtk_list_box_insert(lb, hrow, -1);

        int show_n = (int)paths->len;
        for (int k = 0; k < show_n; k++) {
            const char *path = g_ptr_array_index(paths, k);
            long long sz = g_array_index(sizes, long long, k);
            const char *base = strrchr(path, '/');
            base = base ? base + 1 : path;

            GtkWidget *frow = gtk_list_box_row_new();
            gtk_style_context_add_class(gtk_widget_get_style_context(GTK_WIDGET(frow)), "search-file-row");

            GtkWidget *fbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
            gtk_widget_set_margin_top(fbox, 5);
            gtk_widget_set_margin_bottom(fbox, 5);
            gtk_widget_set_margin_start(fbox, 30);
            gtk_widget_set_margin_end(fbox, 12);

            GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
            gtk_widget_set_hexpand(vbox, TRUE);

            GtkWidget *fname = gtk_label_new(base);
            gtk_style_context_add_class(gtk_widget_get_style_context(fname), "file-name");
            gtk_label_set_xalign(GTK_LABEL(fname), 0.0);
            gtk_label_set_ellipsize(GTK_LABEL(fname), PANGO_ELLIPSIZE_END);
            gtk_box_pack_start(GTK_BOX(vbox), fname, FALSE, FALSE, 0);

            char *dirname = g_path_get_dirname(path);
            GtkWidget *fpath = gtk_label_new(dirname);
            gtk_style_context_add_class(gtk_widget_get_style_context(fpath), "file-path");
            gtk_label_set_xalign(GTK_LABEL(fpath), 0.0);
            gtk_label_set_ellipsize(GTK_LABEL(fpath), PANGO_ELLIPSIZE_MIDDLE);
            gtk_box_pack_start(GTK_BOX(vbox), fpath, FALSE, FALSE, 0);
            g_free(dirname);

            if (cross_index) {
                GList *also = g_hash_table_lookup(cross_index, path);
                if (also) {
                    GString *gs = g_string_new(i18n("also_on"));
                    g_string_append_c(gs, ' ');
                    for (GList *qq = also; qq; qq = qq->next) {
                        if (qq != also) g_string_append(gs, ", ");
                        g_string_append(gs, (const char *)qq->data);
                    }
                    GtkWidget *ext = gtk_label_new(gs->str);
                    g_string_free(gs, TRUE);
                    gtk_style_context_add_class(gtk_widget_get_style_context(ext), "also-on");
                    gtk_label_set_xalign(GTK_LABEL(ext), 0.0);
                    gtk_label_set_ellipsize(GTK_LABEL(ext), PANGO_ELLIPSIZE_END);
                    gtk_box_pack_start(GTK_BOX(vbox), ext, FALSE, FALSE, 0);
                }
            }

            gtk_box_pack_start(GTK_BOX(fbox), vbox, TRUE, TRUE, 0);

            char *szstr = format_bytes(sz);
            GtkWidget *fsize = gtk_label_new(szstr);
            gtk_style_context_add_class(gtk_widget_get_style_context(fsize), "file-size");
            gtk_box_pack_end(GTK_BOX(fbox), fsize, FALSE, FALSE, 0);
            g_free(szstr);

            gtk_container_add(GTK_CONTAINER(frow), fbox);

            char *full_path = g_strdup_printf("/%s", path);
            g_object_set_data_full(G_OBJECT(frow), "full_path", full_path, g_free);
            g_object_set_data(G_OBJECT(frow), "entry_idx", GINT_TO_POINTER(i));
            g_signal_connect(frow, "button-press-event", G_CALLBACK(on_search_file_click), NULL);

            gtk_list_box_insert(lb, frow, -1);
        }

        if (match_count > show_n) {
            char more[64];
            snprintf(more, sizeof(more), "+ %d...", match_count - show_n);
            GtkWidget *mrow = gtk_list_box_row_new();
            gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(mrow), FALSE);
            gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(mrow), FALSE);
            GtkWidget *mlbl = gtk_label_new(more);
            gtk_style_context_add_class(gtk_widget_get_style_context(mlbl), "dim-label");
            gtk_widget_set_margin_start(mlbl, 40);
            gtk_widget_set_margin_top(mlbl, 3);
            gtk_widget_set_margin_bottom(mlbl, 6);
            gtk_label_set_xalign(GTK_LABEL(mlbl), 0.0);
            gtk_container_add(GTK_CONTAINER(mrow), mlbl);
            gtk_list_box_insert(lb, mrow, -1);
        }

        g_ptr_array_free(paths, TRUE);
        g_array_free(sizes, TRUE);
    }

    if (status) {
        if (total_files == 0) {
            gtk_label_set_text(GTK_LABEL(status), i18n("no_results"));
        } else {
            char buf[128];
            snprintf(buf, sizeof(buf), "%d %s · %d %s",
                total_files, i18n("files_found"), total_disks, i18n("disks_found"));
            gtk_label_set_text(GTK_LABEL(status), buf);
        }
    }
    gtk_widget_show_all(GTK_WIDGET(lb));
}

static gboolean on_find_debounce_cb(gpointer data) {
    GtkSearchEntry *se = GTK_SEARCH_ENTRY(data);
    g_object_set_data(G_OBJECT(se), "find_timeout_id", GUINT_TO_POINTER(0));
    on_find_changed_now(se);
    return G_SOURCE_REMOVE;
}

static void cancel_find_debounce(GtkSearchEntry *se) {
    guint id = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(se), "find_timeout_id"));
    if (id) {
        g_source_remove(id);
        g_object_set_data(G_OBJECT(se), "find_timeout_id", GUINT_TO_POINTER(0));
    }
}

static void on_find_changed(GtkSearchEntry *se, gpointer user_data) {
    (void)user_data;
    cancel_find_debounce(se);
    guint id = g_timeout_add_full(G_PRIORITY_DEFAULT, 160, on_find_debounce_cb,
        g_object_ref(se), (GDestroyNotify)g_object_unref);
    g_object_set_data(G_OBJECT(se), "find_timeout_id", GUINT_TO_POINTER(id));
}

static void on_find_changed_immediate(GtkSearchEntry *se) {
    cancel_find_debounce(se);
    on_find_changed_now(se);
}

static void on_find_search_destroy(GtkWidget *w, gpointer user_data) {
    (void)user_data;
    cancel_find_debounce(GTK_SEARCH_ENTRY(w));
}

static void rebuild_filt_box(GtkBox *filt_box, GtkSearchEntry *se, db_manager_t *db) {
    GList *ch = gtk_container_get_children(GTK_CONTAINER(filt_box));
    for (GList *l = ch; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(ch);

    int active_idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(se), "filter_idx"));

    GtkWidget *star = gtk_toggle_button_new_with_label("*");
    gtk_style_context_add_class(gtk_widget_get_style_context(star), "filter-chip");
    g_object_set_data(G_OBJECT(star), "filter_idx", GINT_TO_POINTER(-1));
    g_signal_connect(star, "clicked", G_CALLBACK(on_filter_chip_clicked), se);
    if (active_idx < 0) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(star), TRUE);
    gtk_box_pack_start(GTK_BOX(filt_box), star, FALSE, FALSE, 0);

    for (int i = 0; i < db->filter_count; i++) {
        GtkWidget *b = gtk_toggle_button_new_with_label(db->filters[i].name);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "filter-chip");
        g_object_set_data(G_OBJECT(b), "filter_idx", GINT_TO_POINTER(i));
        gulong click_handler_id =
            g_signal_connect(b, "clicked", G_CALLBACK(on_filter_chip_clicked), se);
        g_object_set_data(G_OBJECT(b), "filter-click-handler-id",
            GSIZE_TO_POINTER((gsize)click_handler_id));
        g_signal_connect(b, "button-press-event", G_CALLBACK(on_filter_chip_press), se);
        if (i == active_idx) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(b), TRUE);
        gtk_box_pack_start(GTK_BOX(filt_box), b, FALSE, FALSE, 0);
    }

    GtkWidget *add_btn = gtk_button_new_with_label("+");
    gtk_style_context_add_class(gtk_widget_get_style_context(add_btn), "filter-chip");
    g_signal_connect(add_btn, "clicked", G_CALLBACK(on_filter_add_clicked), se);
    gtk_box_pack_start(GTK_BOX(filt_box), add_btn, FALSE, FALSE, 0);

    gtk_widget_show_all(GTK_WIDGET(filt_box));
}

static void on_filter_chip_clicked(GtkToggleButton *btn, gpointer user_data) {
    GtkSearchEntry *se = GTK_SEARCH_ENTRY(user_data);
    GtkWidget *filt_box = g_object_get_data(G_OBJECT(se), "filt_box");

    gboolean want_active = gtk_toggle_button_get_active(btn);

    GList *ch = gtk_container_get_children(GTK_CONTAINER(filt_box));
    for (GList *l = ch; l; l = l->next) {
        GtkWidget *w = l->data;
        if (w == GTK_WIDGET(btn)) continue;
        if (GTK_IS_TOGGLE_BUTTON(w)) {
            gulong handler_id = (gulong)GPOINTER_TO_SIZE(
                g_object_get_data(G_OBJECT(w), "filter-click-handler-id"));
            if (handler_id) g_signal_handler_block(w, handler_id);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), FALSE);
            if (handler_id) g_signal_handler_unblock(w, handler_id);
        }
    }
    g_list_free(ch);

    int idx = -1;
    if (want_active)
        idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(btn), "filter_idx"));
    g_object_set_data(G_OBJECT(se), "filter_idx", GINT_TO_POINTER(idx));

    on_find_changed_immediate(se);
}

static void on_filter_delete_activate(GtkMenuItem *mi, gpointer user_data) {
    GtkSearchEntry *se = GTK_SEARCH_ENTRY(user_data);
    db_manager_t *db = g_object_get_data(G_OBJECT(se), "db");
    GtkWidget *filt_box = g_object_get_data(G_OBJECT(se), "filt_box");
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(mi), "filter_idx"));
    if (!db || idx < 0 || idx >= db->filter_count) return;

    search_filter_t removed = db->filters[idx];
    memmove(&db->filters[idx], &db->filters[idx+1],
        (db->filter_count - idx - 1) * sizeof(search_filter_t));
    db->filter_count--;

    char err_buf[256] = "";
    if (db_save(db, err_buf, sizeof(err_buf)) != 0) {
        memmove(&db->filters[idx + 1], &db->filters[idx],
            (db->filter_count - idx) * sizeof(search_filter_t));
        db->filters[idx] = removed;
        db->filter_count++;
        show_save_error(err_buf);
        return;
    }
    secure_free_string(&removed.name);
    secure_free_string(&removed.exts);

    int active = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(se), "filter_idx"));
    if (active == idx) {
        g_object_set_data(G_OBJECT(se), "filter_idx", GINT_TO_POINTER(-1));
    } else if (active > idx) {
        g_object_set_data(G_OBJECT(se), "filter_idx", GINT_TO_POINTER(active - 1));
    }

    rebuild_filt_box(GTK_BOX(filt_box), se, db);
    on_find_changed_immediate(se);
}

static gboolean on_filter_chip_press(GtkWidget *w, GdkEventButton *ev, gpointer user_data) {
    if (ev->button != 3) return FALSE;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "filter_idx"));
    if (idx < 0) return TRUE;

    GtkWidget *menu = gtk_menu_new();
    g_signal_connect_swapped(menu, "selection-done", G_CALLBACK(gtk_widget_destroy), menu);
    GtkWidget *mi = gtk_menu_item_new_with_label(i18n("filter_delete"));
    g_object_set_data(G_OBJECT(mi), "filter_idx", GINT_TO_POINTER(idx));
    g_signal_connect(mi, "activate", G_CALLBACK(on_filter_delete_activate), user_data);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);
    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent*)ev);
    return TRUE;
}

static void on_filter_add_clicked(GtkButton *b, gpointer user_data) {
    (void)b;
    GtkSearchEntry *se = GTK_SEARCH_ENTRY(user_data);
    db_manager_t *db = g_object_get_data(G_OBJECT(se), "db");
    if (!db) return;

    GtkWidget *top = gtk_widget_get_toplevel(GTK_WIDGET(se));
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("filter_add"),
        GTK_IS_WINDOW(top) ? GTK_WINDOW(top) : NULL,
        GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("save"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 380, 200);
    install_dialog_title(GTK_WINDOW(dlg), i18n("filter_add"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 10);

    GtkGrid *g = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(g, 10);
    gtk_grid_set_row_spacing(g, 10);

    gtk_grid_attach(g, gtk_label_new(i18n("filter_name")), 0, 0, 1, 1);
    GtkWidget *name_e = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(name_e), "PDF");
    gtk_widget_set_hexpand(name_e, TRUE);
    gtk_grid_attach(g, name_e, 1, 0, 1, 1);

    gtk_grid_attach(g, gtk_label_new(i18n("filter_exts")), 0, 1, 1, 1);
    GtkWidget *exts_e = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(exts_e), "pdf,doc,docx");
    gtk_widget_set_hexpand(exts_e, TRUE);
    gtk_grid_attach(g, exts_e, 1, 1, 1, 1);

    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(g), TRUE, TRUE, 0);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *nm = gtk_entry_get_text(GTK_ENTRY(name_e));
        const char *ex = gtk_entry_get_text(GTK_ENTRY(exts_e));
        if (nm && nm[0] && ex && ex[0] && db->filter_count < DB_MAX_FILTERS) {
            if (db->filter_count >= db->filter_cap) {
                int new_cap = db->filter_cap ? db->filter_cap * 2 : 8;
                if (new_cap > DB_MAX_FILTERS) new_cap = DB_MAX_FILTERS;
                search_filter_t *tmp = realloc(db->filters, (size_t)new_cap * sizeof(search_filter_t));
                if (!tmp) {
                    gtk_widget_destroy(dlg);
                    return;
                }
                db->filters = tmp;
                db->filter_cap = new_cap;
            }
            db->filters[db->filter_count].name = xstrdup(nm);
            db->filters[db->filter_count].exts = xstrdup(ex);
            db->filter_count++;
            char err_buf[256] = "";
            if (db_save(db, err_buf, sizeof(err_buf)) != 0) {
                db->filter_count--;
                secure_free_string(&db->filters[db->filter_count].name);
                secure_free_string(&db->filters[db->filter_count].exts);
                show_save_error(err_buf);
            } else {
                GtkWidget *filt_box = g_object_get_data(G_OBJECT(se), "filt_box");
                rebuild_filt_box(GTK_BOX(filt_box), se, db);
            }
        }
    }
    gtk_widget_destroy(dlg);
}

static void on_find_file_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;

    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        i18n("find_title"), g_app.window, GTK_DIALOG_MODAL,
        i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 780, 620);
    install_dialog_title(GTK_WINDOW(dlg), i18n("find_title"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 12);
    gtk_box_set_spacing(GTK_BOX(content), 8);

    GtkWidget *se = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(se), i18n("find_hint"));
    gtk_box_pack_start(GTK_BOX(content), se, FALSE, FALSE, 0);

    GtkWidget *filt_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(filt_scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_NEVER);
    gtk_widget_set_size_request(filt_scroll, -1, 38);

    GtkWidget *filt_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_style_context_add_class(gtk_widget_get_style_context(filt_box), "search-filters");
    gtk_container_add(GTK_CONTAINER(filt_scroll), filt_box);
    gtk_box_pack_start(GTK_BOX(content), filt_scroll, FALSE, FALSE, 0);

    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(sw, TRUE);
    GtkWidget *lb = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(lb), GTK_SELECTION_NONE);
    gtk_container_add(GTK_CONTAINER(sw), lb);
    gtk_box_pack_start(GTK_BOX(content), sw, TRUE, TRUE, 0);

    GtkWidget *status_lbl = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(status_lbl), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(status_lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(content), status_lbl, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(se), "listbox", lb);
    g_object_set_data(G_OBJECT(se), "db", g_app.db);
    g_object_set_data(G_OBJECT(se), "status", status_lbl);
    g_object_set_data(G_OBJECT(se), "filt_box", filt_box);
    g_object_set_data(G_OBJECT(se), "filter_idx", GINT_TO_POINTER(-1));
    g_signal_connect(se, "search-changed", G_CALLBACK(on_find_changed), NULL);
    g_signal_connect(se, "destroy", G_CALLBACK(on_find_search_destroy), NULL);

    rebuild_filt_box(GTK_BOX(filt_box), GTK_SEARCH_ENTRY(se), g_app.db);

    int indexed = 0;
    for (int i = 0; i < g_app.db->entry_count; i++)
        if (g_app.db->entries[i].files && g_app.db->entries[i].files[0]) indexed++;
    if (indexed == 0) {
        gtk_label_set_text(GTK_LABEL(status_lbl), i18n("empty_index"));
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "%d %s", indexed, i18n("disks_with_index"));
        gtk_label_set_text(GTK_LABEL(status_lbl), buf);
    }

    gtk_widget_show_all(dlg);
    gtk_widget_grab_focus(se);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static void on_lang_changed_welcome(GtkComboBoxText *combo, gpointer user_data) {
    (void)user_data;
    gchar *id = (gchar*)gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
    if (id && strcmp(id, g_lang) != 0 && i18n_set_language(id)) {
        if (g_app.lang_combo && GTK_WIDGET(combo) != g_app.lang_combo)
            gtk_combo_box_set_active_id(GTK_COMBO_BOX(g_app.lang_combo), g_lang);
        if (g_app.lang_combo_welcome && GTK_WIDGET(combo) != g_app.lang_combo_welcome)
            gtk_combo_box_set_active_id(GTK_COMBO_BOX(g_app.lang_combo_welcome), g_lang);
        update_ui_text();
        save_config();
    }
}

static void build_welcome(void) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(box, 40); gtk_widget_set_margin_end(box, 40);
    GtkWidget *img = make_icon_img(72);
    gtk_box_pack_start(GTK_BOX(box), img, FALSE, FALSE, 0);
    g_app.welcome_title = gtk_label_new("DiskPass");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.welcome_title), "welcome-title");
    gtk_box_pack_start(GTK_BOX(box), g_app.welcome_title, FALSE, FALSE, 0);
    g_app.welcome_desc = gtk_label_new(i18n("app_desc"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.welcome_desc), "dim-label");
    gtk_box_pack_start(GTK_BOX(box), g_app.welcome_desc, FALSE, FALSE, 0);
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(btn_box, 18);
    g_app.btn_open = gtk_button_new_with_label(i18n("open_db"));
    g_signal_connect(g_app.btn_open, "clicked", G_CALLBACK(on_open_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_open, FALSE, FALSE, 0);
    g_app.btn_create = gtk_button_new_with_label(i18n("create_db"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_create), "suggested-action");
    g_signal_connect(g_app.btn_create, "clicked", G_CALLBACK(on_create_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_create, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_box, FALSE, FALSE, 0);
    GtkWidget *lang_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_margin_top(lang_box, 20);
    g_app.lbl_lang_welcome = gtk_label_new(i18n("language"));
    gtk_box_pack_start(GTK_BOX(lang_box), g_app.lbl_lang_welcome, FALSE, FALSE, 0);
    g_app.lang_combo_welcome = gtk_combo_box_text_new();
    i18n_populate_combo(GTK_COMBO_BOX_TEXT(g_app.lang_combo_welcome));
    g_signal_connect(g_app.lang_combo_welcome, "changed", G_CALLBACK(on_lang_changed_welcome), NULL);
    gtk_box_pack_start(GTK_BOX(lang_box), g_app.lang_combo_welcome, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lang_box, FALSE, FALSE, 0);
    gtk_stack_add_named(g_app.stack, box, "welcome");
}

static void build_setup(void) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER); gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(box, 40); gtk_widget_set_margin_end(box, 40);
    g_app.setup_title = gtk_label_new(i18n("setup_title"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.setup_title), "welcome-title");
    gtk_box_pack_start(GTK_BOX(box), g_app.setup_title, FALSE, FALSE, 0);
    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 10); gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_margin_top(GTK_WIDGET(grid), 15);
    g_app.lbl_setup_file = gtk_label_new(i18n("db_file"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_setup_file), 1.0);
    gtk_grid_attach(grid, g_app.lbl_setup_file, 0, 0, 1, 1);
    g_app.setup_file_label = gtk_label_new(i18n("not_selected"));
    gtk_label_set_xalign(GTK_LABEL(g_app.setup_file_label), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(g_app.setup_file_label), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(g_app.setup_file_label, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.setup_file_label), "dim-label");
    gtk_grid_attach(grid, g_app.setup_file_label, 1, 0, 1, 1);
    g_app.lbl_setup_key = gtk_label_new(i18n("pgp_key"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_setup_key), 1.0);
    gtk_grid_attach(grid, g_app.lbl_setup_key, 0, 1, 1, 1);
    GtkWidget *setup_key_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(setup_key_row), "key-row");
    g_app.key_combo = gtk_combo_box_text_new();
    gtk_widget_set_size_request(g_app.key_combo, 300, -1); gtk_widget_set_hexpand(g_app.key_combo, TRUE);
    gtk_box_pack_start(GTK_BOX(setup_key_row), g_app.key_combo, TRUE, TRUE, 0);
    g_app.btn_create_key_setup = gtk_button_new_from_icon_name("list-add-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(g_app.btn_create_key_setup, i18n("create_key"));
    g_signal_connect(g_app.btn_create_key_setup, "clicked", G_CALLBACK(on_create_gpg_key_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(setup_key_row), g_app.btn_create_key_setup, FALSE, FALSE, 0);
    gtk_grid_attach(grid, setup_key_row, 1, 1, 1, 1);
    g_app.lbl_setup_lang = gtk_label_new(i18n("language"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_setup_lang), 1.0);
    gtk_grid_attach(grid, g_app.lbl_setup_lang, 0, 2, 1, 1);
    g_app.lang_combo = gtk_combo_box_text_new();
    i18n_populate_combo(GTK_COMBO_BOX_TEXT(g_app.lang_combo));
    g_signal_connect(g_app.lang_combo, "changed", G_CALLBACK(on_lang_changed_welcome), NULL);
    gtk_grid_attach(grid, g_app.lang_combo, 1, 2, 1, 1);
    gtk_box_pack_start(GTK_BOX(box), GTK_WIDGET(grid), FALSE, TRUE, 0);
    g_app.setup_err = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.setup_err), "error");
    gtk_box_pack_start(GTK_BOX(box), g_app.setup_err, FALSE, FALSE, 0);
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_top(btn_box, 8);
    g_app.btn_setup_back = gtk_button_new_with_label(i18n("back"));
    g_signal_connect(g_app.btn_setup_back, "clicked", G_CALLBACK(on_back_to_welcome), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_setup_back, FALSE, FALSE, 0);
    g_app.btn_setup_create = gtk_button_new_with_label(i18n("create_btn"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_setup_create), "suggested-action");
    g_signal_connect(g_app.btn_setup_create, "clicked", G_CALLBACK(on_setup_create_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_setup_create, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_box, FALSE, FALSE, 0);
    gtk_stack_add_named(g_app.stack, box, "setup");
}

static void build_unlock(void) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER); gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(box, 40); gtk_widget_set_margin_end(box, 40);
    g_app.unlock_title = gtk_label_new(i18n("locked_title"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.unlock_title), "welcome-title");
    gtk_box_pack_start(GTK_BOX(box), g_app.unlock_title, FALSE, FALSE, 0);
    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 10); gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_margin_top(GTK_WIDGET(grid), 15);
    g_app.lbl_unlock_file = gtk_label_new(i18n("file"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_unlock_file), 1.0);
    gtk_grid_attach(grid, g_app.lbl_unlock_file, 0, 0, 1, 1);
    g_app.unlock_file_label = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(g_app.unlock_file_label), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(g_app.unlock_file_label), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(g_app.unlock_file_label, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.unlock_file_label), "dim-label");
    gtk_grid_attach(grid, g_app.unlock_file_label, 1, 0, 1, 1);
    g_app.lbl_unlock_key = gtk_label_new(i18n("pgp_key"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_unlock_key), 1.0);
    gtk_grid_attach(grid, g_app.lbl_unlock_key, 0, 1, 1, 1);
    GtkWidget *unlock_key_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(unlock_key_row), "key-row");
    g_app.unlock_key_combo = gtk_combo_box_text_new();
    gtk_widget_set_size_request(g_app.unlock_key_combo, 300, -1); gtk_widget_set_hexpand(g_app.unlock_key_combo, TRUE);
    gtk_box_pack_start(GTK_BOX(unlock_key_row), g_app.unlock_key_combo, TRUE, TRUE, 0);
    g_app.btn_create_key_unlock = gtk_button_new_from_icon_name("list-add-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(g_app.btn_create_key_unlock, i18n("create_key"));
    g_signal_connect(g_app.btn_create_key_unlock, "clicked", G_CALLBACK(on_create_gpg_key_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(unlock_key_row), g_app.btn_create_key_unlock, FALSE, FALSE, 0);
    gtk_grid_attach(grid, unlock_key_row, 1, 1, 1, 1);
    gtk_box_pack_start(GTK_BOX(box), GTK_WIDGET(grid), FALSE, TRUE, 0);
    g_app.unlock_err = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.unlock_err), "error");
    gtk_box_pack_start(GTK_BOX(box), g_app.unlock_err, FALSE, FALSE, 0);
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_top(btn_box, 8);
    g_app.btn_unlock_back = gtk_button_new_with_label(i18n("back"));
    g_signal_connect(g_app.btn_unlock_back, "clicked", G_CALLBACK(on_back_to_welcome), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_unlock_back, FALSE, FALSE, 0);
    g_app.btn_unlock = gtk_button_new_with_label(i18n("unlock_btn"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_unlock), "suggested-action");
    GtkWidget *unlock_img = make_icon_img(24);
    gtk_button_set_image(GTK_BUTTON(g_app.btn_unlock), unlock_img);
    gtk_button_set_always_show_image(GTK_BUTTON(g_app.btn_unlock), TRUE);
    g_signal_connect(g_app.btn_unlock, "clicked", G_CALLBACK(on_unlock_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_unlock, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_box, FALSE, FALSE, 0);
    gtk_stack_add_named(g_app.stack, box, "unlock");
}

static gboolean toast_hide_cb(gpointer u) {
    (void)u;
    if (g_app.toast_revealer)
        gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);
    g_toast_timer_id = 0;
    return G_SOURCE_REMOVE;
}

static void show_toast(const char *text, int duration_ms, int entry_idx) {
    if (!g_app.toast_revealer || !g_app.toast_label) return;
    g_app.toast_entry_idx = entry_idx;
    gtk_label_set_text(GTK_LABEL(g_app.toast_label), text);
    gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), TRUE);
    if (g_toast_timer_id) g_source_remove(g_toast_timer_id);
    g_toast_timer_id = g_timeout_add(duration_ms, toast_hide_cb, NULL);
}

static gboolean plugin_status_hide_cb(gpointer user_data) {
    (void)user_data;
    g_plugin_status_timer_id = 0;
    if (g_app.plugin_status) {
        gtk_label_set_text(GTK_LABEL(g_app.plugin_status), "");
        gtk_widget_hide(g_app.plugin_status);
    }
    return G_SOURCE_REMOVE;
}

char *diskpass_ui_dup_selected_disk_label(void) {
    if (!g_app.db || g_app.current_entry_idx < 0 ||
        g_app.current_entry_idx >= g_app.db->entry_count)
        return NULL;
    const char *label = g_app.db->entries[g_app.current_entry_idx].label;
    return (label && label[0]) ? g_strdup(label) : NULL;
}

void diskpass_ui_set_plugin_status(const char *text, guint timeout_ms) {
    if (g_plugin_status_timer_id) {
        g_source_remove(g_plugin_status_timer_id);
        g_plugin_status_timer_id = 0;
    }
    if (!g_app.plugin_status) return;
    if (!text || !text[0]) {
        gtk_label_set_text(GTK_LABEL(g_app.plugin_status), "");
        gtk_widget_hide(g_app.plugin_status);
        return;
    }
    gtk_label_set_text(GTK_LABEL(g_app.plugin_status), text);
    gtk_widget_set_tooltip_text(g_app.plugin_status, text);
    gtk_widget_show(g_app.plugin_status);
    if (timeout_ms > 0)
        g_plugin_status_timer_id = g_timeout_add(timeout_ms, plugin_status_hide_cb, NULL);
}

static gboolean on_toast_clicked(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    int idx = g_app.toast_entry_idx;
    if (g_app.toast_revealer)
        gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);
    if (idx >= 0 && g_app.db && idx < g_app.db->entry_count) {
        GtkListBoxRow *row = gtk_list_box_get_row_at_index(g_app.listbox, idx);
        if (row) {
            gtk_list_box_select_row(g_app.listbox, row);
            gtk_widget_grab_focus(GTK_WIDGET(g_app.listbox));
        }
    }
    return TRUE;
}

static void check_new_disks(void) {
    if (!g_app.db) return;
    int n = 0;
    disk_info_t *disks = list_disks(&n);
    if (!disks) return;

    if (!g_known_uuids)
        g_known_uuids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    for (int i = 0; i < n; i++) {
        if (!disks[i].uuid) continue;
        if (g_hash_table_contains(g_known_uuids, disks[i].uuid)) continue;
        g_hash_table_add(g_known_uuids, g_strdup(disks[i].uuid));

        if (!g_uuids_initialized) continue;

        for (int j = 0; j < g_app.db->entry_count; j++) {
            db_entry_t *e = &g_app.db->entries[j];
            if (e->uuid && strcmp(e->uuid, disks[i].uuid) == 0) {
                char msg[512];
                const char *disp = (e->alias && e->alias[0]) ? e->alias : e->label;
                snprintf(msg, sizeof(msg), "%s — %s  ·  %s",
                    i18n("disk_detected"), disp,
                    disks[i].mountpoint ? disks[i].mountpoint : "?");
                show_toast(msg, 8000, j);
                break;
            }
        }
    }
    free_disk_list(disks, n);
    g_uuids_initialized = TRUE;
}

static gboolean connection_check_cb(gpointer user_data) {
    (void)user_data;
    check_new_disks();
    return G_SOURCE_CONTINUE;
}

static void build_main(void) {
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_style_context_add_class(gtk_widget_get_style_context(toolbar), "main-toolbar");
    gtk_widget_set_margin_top(toolbar, 4); gtk_widget_set_margin_bottom(toolbar, 4);
    gtk_widget_set_margin_start(toolbar, 6); gtk_widget_set_margin_end(toolbar, 6);

    g_app.btn_lock = gtk_button_new_from_icon_name("changes-prevent-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_lock), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_lock, i18n("lock_db"));
    g_signal_connect(g_app.btn_lock, "clicked", G_CALLBACK(on_lock_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_lock, FALSE, FALSE, 0);

    GtkWidget *sep1 = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
    gtk_widget_set_margin_start(sep1, 4); gtk_widget_set_margin_end(sep1, 4);
    gtk_box_pack_start(GTK_BOX(toolbar), sep1, FALSE, FALSE, 0);

    g_app.btn_add = gtk_button_new_from_icon_name("list-add-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_add), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_add, i18n("add_entry"));
    g_signal_connect(g_app.btn_add, "clicked", G_CALLBACK(on_add_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_add, FALSE, FALSE, 0);

    g_app.btn_edit = gtk_button_new_from_icon_name("document-edit-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_edit), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_edit, i18n("edit_entry"));
    g_signal_connect(g_app.btn_edit, "clicked", G_CALLBACK(on_edit_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_edit, FALSE, FALSE, 0);

    g_app.btn_del = gtk_button_new_from_icon_name("edit-delete-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_del), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_del, i18n("del_entry"));
    g_signal_connect(g_app.btn_del, "clicked", G_CALLBACK(on_delete_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_del, FALSE, FALSE, 0);

    GtkWidget *sep2 = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
    gtk_widget_set_margin_start(sep2, 4); gtk_widget_set_margin_end(sep2, 4);
    gtk_box_pack_start(GTK_BOX(toolbar), sep2, FALSE, FALSE, 0);

    g_app.btn_snapshot = gtk_button_new_from_icon_name("drive-harddisk-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_snapshot), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_snapshot, i18n("snapshot_btn"));
    g_signal_connect(g_app.btn_snapshot, "clicked", G_CALLBACK(on_attach_snapshot_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_snapshot, FALSE, FALSE, 0);

    g_app.btn_find = gtk_button_new_from_icon_name("system-search-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_find), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_find, i18n("find_btn"));
    g_signal_connect(g_app.btn_find, "clicked", G_CALLBACK(on_find_file_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_find, FALSE, FALSE, 0);

    g_app.btn_batch = gtk_button_new_from_icon_name("view-refresh-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_batch), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_batch, i18n("batch_reindex"));
    g_signal_connect(g_app.btn_batch, "clicked", G_CALLBACK(on_batch_reindex_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_batch, FALSE, FALSE, 0);

    g_app.btn_refresh = gtk_button_new_from_icon_name("emblem-synchronizing-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_refresh), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_refresh, i18n("refresh_connections"));
    g_signal_connect(g_app.btn_refresh, "clicked", G_CALLBACK(on_refresh_connections_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_refresh, FALSE, FALSE, 0);

    g_app.btn_smart = gtk_button_new_from_icon_name("drive-harddisk-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_smart), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_smart, i18n("smart_refresh"));
    g_signal_connect(g_app.btn_smart, "clicked", G_CALLBACK(on_refresh_smart_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_smart, FALSE, FALSE, 0);

    g_app.btn_rekey = gtk_button_new_from_icon_name("dialog-password-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_rekey), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_rekey, i18n("change_key"));
    g_signal_connect(g_app.btn_rekey, "clicked", G_CALLBACK(on_change_key_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_rekey, FALSE, FALSE, 0);

    g_app.btn_create_key_main = gtk_button_new_from_icon_name("list-add-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_create_key_main), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_create_key_main, i18n("create_key"));
    g_signal_connect(g_app.btn_create_key_main, "clicked", G_CALLBACK(on_create_gpg_key_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_create_key_main, FALSE, FALSE, 0);

    g_app.btn_plugins = diskpass_plugins_create_button();
    if (g_app.btn_plugins) {
        gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_plugins), "flat-btn");
        gtk_widget_set_tooltip_text(g_app.btn_plugins, i18n("plugins"));
        gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_plugins, FALSE, FALSE, 0);
    }

    g_app.security_badge = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.security_badge), "security-badge");
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.security_badge, FALSE, FALSE, 4);
    update_security_badge();

    g_app.plugin_status = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.plugin_status), "plugin-status");
    gtk_label_set_ellipsize(GTK_LABEL(g_app.plugin_status), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(g_app.plugin_status), 0.0f);
    gtk_widget_set_size_request(g_app.plugin_status, 180, -1);
    gtk_widget_set_no_show_all(g_app.plugin_status, TRUE);
    gtk_widget_hide(g_app.plugin_status);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.plugin_status, TRUE, TRUE, 8);

    gtk_box_pack_start(GTK_BOX(toolbar), gtk_label_new(""), TRUE, TRUE, 0);

    g_app.btn_sch = gtk_button_new_from_icon_name("dialog-information-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_sch), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_sch, i18n("show_schema"));
    g_signal_connect(g_app.btn_sch, "clicked", G_CALLBACK(on_schema_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(toolbar), g_app.btn_sch, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(main_box), toolbar, FALSE, FALSE, 0);

    g_app.toast_revealer = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(g_app.toast_revealer),
        GTK_REVEALER_TRANSITION_TYPE_SLIDE_DOWN);
    gtk_revealer_set_transition_duration(GTK_REVEALER(g_app.toast_revealer), 250);
    gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);

    GtkWidget *toast_btn = gtk_button_new();
    gtk_button_set_relief(GTK_BUTTON(toast_btn), GTK_RELIEF_NONE);
    gtk_style_context_add_class(gtk_widget_get_style_context(toast_btn), "toast");

    g_app.toast_label = gtk_label_new("");
    gtk_label_set_ellipsize(GTK_LABEL(g_app.toast_label), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(g_app.toast_label), 0.0);
    gtk_widget_set_margin_start(g_app.toast_label, 12);
    gtk_widget_set_margin_end(g_app.toast_label, 12);
    gtk_widget_set_margin_top(g_app.toast_label, 8);
    gtk_widget_set_margin_bottom(g_app.toast_label, 8);
    gtk_container_add(GTK_CONTAINER(toast_btn), g_app.toast_label);

    g_signal_connect(toast_btn, "clicked", G_CALLBACK(on_toast_clicked), NULL);
    gtk_container_add(GTK_CONTAINER(g_app.toast_revealer), toast_btn);

    gtk_box_pack_start(GTK_BOX(main_box), g_app.toast_revealer, FALSE, FALSE, 0);

    g_app.toast_entry_idx = -1;

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 300);
    gtk_paned_set_wide_handle(GTK_PANED(paned), FALSE);

    GtkWidget *left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *search_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(search_box), "sidebar");
    gtk_widget_set_margin_top(search_box, 8); gtk_widget_set_margin_bottom(search_box, 8);
    gtk_widget_set_margin_start(search_box, 8); gtk_widget_set_margin_end(search_box, 8);
    g_app.search = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.search), i18n("search"));
    g_signal_connect(g_app.search, "search-changed", G_CALLBACK(on_search_changed), NULL);
    gtk_box_pack_start(GTK_BOX(search_box), g_app.search, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(left_box), search_box, FALSE, FALSE, 0);

    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(sw, TRUE);
    g_app.listbox = GTK_LIST_BOX(gtk_list_box_new());
    gtk_list_box_set_selection_mode(g_app.listbox, GTK_SELECTION_SINGLE);
    gtk_style_context_add_class(gtk_widget_get_style_context(GTK_WIDGET(g_app.listbox)), "sidebar");
    g_signal_connect(g_app.listbox, "row-selected", G_CALLBACK(on_row_selected), NULL);
    gtk_list_box_set_filter_func(g_app.listbox, filter_func, NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw), GTK_WIDGET(g_app.listbox));
    gtk_box_pack_start(GTK_BOX(left_box), sw, TRUE, TRUE, 0);
    gtk_paned_pack1(GTK_PANED(paned), left_box, TRUE, FALSE);

    GtkWidget *detail_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(detail_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(detail_scroll, TRUE);
    g_app.detail_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(g_app.detail_box, 16); gtk_widget_set_margin_bottom(g_app.detail_box, 16);
    gtk_widget_set_margin_start(g_app.detail_box, 20); gtk_widget_set_margin_end(g_app.detail_box, 20);
    gtk_widget_set_valign(g_app.detail_box, GTK_ALIGN_START);

    GtkWidget *top_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    g_app.lbl_main = gtk_label_new(i18n("select_entry"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.lbl_main), "detail-title");
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_main), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(g_app.lbl_main), PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_set_hexpand(g_app.lbl_main, TRUE);
    gtk_box_pack_start(GTK_BOX(top_box), g_app.lbl_main, TRUE, TRUE, 0);
    g_app.btn_copy_label = gtk_button_new_with_label(i18n("copy_label"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_copy_label), "flat-btn");
    gtk_widget_set_sensitive(g_app.btn_copy_label, FALSE);
    g_signal_connect(g_app.btn_copy_label, "clicked", G_CALLBACK(on_copy_label_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(top_box), g_app.btn_copy_label, FALSE, FALSE, 0);
    g_app.btn_copy_pass = gtk_button_new_with_label(i18n("copy_pass"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_copy_pass), "flat-btn");
    gtk_widget_set_sensitive(g_app.btn_copy_pass, FALSE);
    g_signal_connect(g_app.btn_copy_pass, "clicked", G_CALLBACK(on_copy_pass_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(top_box), g_app.btn_copy_pass, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), top_box, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(g_app.detail_box),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);

    g_app.grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(g_app.grid), 16);
    gtk_grid_set_row_spacing(GTK_GRID(g_app.grid), 6);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.grid, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(g_app.detail_box),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);

    GtkWidget *tree_header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    g_app.tree_summary = gtk_label_new(i18n("no_index_yet"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.tree_summary), "tree-header");
    gtk_label_set_xalign(GTK_LABEL(g_app.tree_summary), 0.0);
    gtk_widget_set_hexpand(g_app.tree_summary, TRUE);
    gtk_box_pack_start(GTK_BOX(tree_header_box), g_app.tree_summary, TRUE, TRUE, 0);

    g_app.tree_expand_btn = gtk_button_new_from_icon_name("zoom-in-symbolic", GTK_ICON_SIZE_MENU);
    gtk_widget_set_tooltip_text(g_app.tree_expand_btn, "Expand");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.tree_expand_btn), "flat-btn");
    g_signal_connect(g_app.tree_expand_btn, "clicked", G_CALLBACK(on_tree_expand_all), NULL);
    gtk_box_pack_end(GTK_BOX(tree_header_box), g_app.tree_expand_btn, FALSE, FALSE, 0);

    g_app.tree_collapse_btn = gtk_button_new_from_icon_name("zoom-out-symbolic", GTK_ICON_SIZE_MENU);
    gtk_widget_set_tooltip_text(g_app.tree_collapse_btn, "Collapse");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.tree_collapse_btn), "flat-btn");
    g_signal_connect(g_app.tree_collapse_btn, "clicked", G_CALLBACK(on_tree_collapse_all), NULL);
    gtk_box_pack_end(GTK_BOX(tree_header_box), g_app.tree_collapse_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(g_app.detail_box), tree_header_box, FALSE, FALSE, 0);

    g_app.tree_filter = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.tree_filter), i18n("search"));
    g_signal_connect(g_app.tree_filter, "search-changed", G_CALLBACK(on_tree_filter_changed), NULL);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.tree_filter, FALSE, FALSE, 0);

    g_app.tree_store = gtk_tree_store_new(3, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_STRING);
    GtkTreeModel *filter_model = gtk_tree_model_filter_new(GTK_TREE_MODEL(g_app.tree_store), NULL);
    gtk_tree_model_filter_set_visible_func(GTK_TREE_MODEL_FILTER(filter_model),
        tree_filter_func, NULL, NULL);

    g_app.tree_view = gtk_tree_view_new_with_model(filter_model);
    g_object_unref(filter_model);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(g_app.tree_view), FALSE);
    gtk_tree_view_set_enable_tree_lines(GTK_TREE_VIEW(g_app.tree_view), TRUE);
    gtk_tree_view_set_show_expanders(GTK_TREE_VIEW(g_app.tree_view), TRUE);
    gtk_tree_view_set_level_indentation(GTK_TREE_VIEW(g_app.tree_view), 18);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.tree_view), "file-tree");

    GtkTreeViewColumn *col = gtk_tree_view_column_new();
    GtkCellRenderer *pix = gtk_cell_renderer_pixbuf_new();
    g_object_set(pix, "stock-size", GTK_ICON_SIZE_MENU, NULL);
    gtk_tree_view_column_pack_start(col, pix, FALSE);
    gtk_tree_view_column_set_cell_data_func(col, pix, tree_icon_func, NULL, NULL);
    GtkCellRenderer *txt = gtk_cell_renderer_text_new();
    g_object_set(txt, "ellipsize", PANGO_ELLIPSIZE_END, NULL);
    gtk_tree_view_column_pack_start(col, txt, TRUE);
    gtk_tree_view_column_add_attribute(col, txt, "text", 0);
    gtk_tree_view_column_set_expand(col, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(g_app.tree_view), col);

    GtkCellRenderer *szr = gtk_cell_renderer_text_new();
    g_object_set(szr, "xalign", 1.0f, NULL);
    GtkTreeViewColumn *szcol = gtk_tree_view_column_new_with_attributes("size", szr, "text", 2, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(g_app.tree_view), szcol);
    gtk_tree_view_column_set_alignment(szcol, 1.0f);

    g_signal_connect(g_app.tree_view, "row-activated", G_CALLBACK(on_tree_row_activated), NULL);
    g_signal_connect(g_app.tree_view, "button-press-event", G_CALLBACK(on_tree_button_press), NULL);

    g_app.tree_sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(g_app.tree_sw, -1, 380);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(g_app.tree_sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(g_app.tree_sw, TRUE);
    gtk_container_add(GTK_CONTAINER(g_app.tree_sw), g_app.tree_view);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.tree_sw, TRUE, TRUE, 0);

    gtk_widget_hide(g_app.tree_summary);
    gtk_widget_hide(g_app.tree_filter);
    gtk_widget_hide(g_app.tree_expand_btn);
    gtk_widget_hide(g_app.tree_collapse_btn);
    gtk_widget_hide(g_app.tree_sw);

    g_app.notes_sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_sep, FALSE, FALSE, 0);

    g_app.notes_lbl = gtk_label_new(i18n("notes"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.notes_lbl), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(g_app.notes_lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_lbl, FALSE, FALSE, 0);

    g_app.notes_text = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(g_app.notes_text), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(g_app.notes_text), TRUE);
    g_object_set(g_app.notes_text, "hexpand", TRUE, "max-width-chars", 60, NULL);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_text, FALSE, FALSE, 0);

    gtk_widget_hide(g_app.notes_sep);
    gtk_widget_hide(g_app.notes_lbl);
    gtk_widget_hide(g_app.notes_text);

    gtk_container_add(GTK_CONTAINER(detail_scroll), g_app.detail_box);
    gtk_paned_pack2(GTK_PANED(paned), detail_scroll, TRUE, FALSE);
    gtk_box_pack_start(GTK_BOX(main_box), paned, TRUE, TRUE, 0);

    gtk_stack_add_named(g_app.stack, main_box, "main");
}

static void load_css(void) {
    static const char css1[] =
        "* { font-family: 'Inter','SF Pro Text','Segoe UI',system-ui,-apple-system,sans-serif; }"
        "window, .background { background-color: #171717; color: #e8e8e8; }"
        "headerbar { min-height: 42px; padding: 0 8px;"
        "  background-image: none; background-color: #111111;"
        "  border-bottom: 1px solid #2a2a2a; box-shadow: none; }"
        "headerbar .title { font-size: 13px; font-weight: 500;"
        "  letter-spacing: 0; color: #b0b0b0; padding: 0 8px; }"
        "headerbar label.title { color: #b0b0b0; }"
        "headerbar button { min-height: 26px; min-width: 26px; padding: 0 6px;"
        "  border: none; background: transparent; color: #999999;"
        "  border-radius: 4px; box-shadow: none; }"
        "headerbar button:hover { background-color: #222222; color: #ffffff; }"
        "label { color: #e8e8e8; }"
        ".welcome-title { font-size: 22px; font-weight: 300; letter-spacing: 4px; color: #f0f0f0; }"
        ".detail-title  { font-size: 15px; font-weight: 500; letter-spacing: 0.2px; color: #f0f0f0; }"
        ".row-title     { font-size: 13px; font-weight: 500; color: #e8e8e8; }"
        ".row-count {"
        "  font-size: 10px; font-weight: 500;"
        "  color: #b0b0b0; background-color: #2a2a2a;"
        "  padding: 1px 6px; border-radius: 8px; }"
        ".dim-label  { color: #888888; font-weight: 400; }"
        ".error      { color: #ff6b6b; font-weight: 500; }"
        ".tree-header { font-size: 12px; font-weight: 500; color: #b0b0b0; padding: 4px 0; }"
        ".sidebar { background-color: #121212; border-right: 1px solid #2a2a2a; }"
        ".key-row { padding: 2px; border-radius: 7px; }"
        ".key-card { background-color: #151515; border: 1px solid #2b2b2b; border-radius: 10px; padding: 14px; }"
        ".plugin-status { font-size: 11px; color: #9cdcfe; padding: 3px 8px; }"
        ".security-badge { font-size: 10px; font-weight: 600; padding: 4px 9px; border-radius: 10px; border: 1px solid #333333; }"
        ".security-pqc { color: #8bd5a0; background-color: #132018; border-color: #285737; }"
        ".security-classic { color: #e7c36a; background-color: #241f12; border-color: #645426; }"
        ".security-locked { color: #aaaaaa; background-color: #181818; border-color: #333333; }"
        ".main-toolbar {"
        "  background-color: #171717;"
        "  border-bottom: 1px solid #2a2a2a;"
        "  padding: 4px 0; }"
        "row { border: none; border-bottom: 1px solid #222222; padding: 0; }"
        "row:hover { background-color: #1f1f1f; }"
        "row:selected {"
        "  background-color: #262626;"
        "  color: #ffffff;"
        "  box-shadow: inset 3px 0 0 0 #4ec9b0; }"
        "row:selected .row-title { color: #ffffff; }"
        "row:selected .dim-label { color: #a0a0a0; }"
        "row:selected .row-count { background-color: #3a3a3a; color: #e8e8e8; }"
        "button {"
        "  border-radius: 4px;"
        "  border: 1px solid transparent;"
        "  background-image: none;"
        "  background-color: transparent;"
        "  color: #e0e0e0;"
        "  box-shadow: none;"
        "  padding: 5px 10px;"
        "  min-height: 24px; }"
        "button:hover { background-color: #262626; color: #ffffff; }"
        "button:active, button:checked { background-color: #303030; }"
        ".suggested-action {"
        "  background-color: #2a2a2a;"
        "  color: #ffffff;";
    static const char css2[] =
        "  border-color: #3a3a3a; }"
        ".suggested-action:hover { background-color: #353535; color: #ffffff; }"
        ".flat-btn {"
        "  border: none; background: transparent;"
        "  padding: 3px 6px;"
        "  color: #a0a0a0;"
        "  font-size: 11px; }"
        ".flat-btn:hover { background-color: #262626; color: #ffffff; }"
        ".flat-btn:disabled { color: #4a4a4a; }"
        "entry, combobox, combobox button, spinbutton {"
        "  border-radius: 4px;"
        "  border: 1px solid #333333;"
        "  background-image: none;"
        "  background-color: #1e1e1e;"
        "  color: #e8e8e8;"
        "  box-shadow: none;"
        "  padding: 5px 8px;"
        "  min-height: 22px; }"
        "entry:focus, combobox:focus-within { border-color: #4ec9b0; }"
        "entry selection { background-color: #4ec9b0; color: #0d0d0d; }"
        "combobox button { background-color: transparent; }"
        "separator { background-color: #2a2a2a; min-height: 1px; min-width: 1px; }"
        ".schema-val {"
        "  background-color: #f0f0f0; color: #0d0d0d;"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 15px;"
        "  padding: 6px 8px;"
        "  border-radius: 3px 0 0 3px; }"
        ".schema-salt {"
        "  background-color: #6a6a6a; color: #ffffff;"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 15px;"
        "  padding: 6px 8px;"
        "  border-radius: 0 3px 3px 0; }"
        ".schema-dash {"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 15px;"
        "  padding: 6px 0; color: #4a4a4a; }"
        ".vlabel-val {"
        "  background-color: #f0f0f0; color: #0d0d0d;"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 13px;"
        "  padding: 3px 6px;"
        "  border-radius: 3px 0 0 3px; }"
        ".vlabel-salt {"
        "  background-color: #6a6a6a; color: #ffffff;"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 13px;"
        "  padding: 3px 6px;"
        "  border-radius: 0 3px 3px 0; }"
        "treeview {"
        "  background-color: #1a1a1a;"
        "  color: #e0e0e0;"
        "  border: 1px solid #2a2a2a;"
        "  border-radius: 4px;"
        "  font-size: 12px; }"
        "treeview:selected { background-color: #2a2a2a; color: #ffffff; }"
        "treeview:hover    { background-color: #202020; }"
        "treeview.view     { background-color: #1a1a1a; color: #e0e0e0; }"
        "treeview .cell    { color: #e0e0e0; }"
        "treeview expander {"
        "  color: #808080;"
        "  min-width: 14px; min-height: 14px; }"
        "treeview expander:hover { color: #ffffff; }";
    static const char css3[] =
        ".search-disk-header {"
        "  background-color: #1e1e1e;"
        "  border-top: 1px solid #2a2a2a;"
        "  border-bottom: 1px solid #2a2a2a; }"
        ".disk-header-name  { font-size: 12px; font-weight: 600; color: #f0f0f0; }"
        ".disk-header-count {"
        "  font-size: 10px; font-weight: 500;"
        "  color: #e0e0e0; background-color: #2a2a2a;"
        "  padding: 1px 7px; border-radius: 8px; }"
        ".file-name { font-size: 12px; font-weight: 500; color: #e0e0e0; }"
        ".file-path { font-size: 11px; font-family: ui-monospace, monospace; color: #808080; }"
        ".file-size { font-size: 11px; font-family: ui-monospace, monospace; color: #a0a0a0; }"
        "scrollbar { background: transparent; border: none; }"
        "scrollbar slider {"
        "  background-color: #3a3a3a;"
        "  border-radius: 4px;"
        "  min-width: 6px; min-height: 6px; }"
        "scrollbar slider:hover { background-color: #4ec9b0; }"
        "tooltip {"
        "  background-color: #0d0d0d;"
        "  color: #e8e8e8;"
        "  border: 1px solid #3a3a3a;"
        "  border-radius: 4px;"
        "  padding: 5px 9px;"
        "  font-size: 11px; }"
        "menu {"
        "  background-color: #1e1e1e;"
        "  border: 1px solid #2a2a2a;"
        "  padding: 4px;"
        "  border-radius: 4px; }"
        "menuitem { padding: 5px 10px; border-radius: 3px; color: #e8e8e8; }"
        "menuitem:hover { background-color: #2a2a2a; color: #ffffff; }"
        "label:disabled { color: #555555; }"
        "cellview { color: #e0e0e0; background-color: #1a1a1a; }"
        ".search-filters { padding: 2px 0; }"
        ".filter-chip {"
        "  font-size: 10px;"
        "  min-height: 20px;"
        "  padding: 2px 10px;"
        "  border-radius: 10px;"
        "  border: 1px solid #333333;"
        "  background-color: #1e1e1e;"
        "  color: #a0a0a0;"
        "  min-width: 0; }"
        ".filter-chip:hover { background-color: #262626; color: #ffffff; }"
        ".filter-chip:checked { background-color: #4ec9b0; color: #0d0d0d;"
        "  border-color: #4ec9b0; }"
        ".smart-ok { color: #4ec9b0; font-weight: 600; }"
        ".smart-bad { color: #ff6b6b; font-weight: 600; }"
        ".connected-dot { color: #4ec9b0; font-weight: 700; }"
        ".disconnected-dot { color: #555555; font-weight: 700; }"
        ".toast {"
        "  background-color: #1e1e1e;"
        "  border-bottom: 1px solid #4ec9b0;"
        "  border-radius: 0; }"
        ".toast label { color: #e8e8e8; font-size: 12px; }"
        ".toast:hover { background-color: #262626; }"
        ".also-on { font-size: 10px; color: #4ec9b0; padding-top: 1px; }";

    GString *css = g_string_sized_new(sizeof(css1) + sizeof(css2) + sizeof(css3));
    if (!css) return;
    g_string_append(css, css1);
    g_string_append(css, css2);
    g_string_append(css, css3);
    GtkCssProvider *provider = gtk_css_provider_new();
    GError *error = NULL;
    gtk_css_provider_load_from_data(provider, css->str, (gssize)css->len, &error);
    if (error) g_error_free(error);
    g_string_free(css, TRUE);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static gboolean graceful_shutdown(gpointer user_data) {
    (void)user_data;
    if (g_shutdown_requested) return G_SOURCE_REMOVE;
    g_shutdown_requested = 1;

    if (g_app.clipboard_timer_id) {
        g_source_remove(g_app.clipboard_timer_id);
        g_app.clipboard_timer_id = 0;
    }
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);

    if (g_app.window)
        gtk_window_close(g_app.window);
    else
        gtk_main_quit();
    return G_SOURCE_REMOVE;
}

static void setup_accelerators(GtkWidget *win) {
    GtkAccelGroup *accel = gtk_accel_group_new();
    gtk_window_add_accel_group(GTK_WINDOW(win), accel);
    gtk_widget_add_accelerator(g_app.btn_add, "clicked", accel,
        GDK_KEY_n, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_del, "clicked", accel,
        GDK_KEY_Delete, 0, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_lock, "clicked", accel,
        GDK_KEY_l, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_sch, "clicked", accel,
        GDK_KEY_s, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_copy_label, "clicked", accel,
        GDK_KEY_c, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_copy_pass, "clicked", accel,
        GDK_KEY_p, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.search, "grab-focus", accel,
        GDK_KEY_f, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_snapshot, "clicked", accel,
        GDK_KEY_i, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_find, "clicked", accel,
        GDK_KEY_g, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_batch, "clicked", accel,
        GDK_KEY_r, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    g_object_unref(accel);
}

