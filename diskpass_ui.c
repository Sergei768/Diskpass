#include "diskpass.h"

AppData g_app;
GdkPixbuf *icon_pb = NULL;

static gboolean clipboard_clear_timer(gpointer user_data) {
    (void)user_data;
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    g_app.clipboard_timer_id = 0;
    return G_SOURCE_REMOVE;
}

void clipboard_copy_secure(const char *text) {
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, text, -1);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    g_app.clipboard_timer_id = g_timeout_add_seconds(30, clipboard_clear_timer, NULL);
}

static char *find_icon_path(void) {
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
    return gtk_image_new_from_icon_name("system-lock-screen", GTK_ICON_SIZE_BUTTON);
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

static void on_lock_clicked(GtkButton *btn, gpointer user_data);

static gboolean on_idle_lock(gpointer user_data) {
    (void)user_data;
    g_app.idle_timer_id = 0;
    if (g_app.db && g_app.current_file) {
        on_lock_clicked(NULL, NULL);
    }
    return G_SOURCE_REMOVE;
}

static void reset_idle_timer(void) {
    if (g_app.idle_timer_id) g_source_remove(g_app.idle_timer_id);
    if (g_app.db && g_app.current_file) {
        g_app.idle_timer_id = g_timeout_add_seconds(60, on_idle_lock, NULL);
    }
}

static gboolean on_activity(GtkWidget *w, GdkEvent *e, gpointer d) {
    (void)w; (void)e; (void)d;
    reset_idle_timer();
    return FALSE;
}

void update_ui_text(void) {
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
    if (g_app.search) gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.search), i18n("search"));
    if (g_app.lbl_main) gtk_label_set_text(GTK_LABEL(g_app.lbl_main), i18n("select_entry"));
    if (g_app.btn_copy_label) gtk_button_set_label(GTK_BUTTON(g_app.btn_copy_label), i18n("copy_label"));
    if (g_app.btn_copy_pass) gtk_button_set_label(GTK_BUTTON(g_app.btn_copy_pass), i18n("copy_pass"));
    if (g_app.notes_lbl) gtk_label_set_text(GTK_LABEL(g_app.notes_lbl), i18n("notes"));
}

void refresh_entry_list(void) {
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
        GtkWidget *lbl = gtk_label_new(has_alias ? e->alias : e->label);
        gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "row-title");
        gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
        gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, TRUE, 0);
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
        GtkWidget *sub = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *l1 = gtk_label_new(e->type ? e->type : "");
        GtkWidget *l2 = gtk_label_new(e->size ? e->size : "");
        GtkWidget *l3 = gtk_label_new(e->cipher ? e->cipher : "");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0); gtk_label_set_xalign(GTK_LABEL(l2), 0.0); gtk_label_set_xalign(GTK_LABEL(l3), 0.0);
        gtk_box_pack_start(GTK_BOX(sub), l1, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(sub), l2, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(sub), l3, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), sub, FALSE, FALSE, 0);
        gtk_container_add(GTK_CONTAINER(row), box);
        g_object_set_data(G_OBJECT(row), "entry_idx", GINT_TO_POINTER(i));
        gtk_list_box_insert(g_app.listbox, row, -1);
    }
    gtk_widget_show_all(GTK_WIDGET(g_app.listbox));
}

void clear_details(void) {
    gtk_label_set_text(GTK_LABEL(g_app.lbl_main), i18n("select_entry"));
    GList *children = gtk_container_get_children(GTK_CONTAINER(g_app.grid));
    for (GList *l = children; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);
    gtk_label_set_text(GTK_LABEL(g_app.notes_text), "");
    gtk_widget_set_sensitive(g_app.btn_copy_label, FALSE);
    gtk_widget_set_sensitive(g_app.btn_copy_pass, FALSE);
}

void show_entry_details(int idx) {
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
        GtkWidget *l2 = gtk_label_new(e->label);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(l2, TRUE);
        char *tip2 = build_label_tooltip(g_app.db, e->label);
        gtk_widget_set_tooltip_text(l2, tip2);
        g_free(tip2);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }
    for (int i = 0; i < block_count; i++) {
        char header[64];
        snprintf(header, sizeof(header), "%s %d (%s)", i18n("block"), i+1, i18n(blocks[i].part_name));
        GtkWidget *l1 = gtk_label_new(header);
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        char val_text[128];
        if (strcmp(blocks[i].part_name, "type") == 0 || strcmp(blocks[i].part_name, "size") == 0 || strcmp(blocks[i].part_name, "cipher") == 0)
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
    {
        GtkWidget *l1 = gtk_label_new(i18n("full_tag"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        GtkWidget *l2 = gtk_label_new(e->tag_full && e->tag_full[0] ? e->tag_full : "—");
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(l2, TRUE);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }
    {
        GtkWidget *l1 = gtk_label_new(i18n("password"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        GtkWidget *l2 = gtk_label_new(e->dpass ? "●●●●●●●●" : "—");
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }
    gtk_label_set_text(GTK_LABEL(g_app.notes_text), e->notes && e->notes[0] ? e->notes : "—");
    gtk_widget_show_all(GTK_WIDGET(grid));
}

static void on_row_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data) {
    (void)box; (void)user_data;
    if (!row) { clear_details(); return; }
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
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

static void on_copy_label_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (g_app.db && idx >= 0 && idx < g_app.db->entry_count && g_app.db->entries[idx].label)
        clipboard_copy_secure(g_app.db->entries[idx].label);
}

static void on_copy_pass_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (g_app.db && idx >= 0 && idx < g_app.db->entry_count && g_app.db->entries[idx].dpass)
        clipboard_copy_secure(g_app.db->entries[idx].dpass);
}

static void on_lock_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (g_app.idle_timer_id) {
        g_source_remove(g_app.idle_timer_id);
        g_app.idle_timer_id = 0;
    }
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    free(g_app.current_file); g_app.current_file = NULL;
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    clear_details();
    refresh_entry_list();
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.clipboard_timer_id) {
        g_source_remove(g_app.clipboard_timer_id);
        g_app.clipboard_timer_id = 0;
    }
    gtk_stack_set_visible_child_name(g_app.stack, "welcome");
}

void populate_gpg_keys(GtkComboBoxText *combo, int secret_only, GtkWidget *err_label) {
    gtk_combo_box_text_remove_all(combo);
    if (!g_app.db) return;
    int count = 0;
    gpg_key_info_t *keys = gpg_list_keys(g_app.db->gpg_ctx, secret_only, &count);
    if (!keys || count == 0) { gtk_label_set_text(GTK_LABEL(err_label), i18n("no_keys")); gpg_free_key_list(keys, count); return; }
    int active = 0;
    for (int i = 0; i < count; i++) {
        gtk_combo_box_text_append(combo, keys[i].fingerprint, keys[i].uid);
        if (g_app.expected_fp && strcmp(keys[i].fingerprint, g_app.expected_fp) == 0) active = i;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), active);
    gtk_label_set_text(GTK_LABEL(err_label), "");
    gpg_free_key_list(keys, count);
}

static void open_file_direct(const char *path) {
    free(g_app.current_file);
    g_app.current_file = xstrdup(path);
    char info[256];
    snprintf(info, sizeof(info), "%s %s", i18n("file"), g_app.current_file);
    gtk_label_set_text(GTK_LABEL(g_app.unlock_file_label), info);
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    FILE *fp = fopen(g_app.current_file, "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
            char *cr = strchr(line, '\r'); if (cr) *cr = '\0';
            g_app.expected_fp = xstrdup(line);
        }
        fclose(fp);
    }
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
    g_app.db = calloc(1, sizeof(db_manager_t));
    db_manager_init(g_app.db);
    gpgme_error_t gerr = gpgme_new(&g_app.db->gpg_ctx);
    if (gerr != GPG_ERR_NO_ERROR) {
        db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL;
    } else {
        gpgme_set_protocol(g_app.db->gpg_ctx, GPGME_PROTOCOL_OpenPGP);
        populate_gpg_keys(GTK_COMBO_BOX_TEXT(g_app.unlock_key_combo), 1, g_app.unlock_err);
        gtk_stack_set_visible_child_name(g_app.stack, "unlock");
    }
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
        gchar *chosen_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        open_file_direct(chosen_path);
        g_free(chosen_path);
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
        db_manager_init(g_app.db);
        gpgme_error_t gerr = gpgme_new(&g_app.db->gpg_ctx);
        if (gerr != GPG_ERR_NO_ERROR) {
            db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL;
        } else {
            gpgme_set_protocol(g_app.db->gpg_ctx, GPGME_PROTOCOL_OpenPGP);
            populate_gpg_keys(GTK_COMBO_BOX_TEXT(g_app.key_combo), 0, g_app.setup_err);
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
    gtk_stack_set_visible_child_name(g_app.stack, "main");
    refresh_entry_list();
    reset_idle_timer();
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
    gtk_stack_set_visible_child_name(g_app.stack, "main");
    refresh_entry_list();
    reset_idle_timer();
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
    GtkWidget *yes_btn = gtk_dialog_get_widget_for_response(GTK_DIALOG(dlg), GTK_RESPONSE_YES);
    if (yes_btn) gtk_style_context_add_class(gtk_widget_get_style_context(yes_btn), "destructive-action");
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_YES) {
        char err_buf[256] = "";
        db_remove_entry(g_app.db, g_app.db->entries[idx].label, err_buf, sizeof(err_buf));
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

static void on_add_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("add_entry"), g_app.window, GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL, i18n("create"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 450, 500);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 12);
    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 12); gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_hexpand(GTK_WIDGET(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(grid), TRUE, TRUE, 0);
    int row = 0;
    gtk_grid_attach(grid, gtk_label_new(i18n("alias")), 0, row, 1, 1);
    GtkWidget *valias = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(valias), i18n("alias_placeholder"));
    gtk_widget_set_hexpand(valias, TRUE);
    gtk_grid_attach(grid, valias, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("media_type")), 0, row, 1, 1);
    GtkWidget *vtp = gtk_combo_box_text_new();
    for (int i = 0; i < TYPE_MAP_N; i++) gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(vtp), TYPE_MAP[i].name);
    gtk_combo_box_set_active(GTK_COMBO_BOX(vtp), 0); gtk_widget_set_hexpand(vtp, TRUE);
    gtk_grid_attach(grid, vtp, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("size")), 0, row, 1, 1);
    GtkWidget *vsz = gtk_combo_box_text_new(); gtk_widget_set_hexpand(vsz, TRUE);
    gtk_grid_attach(grid, vsz, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("cipher")), 0, row, 1, 1);
    GtkWidget *vci = gtk_combo_box_text_new();
    for (int i = 0; i < CIPHER_MAP_N; i++) gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(vci), CIPHER_MAP[i].name);
    gtk_combo_box_set_active(GTK_COMBO_BOX(vci), 0); gtk_widget_set_hexpand(vci, TRUE);
    gtk_grid_attach(grid, vci, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("password")), 0, row, 1, 1);
    GtkWidget *ph = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *vdp = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(vdp), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(vdp), '*');
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, "eye-not-looking-symbolic");
    gtk_entry_set_icon_activatable(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, TRUE);
    gtk_entry_set_icon_tooltip_text(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, "Toggle visibility");
    g_signal_connect(vdp, "icon-press", G_CALLBACK(on_toggle_password_visibility), NULL);
    gtk_widget_set_hexpand(vdp, TRUE);
    gtk_box_pack_start(GTK_BOX(ph), vdp, TRUE, TRUE, 0);
    GtkWidget *bg = gtk_button_new_from_icon_name("view-refresh", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(bg, i18n("generate"));
    gtk_box_pack_start(GTK_BOX(ph), bg, FALSE, FALSE, 0);
    gtk_grid_attach(grid, ph, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("tag_min")), 0, row, 1, 1);
    GtkWidget *vt = gtk_entry_new(); gtk_widget_set_hexpand(vt, TRUE);
    gtk_grid_attach(grid, vt, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("salt")), 0, row, 1, 1);
    char *salt_str = generate_salt(2);
    GtkWidget *vd = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(vd), salt_str);
    gtk_editable_set_editable(GTK_EDITABLE(vd), FALSE); gtk_widget_set_hexpand(vd, TRUE);
    gtk_grid_attach(grid, vd, 1, row++, 1, 1);
    free(salt_str);
    gtk_grid_attach(grid, gtk_label_new(i18n("notes")), 0, row, 1, 1);
    GtkWidget *nt = gtk_text_view_new(); gtk_widget_set_size_request(nt, -1, 60);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw), nt); gtk_widget_set_hexpand(sw, TRUE);
    gtk_grid_attach(grid, sw, 1, row++, 1, 1);
    const char **sizes = get_sizes_for_type(TYPE_MAP[0].name);
    for (int i = 0; sizes[i]; i++) gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(vsz), sizes[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(vsz), 0);
    g_signal_connect(vtp, "changed", G_CALLBACK(on_add_type_changed), vsz);
    g_signal_connect(bg, "clicked", G_CALLBACK(on_gen_password), vdp);
    gtk_widget_show_all(dlg);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *tag_str = gtk_entry_get_text(GTK_ENTRY(vt));
        if (strlen(tag_str) < 2) { gtk_widget_destroy(dlg); return; }
        char tag_val[3] = { toupper((unsigned char)tag_str[0]), toupper((unsigned char)tag_str[1]), '\0' };
        gchar *type_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(vtp));
        gchar *size_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(vsz));
        gchar *cipher_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(vci));
        const char *dpass_val = gtk_entry_get_text(GTK_ENTRY(vdp));
        const char *dsalt_val = gtk_entry_get_text(GTK_ENTRY(vd));
        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt));
        GtkTextIter start, end;
        gtk_text_buffer_get_start_iter(buf, &start); gtk_text_buffer_get_end_iter(buf, &end);
        char *notes_val = gtk_text_buffer_get_text(buf, &start, &end, FALSE);
        const char *actual_dpass = (strcmp(cipher_val, "NONE") == 0) ? "" : dpass_val;
        const char *alias_val = gtk_entry_get_text(GTK_ENTRY(valias));
        char err_buf[256] = "";
        char *label = db_encode_label(g_app.db, type_val, size_val, tag_val, cipher_val, dsalt_val);
        if (db_add_entry(g_app.db, type_val, size_val, cipher_val, tag_val, dsalt_val, tag_str, actual_dpass, notes_val, alias_val, err_buf, sizeof(err_buf)) == 0) {
            clipboard_copy_secure(label);
            refresh_entry_list();
        }
        free(label);
        g_free(notes_val);
        g_free(type_val);
        g_free(size_val);
        g_free(cipher_val);
    }
    gtk_widget_destroy(dlg);
}

static void on_edit_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("edit_entry"), g_app.window, GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL, i18n("save"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 450, 350);
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
    GtkWidget *ph = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *vdp = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(vdp), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(vdp), '*');
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, "eye-not-looking-symbolic");
    gtk_entry_set_icon_activatable(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, TRUE);
    gtk_entry_set_icon_tooltip_text(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, "Toggle visibility");
    g_signal_connect(vdp, "icon-press", G_CALLBACK(on_toggle_password_visibility), NULL);
    if (e->dpass) gtk_entry_set_text(GTK_ENTRY(vdp), e->dpass);
    gtk_widget_set_hexpand(vdp, TRUE);
    gtk_box_pack_start(GTK_BOX(ph), vdp, TRUE, TRUE, 0);
    GtkWidget *bg = gtk_button_new_from_icon_name("view-refresh", GTK_ICON_SIZE_BUTTON);
    gtk_box_pack_start(GTK_BOX(ph), bg, FALSE, FALSE, 0);
    gtk_grid_attach(GTK_GRID(grid), ph, 1, 2, 1, 1);
    g_signal_connect(bg, "clicked", G_CALLBACK(on_gen_password), vdp);
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
        db_update_entry(g_app.db, e->label, new_dpass, new_notes, new_alias, err_buf, sizeof(err_buf));
        g_free(new_notes);
        refresh_entry_list();
        GtkListBoxRow *new_row = gtk_list_box_get_row_at_index(g_app.listbox, idx);
        if (new_row) gtk_list_box_select_row(g_app.listbox, new_row);
        show_entry_details(idx);
    }
    gtk_widget_destroy(dlg);
}

static void on_schema_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("schema_title"), g_app.window, GTK_DIALOG_MODAL, i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 450, 430);
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
        char btxt[32]; snprintf(btxt, sizeof(btxt), "%s %d", i18n("block"), i+1);
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

static void on_lang_changed_welcome(GtkComboBoxText *combo, gpointer user_data) {
    (void)user_data;
    gchar *id = (gchar*)gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
    if (id && strcmp(id, g_lang) != 0) {
        snprintf(g_lang, sizeof(g_lang), "%s", id);
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(g_app.lang_combo), g_lang);
        update_ui_text();
    }
}

void build_welcome(void) {
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
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(g_app.lang_combo_welcome), "ru", "Русский");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(g_app.lang_combo_welcome), "en", "English");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(g_app.lang_combo_welcome), g_lang);
    g_signal_connect(g_app.lang_combo_welcome, "changed", G_CALLBACK(on_lang_changed_welcome), NULL);
    gtk_box_pack_start(GTK_BOX(lang_box), g_app.lang_combo_welcome, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lang_box, FALSE, FALSE, 0);
    gtk_stack_add_named(g_app.stack, box, "welcome");
}

void build_setup(void) {
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
    g_app.key_combo = gtk_combo_box_text_new();
    gtk_widget_set_size_request(g_app.key_combo, 250, -1); gtk_widget_set_hexpand(g_app.key_combo, TRUE);
    gtk_grid_attach(grid, g_app.key_combo, 1, 1, 1, 1);
    g_app.lbl_setup_lang = gtk_label_new(i18n("language"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_setup_lang), 1.0);
    gtk_grid_attach(grid, g_app.lbl_setup_lang, 0, 2, 1, 1);
    g_app.lang_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(g_app.lang_combo), "ru", "Русский");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(g_app.lang_combo), "en", "English");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(g_app.lang_combo), g_lang);
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

void build_unlock(void) {
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
    g_app.unlock_key_combo = gtk_combo_box_text_new();
    gtk_widget_set_size_request(g_app.unlock_key_combo, 250, -1); gtk_widget_set_hexpand(g_app.unlock_key_combo, TRUE);
    gtk_grid_attach(grid, g_app.unlock_key_combo, 1, 1, 1, 1);
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

void build_main(void) {
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(toolbar), "main-toolbar");
    gtk_widget_set_margin_top(toolbar, 6); gtk_widget_set_margin_bottom(toolbar, 6);
    gtk_widget_set_margin_start(toolbar, 6); gtk_widget_set_margin_end(toolbar, 6);
    g_app.btn_lock = gtk_button_new_from_icon_name("changes-prevent-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(g_app.btn_lock, i18n("lock_db"));
    g_signal_connect(g_app.btn_lock, "clicked", G_CALLBACK(on_lock_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_lock, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(toolbar), gtk_label_new(""), TRUE, TRUE, 0);
    g_app.btn_sch = gtk_button_new_from_icon_name("dialog-information-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(g_app.btn_sch, i18n("show_schema"));
    g_signal_connect(g_app.btn_sch, "clicked", G_CALLBACK(on_schema_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(toolbar), g_app.btn_sch, FALSE, FALSE, 0);
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_box), "linked");
    g_app.btn_add = gtk_button_new_from_icon_name("list-add-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_add), "suggested-action");
    gtk_widget_set_tooltip_text(g_app.btn_add, i18n("add_entry"));
    g_signal_connect(g_app.btn_add, "clicked", G_CALLBACK(on_add_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_add, FALSE, FALSE, 0);
    g_app.btn_edit = gtk_button_new_from_icon_name("document-edit-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(g_app.btn_edit, i18n("edit_entry"));
    g_signal_connect(g_app.btn_edit, "clicked", G_CALLBACK(on_edit_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_edit, FALSE, FALSE, 0);
    g_app.btn_del = gtk_button_new_from_icon_name("edit-delete-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_del), "destructive-action");
    gtk_widget_set_tooltip_text(g_app.btn_del, i18n("del_entry"));
    g_signal_connect(g_app.btn_del, "clicked", G_CALLBACK(on_delete_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_del, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(toolbar), btn_box, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), toolbar, FALSE, FALSE, 0);
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 300);
    gtk_paned_set_wide_handle(GTK_PANED(paned), TRUE);
    GtkWidget *left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *search_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(search_box), "sidebar");
    gtk_widget_set_margin_top(search_box, 6); gtk_widget_set_margin_bottom(search_box, 6);
    gtk_widget_set_margin_start(search_box, 6); gtk_widget_set_margin_end(search_box, 6);
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
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(detail_scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(detail_scroll, TRUE);
    g_app.detail_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    gtk_widget_set_margin_top(g_app.detail_box, 18); gtk_widget_set_margin_bottom(g_app.detail_box, 18);
    gtk_widget_set_margin_start(g_app.detail_box, 24); gtk_widget_set_margin_end(g_app.detail_box, 24);
    gtk_widget_set_valign(g_app.detail_box, GTK_ALIGN_START);
    GtkWidget *top_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    g_app.lbl_main = gtk_label_new(i18n("select_entry"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.lbl_main), "detail-title");
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_main), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(g_app.lbl_main), PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_set_hexpand(g_app.lbl_main, TRUE);
    gtk_box_pack_start(GTK_BOX(top_box), g_app.lbl_main, TRUE, TRUE, 0);
    g_app.btn_copy_label = gtk_button_new_with_label(i18n("copy_label"));
    gtk_button_set_image(GTK_BUTTON(g_app.btn_copy_label), gtk_image_new_from_icon_name("edit-copy-symbolic", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(g_app.btn_copy_label), TRUE);
    gtk_widget_set_sensitive(g_app.btn_copy_label, FALSE);
    g_signal_connect(g_app.btn_copy_label, "clicked", G_CALLBACK(on_copy_label_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(top_box), g_app.btn_copy_label, FALSE, FALSE, 0);
    g_app.btn_copy_pass = gtk_button_new_with_label(i18n("copy_pass"));
    gtk_button_set_image(GTK_BUTTON(g_app.btn_copy_pass), gtk_image_new_from_icon_name("dialog-password-symbolic", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(g_app.btn_copy_pass), TRUE);
    gtk_widget_set_sensitive(g_app.btn_copy_pass, FALSE);
    g_signal_connect(g_app.btn_copy_pass, "clicked", G_CALLBACK(on_copy_pass_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(top_box), g_app.btn_copy_pass, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), top_box, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);
    g_app.grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(g_app.grid), 18);
    gtk_grid_set_row_spacing(GTK_GRID(g_app.grid), 10);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.grid, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);
    g_app.notes_lbl = gtk_label_new(i18n("notes"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.notes_lbl), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(g_app.notes_lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_lbl, FALSE, FALSE, 0);
    g_app.notes_text = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(g_app.notes_text), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(g_app.notes_text), TRUE);
    g_object_set(g_app.notes_text, "hexpand", TRUE, "max-width-chars", 40, NULL);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_text, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(detail_scroll), g_app.detail_box);
    gtk_paned_pack2(GTK_PANED(paned), detail_scroll, TRUE, FALSE);
    gtk_box_pack_start(GTK_BOX(main_box), paned, TRUE, TRUE, 0);
    gtk_stack_add_named(g_app.stack, main_box, "main");
}

void load_css(void) {
    static const char css[] =
        ".welcome-title { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }"
        ".detail-title { font-size: 18px; font-weight: 600; letter-spacing: 0.5px; }"
        ".row-title { font-size: 13px; font-weight: 600; }"
        ".dim-label { color: alpha(@theme_fg_color, 0.5); font-weight: 400; }"
        ".error { color: @error_color; font-weight: 600; margin-top: 4px; }"
        ".sidebar { background-color: @theme_base_color; border-right: 1px solid alpha(@borders, 0.5); }"
        ".main-toolbar { background-color: @theme_bg_color; border-bottom: 1px solid alpha(@borders, 0.5); }"
        "row { border-bottom: 1px solid alpha(@borders, 0.2); padding: 2px 0; }"
        "row:hover { background-color: alpha(@theme_fg_color, 0.05); }"
        "row:selected { background-color: @theme_selected_bg_color; color: @theme_selected_fg_color; }"
        "row:selected .dim-label { color: alpha(@theme_selected_fg_color, 0.7); }"
        "button { border-radius: 5px; }"
        ".linked button { border-radius: 0; }"
        ".linked button:first-child { border-radius: 5px 0 0 5px; }"
        ".linked button:last-child { border-radius: 0 5px 5px 0; }"
        "entry, combobox entry { border-radius: 5px; }"
        ".schema-val { background-color: #aee; color: #333; font-family: monospace;"
        " font-weight: bold; font-size: 18px; padding: 8px 4px;"
        " border-radius: 4px 0 0 4px; border: 1px solid #3aa; }"
        ".schema-salt { background-color: #fea; color: #333; font-family: monospace;"
        " font-weight: bold; font-size: 18px; padding: 8px 4px;"
        " border-radius: 0 4px 4px 0; border: 1px solid #c93; }"
        ".schema-dash { font-family: monospace; font-weight: bold; font-size: 18px;"
        " padding: 8px 0; color: #999; }";
    GtkCssProvider *provider = gtk_css_provider_new();
    GError *error = NULL;
    gtk_css_provider_load_from_data(provider, css, -1, &error);
    if (error) g_error_free(error);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

void setup_accelerators(GtkWidget *win) {
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
}

void graceful_shutdown(int sig) {
    (void)sig;
    if (g_app.idle_timer_id) g_source_remove(g_app.idle_timer_id);
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    free(g_app.current_file); g_app.current_file = NULL;
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    gtk_main_quit();
}

int main(int argc, char **argv) {
    umask(0077);
    setlocale(LC_ALL, "");
    if (!g_get_charset(NULL)) {
        g_setenv("LANG", "C.UTF-8", TRUE);
        g_setenv("LC_ALL", "C.UTF-8", TRUE);
    }
    if (sodium_init() < 0) { fprintf(stderr, "FATAL: libsodium init failed\n"); return 1; }
    if (!gpgme_check_version("1.14.0")) { fprintf(stderr, "FATAL: GPGME >= 1.14.0 required\n"); return 1; }
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
        fprintf(stderr, "WARNING: mlockall failed: %s\n", strerror(errno));
    }
    signal(SIGINT, graceful_shutdown);
    signal(SIGTERM, graceful_shutdown);
    gtk_init(&argc, &argv);
    load_css();
    memset(&g_app, 0, sizeof(g_app));
    char *icon_path = find_icon_path();
    if (icon_path) {
        icon_pb = gdk_pixbuf_new_from_file_at_size(icon_path, 256, 256, NULL);
        g_free(icon_path);
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "DiskPass");
    gtk_window_set_default_size(GTK_WINDOW(win), 850, 550);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    if (icon_pb) gtk_window_set_icon(GTK_WINDOW(win), icon_pb);
    g_app.window = GTK_WINDOW(win);
    g_app.stack = GTK_STACK(gtk_stack_new());
    gtk_stack_set_transition_type(g_app.stack, GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_container_add(GTK_CONTAINER(win), GTK_WIDGET(g_app.stack));
    build_welcome();
    build_setup();
    build_unlock();
    build_main();
    setup_accelerators(win);
    gtk_widget_add_events(GTK_WIDGET(g_app.window), GDK_KEY_PRESS_MASK | GDK_POINTER_MOTION_MASK | GDK_BUTTON_PRESS_MASK);
    g_signal_connect(g_app.window, "key-press-event", G_CALLBACK(on_activity), NULL);
    g_signal_connect(g_app.window, "motion-notify-event", G_CALLBACK(on_activity), NULL);
    g_signal_connect(g_app.window, "button-press-event", G_CALLBACK(on_activity), NULL);
    gtk_stack_set_visible_child_name(g_app.stack, "welcome");
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_widget_show_all(win);
    if (argc > 1) {
        open_file_direct(argv[1]);
    }
    gtk_main();
    if (g_app.idle_timer_id) g_source_remove(g_app.idle_timer_id);
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
    free(g_app.current_file);
    free(g_app.expected_fp);
    if (icon_pb) g_object_unref(icon_pb);
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    return 0;
}
