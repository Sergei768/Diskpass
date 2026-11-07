static void on_about_diskpass(GtkButton *item, gpointer data);
#include "diskpass.h"

typedef struct {
    GtkWindow *window;
    GtkStack *stack;
    GtkWidget *welcome_title, *welcome_desc, *lbl_lang_welcome;
    GtkWidget *btn_open, *btn_open_stego, *btn_create, *lang_combo_welcome;
    GtkWidget *setup_title, *lbl_setup_file, *lbl_setup_key, *lbl_setup_lang;
    GtkWidget *setup_file_label, *key_combo, *lang_combo, *setup_err;
    GtkWidget *btn_setup_back, *btn_setup_create;
    GtkWidget *unlock_title, *lbl_unlock_file, *lbl_unlock_key;
    GtkWidget *unlock_file_label, *unlock_key_combo, *unlock_status, *unlock_err;
    GtkWidget *btn_unlock_back, *btn_unlock;
    GtkWidget *search;
    GtkListBox *listbox;
    GtkWidget *detail_box, *lbl_main, *grid, *notes_text;
    GtkWidget *btn_copy_label, *btn_copy_pass;
    GtkWidget *btn_lock, *btn_add, *btn_edit, *btn_del, *btn_sch, *btn_settings, *btn_about;
    GtkWidget *btn_snapshot, *btn_find, *btn_batch;
    GtkWidget *btn_refresh, *btn_smart, *btn_rekey, *btn_plugins, *btn_carrier;
    GtkWidget *btn_create_key_setup, *btn_create_key_unlock, *btn_create_key_main;
    GtkWidget *security_badge;
    GtkWidget *privacy_shield;
    GtkWidget *privacy_shield_title, *privacy_shield_desc;
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
    char *config_last_db; /* preserved across v5 -> protected-format migration */
    char *expected_fp;

    char *mounted_carrier_path;
    char *mounted_temp_db_path;
    dev_t mounted_carrier_dev;
    ino_t mounted_carrier_ino;
    off_t mounted_carrier_size;
    struct timespec mounted_carrier_mtim;


    unsigned char mounted_carrier_hash[32];
    gboolean mounted_carrier_identity_valid;
    guint clipboard_timer_id;
    guint autolock_timer_id;
    guint privacy_shield_timer_id;
    guint focus_lock_timer_id;
    guint autolock_seconds;
    guint clipboard_clear_seconds;
    gboolean screenshot_guard;
    gboolean lock_on_focus_loss;
    gboolean camouflage_enabled;
    char camouflage_hash[crypto_pwhash_STRBYTES];
    /* A password-derived key only available after the numeric code is entered.
     * Never persist this key (or the code) to a file. */
    unsigned char camouflage_salt[crypto_pwhash_SALTBYTES];
    unsigned char camouflage_config_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    gboolean camouflage_key_valid;
    gboolean camouflage_legacy_config;
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
static gboolean g_carrier_running = FALSE;
static gboolean g_unlock_running = FALSE;


static gboolean app_has_open_database(void) {
    return g_app.db && g_app.db->file_path && g_app.db->file_path[0] &&
        g_app.db->noise_key && g_app.db->noise_key_len == 32;
}

static void carrier_unmount_cleanup(void);
static gboolean carrier_capture_identity(const char *path);
static gboolean carrier_identity_unchanged(char *err_msg, size_t err_msg_sz);
static void on_open_stego_clicked(GtkButton *btn, gpointer user_data);
static int carrier_mounted_commit_hook(const char *db_path, char *err_msg, size_t err_msg_sz);
static void privacy_shield_set(gboolean visible);

static char *diskpass_private_dir(void) {
    const char *home = g_get_home_dir();
    if (!home || !home[0]) return NULL;
    /* Override is for an explicit user-selected neutral directory. It must be
     * absolute; do not silently use an environment-relative path. */
    const char *override = g_getenv("DISKPASS_PRIVATE_DIR");
    char *dir = (override && override[0] == '/') ? g_strdup(override) :
        g_build_filename(home, ".diskpass", NULL);
    if (!dir) return NULL;
    if (g_mkdir_with_parents(dir, 0700) != 0) { g_free(dir); return NULL; }
    struct stat st;
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) ||
        st.st_uid != getuid() || (st.st_mode & 077) != 0 || chmod(dir, 0700) != 0) {
        g_free(dir); return NULL;
    }
    return dir;
}

static char *config_path(void) {
    char *dir = diskpass_private_dir();
    if (!dir) return NULL;

    char *path = g_build_filename(dir, "config", NULL);
    if (!path) {
        g_free(dir);
        return NULL;
    }

    struct stat st;
    if (g_lstat(path, &st) != 0 && errno == ENOENT &&
        !(g_getenv("DISKPASS_PRIVATE_DIR") && g_getenv("DISKPASS_PRIVATE_DIR")[0] == '/')) {
        char *old_path = g_build_filename(g_get_user_config_dir(), "diskpass", "config", NULL);
        int in_fd = old_path ? open(old_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK) : -1;
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

/* Only the mode flag, Argon2id verifier and random KDF salt remain in the
 * clear. User preferences (including last database path) are encrypted and
 * authenticated using a separate key derived from the calculator code.
 * This protects content, not the file name or the existence of DiskPass. */
#define CAMOUFLAGE_CONFIG_AD "DiskPass protected configuration v1"
#define CAMOUFLAGE_CONFIG_LIMIT (1024U * 1024U)

static void apply_user_settings(GKeyFile *kf) {
    char *lang = g_key_file_get_string(kf, "main", "lang", NULL);
    if (lang && i18n_language_exists(lang)) i18n_set_language(lang);
    g_free(lang);
    GError *err = NULL;
    gint n = g_key_file_get_integer(kf, "security", "autolock_seconds", &err);
    if (!err && n >= 0 && n <= 86400) g_app.autolock_seconds = (guint)n;
    g_clear_error(&err);
    n = g_key_file_get_integer(kf, "security", "clipboard_clear_seconds", &err);
    if (!err && n >= 5 && n <= 600) g_app.clipboard_clear_seconds = (guint)n;
    g_clear_error(&err);
    gboolean b = g_key_file_get_boolean(kf, "security", "screenshot_guard", &err);
    if (!err) g_app.screenshot_guard = b;
    g_clear_error(&err);
    b = g_key_file_get_boolean(kf, "security", "lock_on_focus_loss", &err);
    if (!err) g_app.lock_on_focus_loss = b;
    g_clear_error(&err);
    /* Preserve this setting during the v5 -> encrypted-format migration,
     * even though the program does not automatically reopen the database. */
    char *last_db = g_key_file_get_string(kf, "main", "last_db", NULL);
    g_free(g_app.config_last_db);
    g_app.config_last_db = last_db;
}

static gboolean camouflage_read_salt(GKeyFile *kf) {
    char *hex = g_key_file_get_string(kf, "camouflage", "config_salt", NULL);
    if (!hex) return FALSE;
    size_t written = 0;
    gboolean ok = strlen(hex) == crypto_pwhash_SALTBYTES * 2 &&
        sodium_hex2bin(g_app.camouflage_salt, sizeof(g_app.camouflage_salt),
                       hex, strlen(hex), NULL, &written, NULL) == 0 &&
        written == sizeof(g_app.camouflage_salt);
    g_free(hex);
    return ok;
}

static gboolean camouflage_decrypt_settings(GKeyFile *outer) {
    if (!g_app.camouflage_key_valid) return FALSE;
    char *nonce_hex = g_key_file_get_string(outer, "camouflage", "nonce", NULL);
    char *payload_b64 = g_key_file_get_string(outer, "camouflage", "payload", NULL);
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    size_t nonce_len = 0;
    gboolean ok = nonce_hex && payload_b64 &&
        strlen(nonce_hex) == sizeof(nonce) * 2 &&
        strlen(payload_b64) <= 2 * CAMOUFLAGE_CONFIG_LIMIT &&
        sodium_hex2bin(nonce, sizeof(nonce), nonce_hex, strlen(nonce_hex),
                       NULL, &nonce_len, NULL) == 0 && nonce_len == sizeof(nonce);
    g_free(nonce_hex);
    if (!ok) { g_free(payload_b64); return FALSE; }

    gsize cipher_len = 0;
    guchar *cipher = g_base64_decode(payload_b64, &cipher_len);
    g_free(payload_b64);
    if (!cipher || cipher_len <= crypto_aead_xchacha20poly1305_ietf_ABYTES ||
        cipher_len > CAMOUFLAGE_CONFIG_LIMIT) {
        g_free(cipher);
        return FALSE;
    }
    unsigned char *plain = g_malloc(cipher_len + 1);
    unsigned long long plain_len = 0;
    const unsigned char ad[] = CAMOUFLAGE_CONFIG_AD;
    ok = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plain, &plain_len, NULL, cipher, (unsigned long long)cipher_len,
        ad, sizeof(ad) - 1, nonce, g_app.camouflage_config_key) == 0 &&
        plain_len <= CAMOUFLAGE_CONFIG_LIMIT;
    sodium_memzero(cipher, cipher_len);
    g_free(cipher);
    if (ok) {
        plain[plain_len] = 0;
        GKeyFile *inner = g_key_file_new();
        ok = g_utf8_validate((char *)plain, (gssize)plain_len, NULL) &&
            g_key_file_load_from_data(inner, (char *)plain, (gsize)plain_len,
                                      G_KEY_FILE_NONE, NULL);
        if (ok) apply_user_settings(inner);
        g_key_file_unref(inner);
    }
    sodium_memzero(plain, cipher_len + 1);
    g_free(plain);
    return ok;
}

static gboolean save_config(void) {
    char *path = config_path();
    if (!path) return FALSE;
    GKeyFile *prefs = g_key_file_new();
    g_key_file_set_string(prefs, "main", "lang", g_lang);
    g_key_file_set_integer(prefs, "security", "autolock_seconds", (gint)g_app.autolock_seconds);
    g_key_file_set_integer(prefs, "security", "clipboard_clear_seconds", (gint)g_app.clipboard_clear_seconds);
    g_key_file_set_boolean(prefs, "security", "screenshot_guard", g_app.screenshot_guard);
    g_key_file_set_boolean(prefs, "security", "lock_on_focus_loss", g_app.lock_on_focus_loss);
    if (!g_app.mounted_carrier_path) {
        const char *last_db = g_app.current_file ? g_app.current_file : g_app.config_last_db;
        if (last_db) g_key_file_set_string(prefs, "main", "last_db", last_db);
    }

    GKeyFile *kf = NULL;
    gboolean ok = TRUE;
    if (g_app.camouflage_enabled) {
        if (!g_app.camouflage_key_valid || !g_app.camouflage_hash[0]) {
            ok = FALSE; /* Never downgrade encrypted settings to plaintext. */
        } else {
            gsize inner_len = 0;
            char *inner = g_key_file_to_data(prefs, &inner_len, NULL);
            if (!inner || inner_len > CAMOUFLAGE_CONFIG_LIMIT - 1024) ok = FALSE;
            if (ok) {
                unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
                randombytes_buf(nonce, sizeof(nonce));
                size_t capacity = inner_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
                unsigned char *cipher = g_malloc(capacity);
                unsigned long long cipher_len = 0;
                const unsigned char ad[] = CAMOUFLAGE_CONFIG_AD;
                if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                        cipher, &cipher_len, (unsigned char *)inner,
                        (unsigned long long)inner_len,
                        ad, sizeof(ad) - 1, NULL, nonce,
                        g_app.camouflage_config_key) != 0 || cipher_len > capacity) {
                    ok = FALSE;
                } else {
                    char salt_hex[crypto_pwhash_SALTBYTES * 2 + 1];
                    char nonce_hex[sizeof(nonce) * 2 + 1];
                    sodium_bin2hex(salt_hex, sizeof(salt_hex), g_app.camouflage_salt,
                                   sizeof(g_app.camouflage_salt));
                    sodium_bin2hex(nonce_hex, sizeof(nonce_hex), nonce, sizeof(nonce));
                    char *encoded = g_base64_encode(cipher, (gsize)cipher_len);
                    kf = g_key_file_new();
                    g_key_file_set_boolean(kf, "camouflage", "enabled", TRUE);
                    g_key_file_set_string(kf, "camouflage", "password_hash",
                                          g_app.camouflage_hash);
                    g_key_file_set_string(kf, "camouflage", "config_salt", salt_hex);
                    g_key_file_set_string(kf, "camouflage", "nonce", nonce_hex);
                    g_key_file_set_string(kf, "camouflage", "payload", encoded);
                    g_free(encoded);
                }
                sodium_memzero(cipher, capacity);
                g_free(cipher);
                sodium_memzero(nonce, sizeof(nonce));
            }
            if (inner) { sodium_memzero(inner, inner_len); g_free(inner); }
        }
    } else {
        kf = prefs;
        g_key_file_set_boolean(kf, "camouflage", "enabled", FALSE);
    }

    if (ok && kf) {
        gsize len = 0;
        char *data = g_key_file_to_data(kf, &len, NULL);
        if (!data) ok = FALSE;
        if (data) {
            char *tmp_path = g_strdup_printf("%s.tmp.XXXXXX", path);
            int fd = tmp_path ? g_mkstemp_full(tmp_path, O_WRONLY | O_CLOEXEC, 0600) : -1;
            ok = FALSE;
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
            sodium_memzero(data, len);
            g_free(data);
        }
    } else ok = FALSE;
    if (kf && kf != prefs) g_key_file_unref(kf);
    g_key_file_unref(prefs);
    g_free(path);
    return ok;
}

static gboolean load_config(void) {
    char *path = config_path();
    if (!path) return FALSE;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { g_free(path); return errno == ENOENT; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) || st.st_size < 0 || st.st_size > CAMOUFLAGE_CONFIG_LIMIT) {
        close(fd); g_free(path); return FALSE;
    }
    gsize len = (gsize)st.st_size;
    char *data = g_malloc(len + 1);
    if (!data) { close(fd); g_free(path); return FALSE; }
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
    if (ok) ok = g_utf8_validate(data, (gssize)len, NULL) &&
        g_key_file_load_from_data(kf, data, len, G_KEY_FILE_NONE, NULL);
    if (ok) {
        GError *err = NULL;
        gboolean enabled = g_key_file_get_boolean(kf, "camouflage", "enabled", &err);
        if (err) { enabled = FALSE; g_clear_error(&err); }
        g_app.camouflage_enabled = enabled;
        if (enabled) {
            char *hash = g_key_file_get_string(kf, "camouflage", "password_hash", NULL);
            ok = hash && strlen(hash) < sizeof(g_app.camouflage_hash) &&
                g_str_has_prefix(hash, crypto_pwhash_STRPREFIX);
            if (ok) g_strlcpy(g_app.camouflage_hash, hash, sizeof(g_app.camouflage_hash));
            if (hash) { sodium_memzero(hash, strlen(hash)); g_free(hash); }
            if (ok) {
                if (g_key_file_has_key(kf, "camouflage", "payload", NULL)) {
                    /* In protected format, settings are not parsed until the
                     * user has authenticated and the code-derived key exists. */
                    ok = camouflage_read_salt(kf);
                    if (ok && g_app.camouflage_key_valid)
                        ok = camouflage_decrypt_settings(kf);
                    g_app.camouflage_legacy_config = FALSE;
                } else if (!g_key_file_has_key(kf, "camouflage", "config_salt", NULL)) {
                    /* One-time upgrade from v5's plain preferences. Keep its
                     * settings in memory until successful PIN unlock, then
                     * atomically replace this file with encrypted content. */
                    if (!g_app.camouflage_legacy_config)
                        randombytes_buf(g_app.camouflage_salt, sizeof(g_app.camouflage_salt));
                    apply_user_settings(kf);
                    g_app.camouflage_legacy_config = TRUE;
                } else {
                    ok = FALSE; /* Broken/incomplete protected configuration. */
                }
            }
        } else {
            g_app.camouflage_legacy_config = FALSE;
            apply_user_settings(kf);
        }
    }
    sodium_memzero(data, len + 1);
    g_free(data);
    g_key_file_unref(kf);
    g_free(path);
    return ok;
}

static char *find_icon_path(void) {
    char svg_exe[PATH_MAX];
    ssize_t svg_len = readlink("/proc/self/exe", svg_exe, sizeof(svg_exe) - 1);
    if (svg_len > 0) {
        svg_exe[svg_len] = '\0';
        char *dir = g_path_get_dirname(svg_exe);
        char *path = g_build_filename(dir, "diskpass-icon.svg", NULL);
        g_free(dir);
        if (g_file_test(path, G_FILE_TEST_IS_REGULAR)) return path;
        g_free(path);
    }
    char *svg_dirs[] = {
        diskpass_private_dir(),
        g_build_filename(g_get_user_data_dir(), "diskpass", NULL),
        g_strdup("/usr/local/share/diskpass"), g_strdup("/usr/share/diskpass"), g_strdup(".")
    };
    char *svg_found = NULL;
    for (size_t i = 0; i < ARRAY_SIZE(svg_dirs); i++) {
        if (!svg_found) {
            char *path = g_build_filename(svg_dirs[i], "diskpass-icon.svg", NULL);
            if (g_file_test(path, G_FILE_TEST_IS_REGULAR)) svg_found = path;
            else g_free(path);
        }
        g_free(svg_dirs[i]);
    }
    if (svg_found) return svg_found;

    return NULL;
}

static GdkPixbuf *load_icon(int size) {
    if (size <= 0 || size > 4096) return NULL;
    char *path = find_icon_path();
    GdkPixbuf *pb = NULL;
    if (path) {
        if (!pb) pb = gdk_pixbuf_new_from_file_at_scale(path, size, size, TRUE, NULL);
        g_free(path);
    }
    if (!pb && icon_pb) pb = gdk_pixbuf_scale_simple(icon_pb, size, size, GDK_INTERP_HYPER);
    return pb;
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
    if (!text) return;
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, text, -1);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    g_app.clipboard_timer_id = g_timeout_add_seconds(g_app.clipboard_clear_seconds ? g_app.clipboard_clear_seconds : 30, clipboard_clear_timer, NULL);
}

static void on_gen_password(GtkButton *b, gpointer d) {
    (void)b;
    char *pw = generate_password(24);
    gtk_entry_set_text(GTK_ENTRY(d), pw);
    sec_strfree(pw);
}

static void on_back_to_welcome(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    if (g_unlock_running) return;


    g_db_external_commit_hook = NULL;
    if (g_app.autolock_timer_id) {
        g_source_remove(g_app.autolock_timer_id);
        g_app.autolock_timer_id = 0;
    }
    g_autolock_pending = FALSE;
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    free(g_app.current_file); g_app.current_file = NULL;
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    carrier_unmount_cleanup();
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
    if (app_has_open_database() && g_app.screenshot_guard) {
        if (ev->new_window_state & GDK_WINDOW_STATE_ICONIFIED)
            privacy_shield_set(TRUE);
        else if (gtk_window_is_active(g_app.window))
            privacy_shield_set(FALSE);
    }
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
    if (g_app.btn_open_stego) gtk_button_set_label(GTK_BUTTON(g_app.btn_open_stego), i18n("carrier_open_hidden_short"));
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
    if (g_app.unlock_status && g_unlock_running) gtk_label_set_text(GTK_LABEL(g_app.unlock_status), i18n("opening_db"));
    if (g_app.btn_lock) gtk_widget_set_tooltip_text(g_app.btn_lock, i18n("lock_db"));
    if (g_app.btn_add) gtk_widget_set_tooltip_text(g_app.btn_add, i18n("add_entry"));
    if (g_app.btn_edit) gtk_widget_set_tooltip_text(g_app.btn_edit, i18n("edit_entry"));
    if (g_app.btn_del) gtk_widget_set_tooltip_text(g_app.btn_del, i18n("del_entry"));
    if (g_app.btn_sch) gtk_widget_set_tooltip_text(g_app.btn_sch, i18n("show_schema"));
    if (g_app.btn_about) gtk_widget_set_tooltip_text(g_app.btn_about, i18n("about_diskpass"));
    if (g_app.btn_settings) gtk_widget_set_tooltip_text(g_app.btn_settings, i18n("security_settings"));
    if (g_app.privacy_shield_title) gtk_label_set_text(GTK_LABEL(g_app.privacy_shield_title), i18n("privacy_screen_title"));
    if (g_app.privacy_shield_desc) gtk_label_set_text(GTK_LABEL(g_app.privacy_shield_desc), i18n("privacy_screen_desc"));
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
    if (g_app.btn_carrier) gtk_widget_set_tooltip_text(g_app.btn_carrier, i18n("carrier_tools"));
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
            snprintf(fc, sizeof(fc), "%d", e->file_count);
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

static void tree_fill_cancel(void);
static void clear_details(void) {
    gtk_label_set_text(GTK_LABEL(g_app.lbl_main), i18n("select_entry"));
    GList *children = gtk_container_get_children(GTK_CONTAINER(g_app.grid));
    for (GList *l = children; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);
    gtk_label_set_text(GTK_LABEL(g_app.notes_text), "");
    gtk_widget_set_sensitive(g_app.btn_copy_label, FALSE);
    gtk_widget_set_sensitive(g_app.btn_copy_pass, FALSE);

    tree_fill_cancel();
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
    gboolean visible = TRUE;
    gtk_tree_model_get(model, iter, 3, &visible, -1);
    return visible;
}

static gboolean tree_update_visibility(GtkTreeModel *model, GtkTreeIter *iter) {
    gboolean self_match = !g_tree_filter_needle || !g_tree_filter_needle[0];
    if (!self_match) {
        char *name = NULL;
        gtk_tree_model_get(model, iter, 0, &name, -1);
        if (name) {
            char *low = g_ascii_strdown(name, -1);
            self_match = strstr(low, g_tree_filter_needle) != NULL;
            g_free(low);
            g_free(name);
        }
    }

    gboolean child_match = FALSE;
    GtkTreeIter child;
    if (gtk_tree_model_iter_children(model, &child, iter)) {
        do {
            if (tree_update_visibility(model, &child)) child_match = TRUE;
        } while (gtk_tree_model_iter_next(model, &child));
    }

    gboolean visible = self_match || child_match;
    gtk_tree_store_set(GTK_TREE_STORE(model), iter, 3, visible, -1);
    return visible;
}

static void on_tree_filter_changed(GtkSearchEntry *e, gpointer u) {
    (void)u;
    const char *txt = gtk_entry_get_text(GTK_ENTRY(e));

    free(g_tree_filter_needle);
    g_tree_filter_needle = (txt && txt[0]) ? g_ascii_strdown(txt, -1) : NULL;

    GtkTreeModel *store_model = GTK_TREE_MODEL(g_app.tree_store);
    GtkTreeIter root;
    if (gtk_tree_model_get_iter_first(store_model, &root)) {
        do {
            tree_update_visibility(store_model, &root);
        } while (gtk_tree_model_iter_next(store_model, &root));
    }

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


typedef struct {
    GList *next;
    GtkTreeIter parent;
    gboolean has_parent;
} TreeFillFrame;
static fs_node_t *g_tree_fill_root;
static GArray *g_tree_fill_stack;
static guint g_tree_fill_source;

static void tree_fill_cancel(void) {
    if (g_tree_fill_source) {
        g_source_remove(g_tree_fill_source);
        g_tree_fill_source = 0;
    }
    if (g_tree_fill_stack) {
        g_array_free(g_tree_fill_stack, TRUE);
        g_tree_fill_stack = NULL;
    }
    if (g_tree_fill_root) {
        fs_node_free(g_tree_fill_root);
        g_tree_fill_root = NULL;
    }
}

static gboolean tree_fill_step(gpointer unused) {
    (void)unused;
    gint64 deadline = g_get_monotonic_time() + 4000;
    unsigned inserted = 0;
    while (g_tree_fill_stack && g_tree_fill_stack->len &&
           inserted < 128 && g_get_monotonic_time() < deadline) {
        guint top = g_tree_fill_stack->len - 1;
        TreeFillFrame *frame = &g_array_index(g_tree_fill_stack, TreeFillFrame, top);
        if (!frame->next) {
            g_array_set_size(g_tree_fill_stack, top);
            continue;
        }
        fs_node_t *node = frame->next->data;
        frame->next = frame->next->prev;
        GtkTreeIter iter;
        char *size = (!node->is_dir && node->size >= 0) ? format_bytes(node->size) : NULL;
        gtk_tree_store_insert_with_values(g_app.tree_store, &iter,
            frame->has_parent ? &frame->parent : NULL, 0,
            0, node->name, 1, node->is_dir, 2, size ? size : "", 3, TRUE, -1);
        g_free(size);
        inserted++;
        if (node->is_dir && node->children) {
            TreeFillFrame child = { g_list_last(node->children), iter, TRUE };
            g_array_append_val(g_tree_fill_stack, child);
        }
    }
    if (g_tree_fill_stack && g_tree_fill_stack->len) return G_SOURCE_CONTINUE;
    g_tree_fill_source = 0;
    tree_fill_cancel();
    if (g_app.tree_filter) {
        gtk_widget_set_sensitive(g_app.tree_filter, TRUE);
        if (gtk_entry_get_text(GTK_ENTRY(g_app.tree_filter))[0])
            on_tree_filter_changed(GTK_SEARCH_ENTRY(g_app.tree_filter), NULL);
    }
    if (g_app.tree_expand_btn) gtk_widget_set_sensitive(g_app.tree_expand_btn, TRUE);
    return G_SOURCE_REMOVE;
}

static void build_file_tree(const char *files) {
    tree_fill_cancel();
    if (!g_app.tree_store) return;
    gtk_tree_store_clear(g_app.tree_store);
    if (g_app.tree_filter) gtk_widget_set_sensitive(g_app.tree_filter, TRUE);
    if (g_app.tree_expand_btn) gtk_widget_set_sensitive(g_app.tree_expand_btn, TRUE);
    if (!files || !files[0]) return;
    g_tree_fill_root = fs_build_tree(files);
    g_tree_fill_stack = g_array_new(FALSE, FALSE, sizeof(TreeFillFrame));
    TreeFillFrame first = {0};

    first.next = g_list_last(g_tree_fill_root->children);
    g_array_append_val(g_tree_fill_stack, first);
    if (g_app.tree_filter) gtk_widget_set_sensitive(g_app.tree_filter, FALSE);
    if (g_app.tree_expand_btn) gtk_widget_set_sensitive(g_app.tree_expand_btn, FALSE);
    g_tree_fill_source = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, tree_fill_step, NULL, NULL);
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
        int fc = e->file_count;
        char *ts = format_bytes(e->indexed_bytes);
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
        tree_fill_cancel();
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
static void request_system_security_lock(void);
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

static gboolean privacy_shield_hide_cb(gpointer user_data) {
    (void)user_data;
    g_app.privacy_shield_timer_id = 0;
    if (g_app.privacy_shield && gtk_window_is_active(g_app.window))
        gtk_widget_hide(g_app.privacy_shield);
    return G_SOURCE_REMOVE;
}

static void privacy_shield_set(gboolean visible) {
    if (!g_app.privacy_shield) return;
    if (g_app.privacy_shield_timer_id) {
        g_source_remove(g_app.privacy_shield_timer_id);
        g_app.privacy_shield_timer_id = 0;
    }
    if (visible && app_has_open_database() && g_app.screenshot_guard) {
        gtk_widget_show(g_app.privacy_shield);
    } else {
        gtk_widget_hide(g_app.privacy_shield);
    }
}

static gboolean focus_lock_cb(gpointer user_data) {
    (void)user_data;
    g_app.focus_lock_timer_id = 0;
    const char *visible = g_app.stack ? gtk_stack_get_visible_child_name(g_app.stack) : NULL;
    if (!app_has_open_database() || g_unlock_running || g_strcmp0(visible, "main") != 0 ||
        !g_app.lock_on_focus_loss || gtk_window_is_active(g_app.window) ||
        has_visible_modal_window())
        return G_SOURCE_REMOVE;
    request_system_security_lock();
    return G_SOURCE_REMOVE;
}

static gboolean on_security_focus_out(GtkWidget *w, GdkEventFocus *ev, gpointer user_data) {
    (void)w; (void)ev; (void)user_data;

    const char *visible = g_app.stack ? gtk_stack_get_visible_child_name(g_app.stack) : NULL;
    if (!app_has_open_database() || g_unlock_running || g_strcmp0(visible, "main") != 0 ||
        has_visible_modal_window()) return FALSE;
    if (g_app.screenshot_guard) privacy_shield_set(TRUE);
    if (g_app.lock_on_focus_loss) {
        if (g_app.focus_lock_timer_id) g_source_remove(g_app.focus_lock_timer_id);
        g_app.focus_lock_timer_id = g_timeout_add(250, focus_lock_cb, NULL);
    }
    return FALSE;
}

static gboolean on_security_focus_in(GtkWidget *w, GdkEventFocus *ev, gpointer user_data) {
    (void)w; (void)ev; (void)user_data;
    if (g_app.focus_lock_timer_id) {
        g_source_remove(g_app.focus_lock_timer_id);
        g_app.focus_lock_timer_id = 0;
    }
    privacy_shield_set(FALSE);
    reset_autolock();
    return FALSE;
}

static gboolean on_security_key_press(GtkWidget *w, GdkEventKey *ev, gpointer user_data) {
    (void)w; (void)user_data;
    if (!ev || !app_has_open_database() || !g_app.screenshot_guard) return FALSE;
    if (ev->keyval == GDK_KEY_Print || ev->keyval == GDK_KEY_Sys_Req) {
        privacy_shield_set(TRUE);
        g_app.privacy_shield_timer_id = g_timeout_add(1200, privacy_shield_hide_cb, NULL);
        return TRUE;
    }
    return FALSE;
}

static void on_lock_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    privacy_shield_set(FALSE);
    if (g_app.focus_lock_timer_id) {
        g_source_remove(g_app.focus_lock_timer_id);
        g_app.focus_lock_timer_id = 0;
    }
    g_autolock_pending = FALSE;
    if (g_app.autolock_timer_id) {
        g_source_remove(g_app.autolock_timer_id);
        g_app.autolock_timer_id = 0;
    }
    g_db_external_commit_hook = NULL;
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    free(g_app.current_file); g_app.current_file = NULL;
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    carrier_unmount_cleanup();
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


    if (g_batch_running || g_carrier_running || has_visible_modal_window()) {
        g_autolock_pending = TRUE;
        g_app.autolock_timer_id = g_timeout_add_seconds(1, autolock_cb, NULL);
        return G_SOURCE_REMOVE;
    }
    g_autolock_pending = FALSE;
    if (app_has_open_database()) on_lock_clicked(NULL, NULL);
    return G_SOURCE_REMOVE;
}

static void reset_autolock(void) {
    if (g_app.autolock_timer_id) g_source_remove(g_app.autolock_timer_id);
    g_app.autolock_timer_id = 0;
    if (app_has_open_database() && g_app.autolock_seconds > 0)
        g_app.autolock_timer_id =
            g_timeout_add_seconds(g_app.autolock_seconds, autolock_cb, NULL);
}

static gboolean on_user_activity(GtkWidget *w, GdkEvent *ev, gpointer u) {
    (void)w; (void)ev; (void)u;
    reset_autolock();
    return FALSE;
}

static void request_system_security_lock(void) {
    if (!app_has_open_database()) return;

    if (g_batch_running || g_carrier_running || has_visible_modal_window()) {
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
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(type_cb), "pqc");
    gtk_widget_set_sensitive(type_cb, FALSE);

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
    (void)secret_only;
    gtk_combo_box_text_remove_all(combo);
    if (!g_app.db) return;


    int count = 0;
    gpg_key_info_t *keys = gpg_list_keys(g_app.db->gpg_ctx, 0, &count);
    if (!keys || count == 0) {
        gtk_label_set_text(GTK_LABEL(err_label), i18n("no_keys"));
        gpg_free_key_list(keys, count); return;
    }


    for (int i = 0; i < count; i++) {

        char caps[128] = "";
        if (keys[i].has_pqc) g_strlcat(caps, "[PQC] ", sizeof(caps));
        if (keys[i].has_secret) g_strlcat(caps, "[SECRET] ", sizeof(caps));
        else g_strlcat(caps, "[PUBLIC ONLY] ", sizeof(caps));
        if (!keys[i].has_secret_sign) g_strlcat(caps, "[NO SIGN SECRET] ", sizeof(caps));
        if (!keys[i].has_secret_encrypt) g_strlcat(caps, "[NO DECRYPT SECRET] ", sizeof(caps));
        if (!keys[i].can_encrypt) g_strlcat(caps, "[NO ENCRYPT] ", sizeof(caps));
        char *display = g_strdup_printf("%s %s", caps, keys[i].uid);
        gtk_combo_box_text_append(combo, keys[i].fingerprint, display);
        g_free(display);
    }


    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), -1);
    gtk_label_set_text(GTK_LABEL(err_label), "");
    gpg_free_key_list(keys, count);
}

static void on_change_key_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!app_has_open_database() || g_app.db->legacy_read_only || g_carrier_running) return;


    int count = 0;
    gpg_key_info_t *keys = gpg_list_keys(g_app.db->gpg_ctx, 0, &count);
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


    for (int i = 0; i < count; i++) {
        char caps[128] = "";
        if (keys[i].has_pqc) g_strlcat(caps, "[PQC] ", sizeof(caps));
        if (keys[i].has_secret) g_strlcat(caps, "[SECRET] ", sizeof(caps));
        else g_strlcat(caps, "[PUBLIC ONLY] ", sizeof(caps));
        if (!keys[i].has_secret_sign) g_strlcat(caps, "[NO SIGN SECRET] ", sizeof(caps));
        if (!keys[i].has_secret_encrypt) g_strlcat(caps, "[NO DECRYPT SECRET] ", sizeof(caps));
        if (!keys[i].can_encrypt) g_strlcat(caps, "[NO ENCRYPT] ", sizeof(caps));
        char *display = g_strdup_printf("%s %s", caps, keys[i].uid);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), keys[i].fingerprint, display);
        g_free(display);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), -1);
    gtk_box_pack_start(GTK_BOX(new_box), combo, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(content), new_box, FALSE, FALSE, 0);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const gchar *selected = gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
        if (selected && (!g_app.db->recipient || g_ascii_strcasecmp(selected, g_app.db->recipient) != 0)) {
            char *new_fp = xstrdup(selected);
            char key_err[256] = "";
            gboolean valid = gpg_key_usable_for_database(g_app.db->gpg_ctx, new_fp,
                g_app.db->require_pqc, key_err, sizeof(key_err));
            if (!valid) {
                secure_free_string(&new_fp);
                show_save_error(key_err[0] ? key_err : i18n("selected_key_invalid"));
            } else {
                char *old_fp = g_app.db->recipient;
                g_app.db->recipient = new_fp;
                char err[256] = "";
                int history_before = g_app.db->history_count;
                if (db_history_mark(g_app.db, "key_changed", "", &history_before, err, sizeof(err)) != 0) {
                    secure_free_string(&g_app.db->recipient);
                    g_app.db->recipient = old_fp;
                    show_save_error(err);
                } else if (db_save(g_app.db, err, sizeof(err)) != 0) {
                    db_history_restore_count(g_app.db, history_before);
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

static gboolean prepare_unlock_for_db_path(const char *db_path, const char *display_path) {
    if (!db_path || !db_path[0]) return FALSE;

    free(g_app.current_file);
    g_app.current_file = xstrdup(db_path);
    if (!g_app.current_file) return FALSE;

    char info[768];
    snprintf(info, sizeof(info), "%s %s", i18n("file"),
        (display_path && display_path[0]) ? display_path : db_path);
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

    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    g_app.db = calloc(1, sizeof(db_manager_t));
    if (!g_app.db) return FALSE;
    db_manager_init(g_app.db);
    if (ensure_db_gpg(g_app.db) != 0) {
        db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL;
        return FALSE;
    }
    if (g_app.unlock_status) gtk_label_set_text(GTK_LABEL(g_app.unlock_status), "");
    if (g_app.unlock_err) gtk_label_set_text(GTK_LABEL(g_app.unlock_err), "");
    populate_gpg_keys(GTK_COMBO_BOX_TEXT(g_app.unlock_key_combo), 1, g_app.unlock_err);
    gtk_stack_set_visible_child_name(g_app.stack, "unlock");
    return TRUE;
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
        if (chosen_path) {
            carrier_unmount_cleanup();
            if (!prepare_unlock_for_db_path(chosen_path, chosen_path))
                gtk_label_set_text(GTK_LABEL(g_app.unlock_err), i18n("file_corrupted"));
            g_free(chosen_path);
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
        carrier_unmount_cleanup();
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


    if (!g_app.db || !g_app.db->gpg_ctx ||
        !gpg_key_usable_for_database(g_app.db->gpg_ctx, recipient, TRUE, err_buf, sizeof(err_buf))) {
        gtk_label_set_text(GTK_LABEL(g_app.setup_err),
            err_buf[0] ? err_buf : i18n("selected_key_invalid"));
        return;
    }
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    g_app.db = db_manager_create(g_app.current_file, recipient, g_lang, err_buf, sizeof(err_buf));
    if (!g_app.db) { gtk_label_set_text(GTK_LABEL(g_app.setup_err), err_buf); return; }
    update_ui_text();
    g_app.current_entry_idx = -1;
    if (g_known_uuids) g_hash_table_remove_all(g_known_uuids);
    g_uuids_initialized = FALSE;
    if (!save_config()) g_warning("DiskPass: configuration could not be saved");
    reset_autolock();
    gtk_stack_set_visible_child_name(g_app.stack, "main");
    refresh_entry_list();
    update_db_write_controls();
}

typedef struct {
    char *path;
    char *key_fingerprint;
    gboolean mounted_carrier;
} unlock_job_t;

static void unlock_job_free(unlock_job_t *job) {
    if (!job) return;
    if (job->key_fingerprint) {
        sodium_memzero(job->key_fingerprint, strlen(job->key_fingerprint));
        g_free(job->key_fingerprint);
    }
    g_free(job->path);
    g_free(job);
}

static void unlock_manager_free(gpointer data) {
    db_manager_t *m = data;
    if (!m) return;
    db_manager_clear(m);
    free(m);
}

static void unlock_set_busy(gboolean busy) {
    g_unlock_running = busy;
    if (g_app.btn_unlock) gtk_widget_set_sensitive(g_app.btn_unlock, !busy);
    if (g_app.btn_unlock_back) gtk_widget_set_sensitive(g_app.btn_unlock_back, !busy);
    if (g_app.unlock_key_combo) gtk_widget_set_sensitive(g_app.unlock_key_combo, !busy);
    if (g_app.btn_create_key_unlock) gtk_widget_set_sensitive(g_app.btn_create_key_unlock, !busy);
    if (g_app.unlock_status)
        gtk_label_set_text(GTK_LABEL(g_app.unlock_status), busy ? i18n("opening_db") : "");
}

static void unlock_job_worker(GTask *task, gpointer source_object, gpointer task_data,
    GCancellable *cancellable)
{
    (void)source_object; (void)cancellable;
    unlock_job_t *job = task_data;
    char err_buf[384] = "";
    db_manager_t *opened = db_manager_open(job->path, job->key_fingerprint,
        TRUE, TRUE, err_buf, sizeof(err_buf));
    if (!opened) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_FAILED, "%s",
            err_buf[0] ? err_buf : "Database open failed");
        return;
    }
    g_task_return_pointer(task, opened, unlock_manager_free);
}

static void unlock_job_done(GObject *source, GAsyncResult *result, gpointer user_data) {
    (void)source; (void)user_data;
    GTask *task = G_TASK(result);
    unlock_job_t *job = g_task_get_task_data(task);
    GError *error = NULL;
    db_manager_t *opened = g_task_propagate_pointer(task, &error);
    unlock_set_busy(FALSE);

    if (!job || !g_app.current_file || strcmp(g_app.current_file, job->path) != 0) {
        if (opened) unlock_manager_free(opened);
        g_clear_error(&error);
        return;
    }

    if (!opened) {
        const char *unlock_msg = error && error->message ? error->message : i18n("file_corrupted");
        if (unlock_msg && strcmp(unlock_msg, i18n("sig_mismatch")) == 0) unlock_msg = "";
        gtk_label_set_text(GTK_LABEL(g_app.unlock_err), unlock_msg ? unlock_msg : "");
        g_clear_error(&error);
        return;
    }

    if (job->mounted_carrier) {
        char carrier_err[256] = "";
        if (!g_app.mounted_carrier_path || !g_app.mounted_temp_db_path ||
            strcmp(g_app.mounted_temp_db_path, job->path) != 0 ||
            !carrier_identity_unchanged(carrier_err, sizeof(carrier_err))) {
            unlock_manager_free(opened);
            gtk_label_set_text(GTK_LABEL(g_app.unlock_err),
                carrier_err[0] ? carrier_err : i18n("carrier_changed_during_open"));
            g_clear_error(&error);
            return;
        }
    }


    if (!opened->has_commit_chain) {
        unlock_set_busy(TRUE);
        GtkWidget *dlg = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
            GTK_MESSAGE_WARNING, GTK_BUTTONS_NONE, "%s", i18n("legacy_consent"));
        gtk_dialog_add_buttons(GTK_DIALOG(dlg),
            i18n("cancel"), GTK_RESPONSE_CANCEL,
            i18n("legacy_open_read_only"), GTK_RESPONSE_NO,
            i18n("legacy_convert"), GTK_RESPONSE_YES, NULL);
        gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_CANCEL);
        int choice = gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        opened->defer_chainless_consent = FALSE;
        if (choice != GTK_RESPONSE_NO && choice != GTK_RESPONSE_YES) {
            unlock_manager_free(opened);
            unlock_set_busy(FALSE);
            return;
        }
        if (choice == GTK_RESPONSE_YES) {

            g_db_external_commit_hook = job->mounted_carrier ? carrier_mounted_commit_hook : NULL;
            char conversion_err[512] = "";
            opened->legacy_read_only = FALSE;
            int rc = db_save(opened, conversion_err, sizeof(conversion_err));
            if (rc != 0 || !opened->rollback_state_verified) {
                opened->legacy_read_only = TRUE;
                gtk_label_set_text(GTK_LABEL(g_app.unlock_err), rc != 0
                    ? conversion_err : i18n("legacy_conversion_state_failed"));
                g_db_external_commit_hook = NULL;
                unlock_manager_free(opened);
                unlock_set_busy(FALSE);
                return;
            }
        }
        unlock_set_busy(FALSE);
    }
    opened->defer_chainless_consent = FALSE;

    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
    g_app.db = opened;
    if (g_app.mounted_carrier_path)
        g_db_external_commit_hook = carrier_mounted_commit_hook;
    else
        g_db_external_commit_hook = NULL;

    gtk_label_set_text(GTK_LABEL(g_app.unlock_err), "");
    update_ui_text();
    g_app.current_entry_idx = -1;
    if (g_known_uuids) g_hash_table_remove_all(g_known_uuids);
    g_uuids_initialized = FALSE;
    if (!save_config()) g_warning("DiskPass: configuration could not be saved");
    reset_autolock();
    gtk_stack_set_visible_child_name(g_app.stack, "main");
    refresh_entry_list();
    update_db_write_controls();
    if (g_app.db->legacy_read_only) {
        show_toast(i18n("legacy_read_only"), 15000, -1);
    } else if (!g_app.db->is_pqc_encrypted) {
        if (db_recipient_has_pqc(g_app.db))
            show_toast(i18n("legacy_upgrade_msg"), 12000, -1);
        else
            show_toast(i18n("legacy_classic_msg"), 15000, -1);
    } else if (g_app.mounted_carrier_path) {
        show_toast(i18n("carrier_mounted_active"), 9000, -1);
    }
    g_clear_error(&error);
}

static void on_unlock_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.current_file || g_unlock_running) return;
    const gchar *selected_fp = gtk_combo_box_get_active_id(GTK_COMBO_BOX(g_app.unlock_key_combo));
    if (!selected_fp) { gtk_label_set_text(GTK_LABEL(g_app.unlock_err), i18n("pgp_key")); return; }
    char key_err[256] = "";
    if (!g_app.db || !g_app.db->gpg_ctx ||
        !gpg_key_usable_for_unlock(g_app.db->gpg_ctx, selected_fp, key_err, sizeof(key_err))) {
        gtk_label_set_text(GTK_LABEL(g_app.unlock_err),
            key_err[0] ? key_err : i18n("selected_key_invalid"));
        return;
    }

    unlock_job_t *job = g_new0(unlock_job_t, 1);
    if (!job) {
        gtk_label_set_text(GTK_LABEL(g_app.unlock_err), "Out of memory");
        return;
    }
    job->path = g_strdup(g_app.current_file);
    job->key_fingerprint = g_strdup(selected_fp);
    job->mounted_carrier = g_app.mounted_carrier_path != NULL;
    if (!job->path || !job->key_fingerprint) {
        unlock_job_free(job);
        gtk_label_set_text(GTK_LABEL(g_app.unlock_err), "Out of memory");
        return;
    }

    gtk_label_set_text(GTK_LABEL(g_app.unlock_err), "");
    unlock_set_busy(TRUE);
    GTask *task = g_task_new(NULL, NULL, unlock_job_done, NULL);
    g_task_set_task_data(task, job, (GDestroyNotify)unlock_job_free);
    g_task_run_in_thread(task, unlock_job_worker);
    g_object_unref(task);
}

static void on_delete_clicked(GtkButton *btn, gpointer user_data) {
    if (app_has_open_database() && g_app.db->legacy_read_only) return;
    (void)btn; (void)user_data;
    if (!app_has_open_database() || g_app.db->legacy_read_only || g_carrier_running) return;
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
    gboolean have_db = app_has_open_database();

    gboolean writable = have_db && !g_app.db->legacy_read_only && !g_carrier_running;
    if (g_app.btn_add) gtk_widget_set_sensitive(g_app.btn_add, writable);
    if (g_app.btn_edit) gtk_widget_set_sensitive(g_app.btn_edit, writable);
    if (g_app.btn_del) gtk_widget_set_sensitive(g_app.btn_del, writable);
    if (g_app.btn_snapshot) gtk_widget_set_sensitive(g_app.btn_snapshot, writable);
    if (g_app.btn_smart) gtk_widget_set_sensitive(g_app.btn_smart, writable);
    if (g_app.btn_batch) gtk_widget_set_sensitive(g_app.btn_batch, writable);
    if (g_app.btn_find) gtk_widget_set_sensitive(g_app.btn_find, writable);
    if (g_app.btn_rekey) gtk_widget_set_sensitive(g_app.btn_rekey, writable);
    if (g_app.btn_carrier) gtk_widget_set_sensitive(g_app.btn_carrier,
        have_db && !g_carrier_running && !g_batch_running);
}

typedef enum {
    CARRIER_JOB_ATTACH = 1,
    CARRIER_JOB_EXTRACT = 2,
    CARRIER_JOB_OPEN = 3
} carrier_job_mode_t;

typedef struct {
    carrier_job_mode_t mode;
    char *input_path;
    char *db_path;
    char *output_path;
    dev_t input_dev;
    ino_t input_ino;
    off_t input_size;
    struct timespec input_mtim;
    gboolean input_identity_valid;
} carrier_job_t;

static void carrier_job_free(carrier_job_t *job) {
    if (!job) return;
    g_free(job->input_path);
    g_free(job->db_path);
    g_free(job->output_path);
    g_free(job);
}

static void carrier_job_worker(GTask *task, gpointer source_object, gpointer task_data,
    GCancellable *cancellable)
{
    (void)source_object; (void)cancellable;
    carrier_job_t *job = (carrier_job_t *)task_data;
    char err[384] = "";
    int rc = -1;
    if (job && job->mode == CARRIER_JOB_ATTACH)
        rc = carrier_attach_dpdb(job->input_path, job->db_path, job->output_path, err, sizeof(err));
    else if (job && (job->mode == CARRIER_JOB_EXTRACT || job->mode == CARRIER_JOB_OPEN))
        rc = carrier_extract_dpdb(job->input_path, job->output_path, err, sizeof(err));
    if (rc == 0) g_task_return_boolean(task, TRUE);
    else g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_FAILED, "%s", err[0] ? err : "Steganography operation failed");
}

static gboolean carrier_job_input_unchanged(const carrier_job_t *job) {
    if (!job || !job->input_identity_valid || !job->input_path) return FALSE;
    struct stat st;
    if (lstat(job->input_path, &st) != 0 || !S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) return FALSE;
    return st.st_dev == job->input_dev && st.st_ino == job->input_ino &&
        st.st_size == job->input_size && st.st_mtim.tv_sec == job->input_mtim.tv_sec &&
        st.st_mtim.tv_nsec == job->input_mtim.tv_nsec;
}

static void carrier_job_done(GObject *source, GAsyncResult *result, gpointer user_data) {
    (void)source; (void)user_data;
    GTask *task = G_TASK(result);
    carrier_job_t *job = (carrier_job_t *)g_task_get_task_data(task);
    GError *error = NULL;
    gboolean ok = g_task_propagate_boolean(task, &error);
    g_carrier_running = FALSE;
    update_db_write_controls();
    if (!ok) {
        if (job && job->mode == CARRIER_JOB_OPEN && job->output_path) (void)unlink(job->output_path);
        GtkWidget *dlg = gtk_message_dialog_new(g_app.window,
            GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s",
            error && error->message ? error->message : i18n("carrier_failed"));
        gtk_window_set_title(GTK_WINDOW(dlg), i18n("carrier_tools"));
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        g_clear_error(&error);
        return;
    }

    if (job && job->mode == CARRIER_JOB_OPEN) {
        if (!carrier_job_input_unchanged(job)) {
            if (job->output_path) (void)unlink(job->output_path);
            GtkWidget *dlg = gtk_message_dialog_new(g_app.window,
                GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", i18n("carrier_changed_during_open"));
            gtk_dialog_run(GTK_DIALOG(dlg)); gtk_widget_destroy(dlg);
            return;
        }

        carrier_unmount_cleanup();
        g_app.mounted_carrier_path = g_strdup(job->input_path);
        g_app.mounted_temp_db_path = g_strdup(job->output_path);
        if (!g_app.mounted_carrier_path || !g_app.mounted_temp_db_path ||
            !carrier_capture_identity(g_app.mounted_carrier_path) ||
            !prepare_unlock_for_db_path(g_app.mounted_temp_db_path, g_app.mounted_carrier_path)) {
            if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
            free(g_app.current_file); g_app.current_file = NULL;
            free(g_app.expected_fp); g_app.expected_fp = NULL;
            carrier_unmount_cleanup();
            GtkWidget *dlg = gtk_message_dialog_new(g_app.window,
                GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", i18n("carrier_open_failed"));
            gtk_dialog_run(GTK_DIALOG(dlg)); gtk_widget_destroy(dlg);
            return;
        }
        show_toast(i18n("carrier_open_ready"), 7000, -1);
        return;
    }
    show_toast(i18n("carrier_done"), 7000, -1);
}

static void carrier_start_job(carrier_job_t *job) {
    if (!job || g_carrier_running) { carrier_job_free(job); return; }
    g_carrier_running = TRUE;
    update_db_write_controls();
    show_toast(i18n("carrier_working"), 5000, -1);
    GTask *task = g_task_new(NULL, NULL, carrier_job_done, NULL);
    g_task_set_task_data(task, job, (GDestroyNotify)carrier_job_free);
    g_task_run_in_thread(task, carrier_job_worker);
    g_object_unref(task);
}

static gboolean carrier_suffix_ci(const char *path, const char *suffix) {
    if (!path || !suffix) return FALSE;
    size_t lp = strlen(path), ls = strlen(suffix);
    return lp >= ls && g_ascii_strcasecmp(path + lp - ls, suffix) == 0;
}

static const char *carrier_kind_ui_name(carrier_kind_t kind) {
    switch (kind) {
        case CARRIER_KIND_JPEG: return "JPEG / DCT";
        case CARRIER_KIND_MP3: return "MP3 / ID3 cover";
        case CARRIER_KIND_FLAC: return "FLAC / PICTURE cover";
        case CARRIER_KIND_WAV: return "PCM WAV / sample LSB";
        case CARRIER_KIND_IMAGE: return "Lossless image / pixel LSB";
        default: return "Unsupported";
    }
}

static const char *carrier_preferred_ext(const char *path, carrier_kind_t kind) {
    if (kind == CARRIER_KIND_WAV) return ".wav";
    if (kind == CARRIER_KIND_MP3) return ".mp3";
    if (kind == CARRIER_KIND_FLAC) return ".flac";
    if (kind == CARRIER_KIND_JPEG) return carrier_suffix_ci(path, ".jpeg") ? ".jpeg" : ".jpg";
    if (kind == CARRIER_KIND_IMAGE) {
        if (carrier_suffix_ci(path, ".bmp")) return ".bmp";
        if (carrier_suffix_ci(path, ".webp")) return ".webp";
        if (carrier_suffix_ci(path, ".tiff")) return ".tiff";
        if (carrier_suffix_ci(path, ".tif")) return ".tif";
        if (carrier_suffix_ci(path, ".ppm")) return ".ppm";
        if (carrier_suffix_ci(path, ".pnm")) return ".pnm";
        if (carrier_suffix_ci(path, ".tga")) return ".tga";
        return ".png";
    }
    return ".png";
}

static gchar *carrier_default_output_name(const char *path, carrier_kind_t kind) {
    gchar *base = g_path_get_basename(path ? path : "carrier");
    const char *ext = carrier_preferred_ext(path, kind);
    if (!base) return g_strdup_printf("stego%s", ext);
    char *dot = strrchr(base, '.');
    gchar *out = (dot && dot != base)
        ? g_strdup_printf("%.*s-stego%s", (int)(dot - base), base, ext)
        : g_strdup_printf("%s-stego%s", base, ext);
    g_free(base);
    return out;
}

static gchar *carrier_choose_open(const char *title) {
    GtkWidget *dlg = gtk_file_chooser_dialog_new(title, g_app.window,
        GTK_FILE_CHOOSER_ACTION_OPEN,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("carrier_open"), GTK_RESPONSE_OK, NULL);

    GtkFileFilter *supported = gtk_file_filter_new();
    gtk_file_filter_set_name(supported, i18n("carrier_supported"));
    const char *patterns[] = {
        "*.jpg","*.jpeg","*.jpe","*.jfif","*.png","*.webp","*.bmp","*.tif","*.tiff","*.ppm","*.pnm","*.tga",
        "*.gif","*.ico","*.xpm","*.svg","*.pgm","*.pbm","*.wav","*.mp3","*.flac",
        "*.JPG","*.JPEG","*.JPE","*.JFIF","*.PNG","*.WEBP","*.BMP","*.TIF","*.TIFF","*.PPM","*.PNM","*.TGA",
        "*.GIF","*.ICO","*.XPM","*.SVG","*.PGM","*.PBM","*.WAV","*.MP3","*.FLAC"
    };
    for (size_t i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++)
        gtk_file_filter_add_pattern(supported, patterns[i]);
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), supported);

    GtkFileFilter *images = gtk_file_filter_new();
    gtk_file_filter_set_name(images, i18n("carrier_images"));
    const char *image_mimes[] = {
        "image/jpeg","image/png","image/webp","image/bmp","image/tiff","image/gif",
        "image/x-icon","image/x-portable-anymap","image/x-tga","image/x-xpixmap","image/svg+xml"
    };
    for (size_t i = 0; i < sizeof(image_mimes)/sizeof(image_mimes[0]); i++)
        gtk_file_filter_add_mime_type(images, image_mimes[i]);
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), images);

    GtkFileFilter *audio = gtk_file_filter_new();
    gtk_file_filter_set_name(audio, i18n("carrier_audio"));
    gtk_file_filter_add_mime_type(audio, "audio/x-wav");
    gtk_file_filter_add_mime_type(audio, "audio/wav");
    gtk_file_filter_add_mime_type(audio, "audio/mpeg");
    gtk_file_filter_add_mime_type(audio, "audio/flac");
    gtk_file_filter_add_pattern(audio, "*.wav"); gtk_file_filter_add_pattern(audio, "*.WAV");
    gtk_file_filter_add_pattern(audio, "*.mp3"); gtk_file_filter_add_pattern(audio, "*.MP3");
    gtk_file_filter_add_pattern(audio, "*.flac"); gtk_file_filter_add_pattern(audio, "*.FLAC");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), audio);

    GtkFileFilter *all = gtk_file_filter_new();
    gtk_file_filter_set_name(all, i18n("carrier_all_files"));
    gtk_file_filter_add_pattern(all, "*");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), all);

    gchar *path = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK)
        path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
    gtk_widget_destroy(dlg);
    return path;
}

static gchar *carrier_replace_extension(gchar *path, const char *ext) {
    if (!path || !ext) return path;
    if (carrier_suffix_ci(path, ext)) return path;
    char *slash = strrchr(path, G_DIR_SEPARATOR);
    char *dot = strrchr(path, '.');
    gchar *fixed = (dot && (!slash || dot > slash))
        ? g_strdup_printf("%.*s%s", (int)(dot - path), path, ext)
        : g_strconcat(path, ext, NULL);
    g_free(path);
    return fixed;
}

static gchar *carrier_choose_save(const char *title, const char *suggested, gboolean dpdb) {
    GtkWidget *dlg = gtk_file_chooser_dialog_new(title, g_app.window,
        GTK_FILE_CHOOSER_ACTION_SAVE,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("save"), GTK_RESPONSE_OK, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    if (suggested && *suggested) gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), suggested);

    const char *expected = ".dpdb";
    const char *label = "DiskPass (*.dpdb)";
    if (!dpdb) {
        static const struct { const char *ext; const char *label; } fmts[] = {
            {".jpeg","JPEG DCT (*.jpeg)"},{".jpg","JPEG DCT (*.jpg)"},{".wav","PCM WAV (*.wav)"},
            {".mp3","MP3 stego cover (*.mp3)"},{".flac","FLAC stego cover (*.flac)"},
            {".webp","Lossless WebP (*.webp)"},{".tiff","TIFF (*.tiff)"},{".tif","TIFF (*.tif)"},
            {".bmp","BMP (*.bmp)"},{".ppm","PPM (*.ppm)"},{".pnm","PNM/PPM (*.pnm)"},
            {".tga","TGA (*.tga)"},{".png","PNG (*.png)"}
        };
        expected = ".png"; label = "PNG (*.png)";
        for (size_t i=0;i<sizeof(fmts)/sizeof(fmts[0]);i++) {
            if (carrier_suffix_ci(suggested, fmts[i].ext)) { expected=fmts[i].ext; label=fmts[i].label; break; }
        }
    }
    GtkFileFilter *f = gtk_file_filter_new();
    gtk_file_filter_set_name(f, label);
    gchar *pattern = g_strdup_printf("*%s", expected);
    gtk_file_filter_add_pattern(f, pattern); g_free(pattern);
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), f);

    gchar *path = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK)
        path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
    gtk_widget_destroy(dlg);
    return carrier_replace_extension(path, expected);
}

static char *carrier_make_private_temp_db(char *err_msg, size_t err_msg_sz) {
    const char *base = g_get_user_runtime_dir();
    if (!base || !base[0]) base = g_get_user_cache_dir();
    if (!base || !base[0]) {
        snprintf(err_msg, err_msg_sz, "No private runtime directory is available");
        return NULL;
    }
    char *dir = g_build_filename(base, "diskpass", "stego-open", NULL);
    if (!dir) { snprintf(err_msg, err_msg_sz, "Out of memory for runtime path"); return NULL; }
    if (g_mkdir_with_parents(dir, 0700) != 0 || chmod(dir, 0700) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot create private stego runtime directory: %s", strerror(errno));
        g_free(dir); return NULL;
    }
    struct stat st;
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & (S_IRWXG | S_IRWXO))) {
        snprintf(err_msg, err_msg_sz, "Stego runtime directory is not private");
        g_free(dir); return NULL;
    }
    char hex[33];
    for (int attempt = 0; attempt < 32; attempt++) {
        unsigned char rnd[16]; randombytes_buf(rnd, sizeof(rnd));
        for (size_t i = 0; i < sizeof(rnd); i++) snprintf(hex + i*2, 3, "%02x", rnd[i]);
        sodium_memzero(rnd, sizeof(rnd));
        char *path = g_strdup_printf("%s/%s.dpdb", dir, hex);
        if (!path) break;
        if (lstat(path, &st) != 0 && errno == ENOENT) { g_free(dir); return path; }
        g_free(path);
    }
    snprintf(err_msg, err_msg_sz, "Cannot allocate a unique private database path");
    g_free(dir);
    return NULL;
}

static gboolean carrier_capture_identity(const char *path) {
    struct stat st;
    if (!path || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
        g_app.mounted_carrier_identity_valid = FALSE;
        return FALSE;
    }


    if (st.st_nlink != 1) {
        g_app.mounted_carrier_identity_valid = FALSE;
        return FALSE;
    }

    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        g_app.mounted_carrier_identity_valid = FALSE;
        return FALSE;
    }
    char hash_err[128] = "";
    if (stego_keyed_hash_fd(fd, (uint64_t)st.st_size, g_app.mounted_carrier_hash,
            hash_err, sizeof(hash_err)) != 0) {
        close(fd);
        g_app.mounted_carrier_identity_valid = FALSE;
        return FALSE;
    }
    close(fd);

    g_app.mounted_carrier_dev = st.st_dev;
    g_app.mounted_carrier_ino = st.st_ino;
    g_app.mounted_carrier_size = st.st_size;
    g_app.mounted_carrier_mtim = st.st_mtim;
    g_app.mounted_carrier_identity_valid = TRUE;
    return TRUE;
}

static void carrier_unmount_cleanup(void) {
    g_db_external_commit_hook = NULL;
    if (g_app.mounted_temp_db_path) {
        (void)unlink(g_app.mounted_temp_db_path);
        size_t n = strlen(g_app.mounted_temp_db_path) + sizeof(".bak");
        char *bak = malloc(n);
        if (bak) { snprintf(bak, n, "%s.bak", g_app.mounted_temp_db_path); (void)unlink(bak); free(bak); }
    }
    g_free(g_app.mounted_carrier_path); g_app.mounted_carrier_path = NULL;
    g_free(g_app.mounted_temp_db_path); g_app.mounted_temp_db_path = NULL;
    g_app.mounted_carrier_identity_valid = FALSE;
}

static gboolean carrier_identity_unchanged(char *err_msg, size_t err_msg_sz) {
    if (!g_app.mounted_carrier_path || !g_app.mounted_carrier_identity_valid) {
        snprintf(err_msg, err_msg_sz, "Steganographic carrier is not mounted");
        return FALSE;
    }
    struct stat st;
    if (lstat(g_app.mounted_carrier_path, &st) != 0 || !S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
        snprintf(err_msg, err_msg_sz, "Mounted carrier is no longer the same regular file");
        return FALSE;
    }
    if (st.st_dev != g_app.mounted_carrier_dev || st.st_ino != g_app.mounted_carrier_ino ||
        st.st_size != g_app.mounted_carrier_size ||
        st.st_mtim.tv_sec != g_app.mounted_carrier_mtim.tv_sec ||
        st.st_mtim.tv_nsec != g_app.mounted_carrier_mtim.tv_nsec) {
        snprintf(err_msg, err_msg_sz,
            "The steganographic carrier changed outside DiskPass; refusing to overwrite it");
        return FALSE;
    }


    if (st.st_nlink != 1) {
        snprintf(err_msg, err_msg_sz,
            "Carrier has multiple hard links; refusing to overwrite (potential attack)");
        return FALSE;
    }
    int fd = open(g_app.mounted_carrier_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err_msg, err_msg_sz, "Cannot re-open carrier for integrity check: %s", strerror(errno));
        return FALSE;
    }
    unsigned char current_hash[32];
    char hash_err[128] = "";
    gboolean hash_ok = (stego_keyed_hash_fd(fd, (uint64_t)st.st_size, current_hash,
            hash_err, sizeof(hash_err)) == 0);
    close(fd);
    if (!hash_ok || sodium_memcmp(current_hash, g_app.mounted_carrier_hash, 32) != 0) {
        sodium_memzero(current_hash, sizeof(current_hash));
        snprintf(err_msg, err_msg_sz,
            "Carrier content integrity check failed; the file was modified outside DiskPass");
        return FALSE;
    }
    sodium_memzero(current_hash, sizeof(current_hash));
    return TRUE;
}

static int carrier_mounted_commit_hook(const char *db_path, char *err_msg, size_t err_msg_sz) {
    if (!g_app.mounted_carrier_path || !db_path ||
        !g_app.mounted_temp_db_path || strcmp(db_path, g_app.mounted_temp_db_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Invalid steganographic mount state");
        return -1;
    }
    if (!carrier_identity_unchanged(err_msg, err_msg_sz)) return -1;

    carrier_kind_t kind = carrier_detect_kind(g_app.mounted_carrier_path);
    if (kind == CARRIER_KIND_UNKNOWN) {
        snprintf(err_msg, err_msg_sz, "Mounted carrier format is no longer recognized");
        return -1;
    }
    const char *ext = carrier_preferred_ext(g_app.mounted_carrier_path, kind);
    char *dir = g_path_get_dirname(g_app.mounted_carrier_path);
    if (!dir) { snprintf(err_msg, err_msg_sz, "Cannot resolve carrier directory"); return -1; }

    char *stage = NULL;
    for (int attempt = 0; attempt < 32 && !stage; attempt++) {
        unsigned char rnd[12]; char hex[25];
        randombytes_buf(rnd, sizeof(rnd));
        for (size_t i=0;i<sizeof(rnd);i++) snprintf(hex+i*2,3,"%02x",rnd[i]);
        sodium_memzero(rnd,sizeof(rnd));
        char *candidate = g_strdup_printf("%s/.diskpass-stego-%s%s", dir, hex, ext);
        struct stat st;
        if (candidate && lstat(candidate, &st) != 0 && errno == ENOENT) stage = candidate;
        else g_free(candidate);
    }
    g_free(dir);
    if (!stage) { snprintf(err_msg, err_msg_sz, "Cannot allocate carrier update path"); return -1; }

    g_atomic_int_set(&g_stego_replace_existing_payload, 1);
    int rc = carrier_attach_dpdb(g_app.mounted_carrier_path, db_path, stage, err_msg, err_msg_sz);
    g_atomic_int_set(&g_stego_replace_existing_payload, 0);
    if (rc != 0) { (void)unlink(stage); g_free(stage); return -1; }
    if (!carrier_identity_unchanged(err_msg, err_msg_sz)) {
        (void)unlink(stage); g_free(stage); return -1;
    }
    if (rename(stage, g_app.mounted_carrier_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot atomically replace steganographic carrier: %s", strerror(errno));
        (void)unlink(stage); g_free(stage); return -1;
    }
    carrier_fsync_parent(g_app.mounted_carrier_path);
    g_free(stage);
    if (!carrier_capture_identity(g_app.mounted_carrier_path)) {

        fprintf(stderr, "DiskPass: warning: updated stego carrier identity could not be captured; reopen before the next write\n");
    }
    return 0;
}

static void on_open_stego_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (g_carrier_running || g_batch_running) return;

    gchar *carrier = carrier_choose_open(i18n("carrier_choose_open_hidden"));
    if (!carrier) return;
    carrier_kind_t kind = carrier_detect_kind(carrier);
    if (kind == CARRIER_KIND_UNKNOWN) {
        GtkWidget *bad = gtk_message_dialog_new(g_app.window,
            GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", i18n("carrier_unsupported"));
        gtk_dialog_run(GTK_DIALOG(bad)); gtk_widget_destroy(bad); g_free(carrier); return;
    }

    char err[384] = "";
    char *temp_db = carrier_make_private_temp_db(err, sizeof(err));
    if (!temp_db) {
        show_save_error(err[0] ? err : i18n("carrier_open_failed"));
        g_free(carrier); return;
    }

    carrier_job_t *job = g_new0(carrier_job_t, 1);
    if (!job) {
        (void)unlink(temp_db); g_free(temp_db); g_free(carrier);
        show_save_error("Out of memory"); return;
    }
    job->mode = CARRIER_JOB_OPEN;
    job->input_path = carrier;
    job->output_path = temp_db;
    struct stat cst;
    if (lstat(carrier, &cst) != 0 || !S_ISREG(cst.st_mode) || S_ISLNK(cst.st_mode)) {
        carrier_job_free(job);
        show_save_error(i18n("carrier_open_failed"));
        return;
    }
    job->input_dev = cst.st_dev; job->input_ino = cst.st_ino; job->input_size = cst.st_size;
    job->input_mtim = cst.st_mtim; job->input_identity_valid = TRUE;
    carrier_start_job(job);
}

static void carrier_choice_clicked(GtkButton *button, gpointer user_data) {
    GtkDialog *dlg = GTK_DIALOG(user_data);
    gint response = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "carrier-response"));
    gtk_dialog_response(dlg, response);
}

static GtkWidget *carrier_choice_button(GtkDialog *dlg, const char *icon_name,
    const char *title, const char *description, gint response)
{
    GtkWidget *button = gtk_button_new();
    gtk_widget_set_hexpand(button, TRUE);
    gtk_widget_set_halign(button, GTK_ALIGN_FILL);
    gtk_style_context_add_class(gtk_widget_get_style_context(button), "carrier-choice");

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(row), 1);

    GtkWidget *icon = gtk_image_new_from_icon_name(icon_name, GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_valign(icon, GTK_ALIGN_CENTER);
    gtk_style_context_add_class(gtk_widget_get_style_context(icon), "carrier-choice-icon");
    gtk_box_pack_start(GTK_BOX(row), icon, FALSE, FALSE, 0);

    GtkWidget *texts = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_hexpand(texts, TRUE);
    GtkWidget *title_lbl = gtk_label_new(title);
    gtk_label_set_xalign(GTK_LABEL(title_lbl), 0.0f);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "carrier-choice-title");
    gtk_box_pack_start(GTK_BOX(texts), title_lbl, FALSE, FALSE, 0);

    GtkWidget *desc_lbl = gtk_label_new(description);
    gtk_label_set_xalign(GTK_LABEL(desc_lbl), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(desc_lbl), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(desc_lbl), 42);
    gtk_style_context_add_class(gtk_widget_get_style_context(desc_lbl), "carrier-choice-desc");
    gtk_box_pack_start(GTK_BOX(texts), desc_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), texts, TRUE, TRUE, 0);

    GtkWidget *arrow = gtk_image_new_from_icon_name("go-next-symbolic", GTK_ICON_SIZE_MENU);
    gtk_widget_set_valign(arrow, GTK_ALIGN_CENTER);
    gtk_style_context_add_class(gtk_widget_get_style_context(arrow), "carrier-choice-arrow");
    gtk_box_pack_end(GTK_BOX(row), arrow, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(button), row);
    g_object_set_data(G_OBJECT(button), "carrier-response", GINT_TO_POINTER(response));
    g_signal_connect(button, "clicked", G_CALLBACK(carrier_choice_clicked), dlg);
    return button;
}

static GtkWidget *carrier_format_row(const char *title, const char *value) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *name = gtk_label_new(title);
    gtk_widget_set_size_request(name, 105, -1);
    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    gtk_style_context_add_class(gtk_widget_get_style_context(name), "carrier-format-name");
    gtk_box_pack_start(GTK_BOX(row), name, FALSE, FALSE, 0);

    GtkWidget *desc = gtk_label_new(value);
    gtk_label_set_xalign(GTK_LABEL(desc), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(desc), TRUE);
    gtk_widget_set_hexpand(desc, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(desc), "carrier-format-value");
    gtk_box_pack_start(GTK_BOX(row), desc, TRUE, TRUE, 0);
    return row;
}

static gint carrier_run_action_dialog(void) {
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("carrier_tools"), g_app.window,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("cancel"), GTK_RESPONSE_CANCEL, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 520, -1);
    gtk_window_set_resizable(GTK_WINDOW(dlg), FALSE);
    install_dialog_title(GTK_WINDOW(dlg), i18n("carrier_tools"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 12);

    const char *badge_path = g_app.mounted_carrier_path ? g_app.mounted_carrier_path :
        (g_app.db && g_app.db->file_path ? g_app.db->file_path : "database.dpdb");
    gchar *db_name = g_path_get_basename(badge_path);
    gchar *db_text = g_strdup_printf("%s: %s", i18n("carrier_current_db"), db_name ? db_name : "database.dpdb");
    GtkWidget *db_badge = gtk_label_new(db_text);
    gtk_label_set_xalign(GTK_LABEL(db_badge), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(db_badge), PANGO_ELLIPSIZE_MIDDLE);
    gtk_label_set_max_width_chars(GTK_LABEL(db_badge), 42);
    gtk_style_context_add_class(gtk_widget_get_style_context(db_badge), "carrier-current-db");
    gtk_box_pack_start(GTK_BOX(content), db_badge, FALSE, FALSE, 0);
    g_free(db_text);
    g_free(db_name);

    GtkWidget *attach = carrier_choice_button(GTK_DIALOG(dlg), "mail-attachment-symbolic",
        i18n("carrier_attach_short"), i18n("carrier_attach_desc"), 1);
    gtk_box_pack_start(GTK_BOX(content), attach, FALSE, FALSE, 0);

    GtkWidget *extract = carrier_choice_button(GTK_DIALOG(dlg), "document-save-symbolic",
        i18n("carrier_extract_short"), i18n("carrier_extract_desc"), 2);
    gtk_box_pack_start(GTK_BOX(content), extract, FALSE, FALSE, 0);

    GtkWidget *expander = gtk_expander_new(i18n("carrier_formats_title"));
    gtk_style_context_add_class(gtk_widget_get_style_context(expander), "carrier-expander");
    GtkWidget *formats = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(formats), 7);
    gtk_box_pack_start(GTK_BOX(formats), carrier_format_row(
        i18n("carrier_formats_images"), i18n("carrier_formats_images_list")), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(formats), carrier_format_row(
        i18n("carrier_formats_audio"), i18n("carrier_formats_audio_list")), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(formats), carrier_format_row(
        i18n("carrier_formats_sources"), i18n("carrier_formats_sources_list")), FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(expander), formats);
    gtk_box_pack_start(GTK_BOX(content), expander, FALSE, FALSE, 0);

    GtkWidget *note = gtk_label_new(i18n("carrier_safe_note"));
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(note), "carrier-note");
    gtk_box_pack_start(GTK_BOX(content), note, FALSE, FALSE, 0);

    gtk_widget_show_all(dlg);
    gint response = gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
    return response;
}

static void on_carrier_tools_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (g_carrier_running || g_batch_running || !app_has_open_database()) return;

    gint response = carrier_run_action_dialog();

    if (response == 1) {
        gchar *carrier = carrier_choose_open(i18n("carrier_choose_file"));
        if (!carrier) return;
        carrier_kind_t kind = carrier_detect_kind(carrier);
        if (kind == CARRIER_KIND_UNKNOWN) {
            GtkWidget *bad = gtk_message_dialog_new(g_app.window,
                GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
                "%s", i18n("carrier_unsupported"));
            gtk_dialog_run(GTK_DIALOG(bad)); gtk_widget_destroy(bad); g_free(carrier); return;
        }
        gchar *method = g_strdup_printf("%s: %s", i18n("carrier_detected"), carrier_kind_ui_name(kind));
        show_toast(method, 3500, -1); g_free(method);
        gchar *suggested = carrier_default_output_name(carrier, kind);
        gchar *output = carrier_choose_save(i18n("carrier_choose_output"), suggested, FALSE);
        g_free(suggested);
        if (!output) { g_free(carrier); return; }
        carrier_job_t *job = g_new0(carrier_job_t, 1);
        job->mode = CARRIER_JOB_ATTACH;
        job->input_path = carrier;
        job->db_path = g_strdup(g_app.db->file_path);
        job->output_path = output;
        carrier_start_job(job);
    } else if (response == 2) {
        gchar *joined = carrier_choose_open(i18n("carrier_choose_joined"));
        if (!joined) return;
        gchar *output = carrier_choose_save(i18n("carrier_extract_to"), "extracted.dpdb", TRUE);
        if (!output) { g_free(joined); return; }
        carrier_job_t *job = g_new0(carrier_job_t, 1);
        job->mode = CARRIER_JOB_EXTRACT;
        job->input_path = joined;
        job->output_path = output;
        carrier_start_job(job);
    }
}

typedef struct {
    GtkWidget *radio_auto;
    GtkWidget *radio_manual;
    GtkWidget *disk_section;
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
    errno = 0;
    char *end = NULL;
    long parsed = strtol(id, &end, 10);
    if (errno != 0 || !end || *end || parsed < 0 || parsed >= ctx->disk_count) return;
    int idx = (int)parsed;
    disk_info_t *d = &ctx->disks[idx];

    if (ctx->uuid_label) {
        char buf[600];
        snprintf(buf, sizeof(buf), "UUID: %s", d->uuid ? d->uuid : "?");
        gtk_label_set_text(GTK_LABEL(ctx->uuid_label), buf);
    }

    const char *guess_type = transport_to_type(d->transport, d->rotational);
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

    if (ctx->disk_section) {
        if (auto_mode)
            gtk_widget_show_all(ctx->disk_section);
        else
            gtk_widget_hide(ctx->disk_section);
    }

    gtk_widget_set_sensitive(ctx->disk_combo, auto_mode && ctx->disk_count > 0);
    gtk_widget_set_sensitive(ctx->refresh_btn, auto_mode);
    gtk_widget_set_sensitive(ctx->size_combo, !auto_mode);

    if (auto_mode)
        on_disk_combo_changed(GTK_COMBO_BOX(ctx->disk_combo), ctx);
}

static void on_add_clicked(GtkButton *btn, gpointer user_data) {
    if (app_has_open_database() && g_app.db->legacy_read_only) return;
    (void)btn; (void)user_data;
    if (!app_has_open_database() || g_app.db->legacy_read_only || g_carrier_running) return;

    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("add_entry"), g_app.window,
        GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("create"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 520, -1);
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

    ctx.disk_section = gtk_box_new(GTK_ORIENTATION_VERTICAL, 7);

    GtkWidget *disk_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    ctx.disk_combo = gtk_combo_box_text_new();
    gtk_widget_set_hexpand(ctx.disk_combo, TRUE);
    gtk_box_pack_start(GTK_BOX(disk_row), ctx.disk_combo, TRUE, TRUE, 0);

    ctx.refresh_btn = gtk_button_new_from_icon_name("view-refresh-symbolic",
        GTK_ICON_SIZE_BUTTON);
    gtk_box_pack_start(GTK_BOX(disk_row), ctx.refresh_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(ctx.disk_section), disk_row, FALSE, FALSE, 0);

    ctx.uuid_label = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx.uuid_label), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(ctx.uuid_label), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(ctx.uuid_label), PANGO_ELLIPSIZE_MIDDLE);
    gtk_box_pack_start(GTK_BOX(ctx.disk_section), ctx.uuid_label, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(content), ctx.disk_section, FALSE, FALSE, 0);

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
    GtkWidget *vt = gtk_entry_new();
    gtk_widget_set_hexpand(vt, TRUE);
    gtk_widget_set_size_request(vt, -1, 42);
    gtk_widget_set_margin_top(vt, 2);
    gtk_widget_set_margin_bottom(vt, 2);
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

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ctx.radio_manual)))
        on_add_mode_changed(GTK_TOGGLE_BUTTON(ctx.radio_manual), &ctx);
    else
        on_add_mode_changed(GTK_TOGGLE_BUTTON(ctx.radio_auto), &ctx);

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
                errno = 0;
                char *end = NULL;
                long parsed = strtol(id, &end, 10);
                if (errno == 0 && end && !*end && parsed >= 0 && parsed < ctx.disk_count)
                    uuid_to_save = ctx.disks[(int)parsed].uuid;
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
    if (app_has_open_database() && g_app.db->legacy_read_only) return;
    (void)btn; (void)user_data;
    if (!app_has_open_database() || g_app.db->legacy_read_only || g_carrier_running) return;
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

static GtkWidget *settings_row_new(const char *title, const char *desc, GtkWidget *control) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
    gtk_widget_set_margin_top(row, 6);
    gtk_widget_set_margin_bottom(row, 6);
    GtkWidget *text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);
    gtk_widget_set_hexpand(text, TRUE);
    GtkWidget *ttl = gtk_label_new(title);
    gtk_label_set_xalign(GTK_LABEL(ttl), 0.0f);
    /* Let the text column shrink instead of pushing switches and buttons
     * outside the right edge of the security dialog on narrow screens. */
    gtk_label_set_ellipsize(GTK_LABEL(ttl), PANGO_ELLIPSIZE_END);
    gtk_label_set_width_chars(GTK_LABEL(ttl), 1);
    gtk_style_context_add_class(gtk_widget_get_style_context(ttl), "settings-row-title");
    gtk_box_pack_start(GTK_BOX(text), ttl, FALSE, FALSE, 0);
    if (desc && *desc) {
        GtkWidget *d = gtk_label_new(desc);
        gtk_label_set_xalign(GTK_LABEL(d), 0.0f);
        gtk_label_set_line_wrap(GTK_LABEL(d), TRUE);
        gtk_label_set_line_wrap_mode(GTK_LABEL(d), PANGO_WRAP_WORD_CHAR);
        gtk_label_set_width_chars(GTK_LABEL(d), 1);
        gtk_label_set_max_width_chars(GTK_LABEL(d), 44);
        gtk_style_context_add_class(gtk_widget_get_style_context(d), "settings-row-desc");
        gtk_box_pack_start(GTK_BOX(text), d, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(row), text, TRUE, TRUE, 0);
    if (control) {
        gtk_widget_set_valign(control, GTK_ALIGN_CENTER);
        gtk_box_pack_end(GTK_BOX(row), control, FALSE, FALSE, 0);
    }
    return row;
}

static void combo_append_seconds(GtkComboBoxText *combo, guint seconds, const char *label) {
    char id[24];
    snprintf(id, sizeof(id), "%u", seconds);
    gtk_combo_box_text_append(combo, id, label);
}

static guint combo_active_seconds(GtkComboBox *combo, guint fallback) {
    const char *id = gtk_combo_box_get_active_id(combo);
    if (!id || !*id) return fallback;
    char *end = NULL;
    unsigned long n = strtoul(id, &end, 10);
    if (!end || *end || n > 86400UL) return fallback;
    return (guint)n;
}

typedef struct {
    char *path;
    char *key;
    gboolean carrier_checked;
    char *carrier_path;
    dev_t carrier_dev;
    ino_t carrier_ino;
    off_t carrier_size;
    struct timespec carrier_mtim;
} integrity_task_ctx_t;

typedef struct {
    gboolean opened;
    gboolean signature_ok;
    gboolean pqc_encrypted;
    gboolean policy_ok;
    gboolean commit_chain;
    gboolean rollback_ok;
    gboolean structure_ok;
    gboolean permissions_ok;
    gboolean carrier_checked;
    gboolean carrier_ok;
    int entry_count;
    int filter_count;
    int history_count;
    uint64_t generation;
    char *error;
} integrity_report_t;

static void integrity_task_ctx_free(integrity_task_ctx_t *ctx) {
    if (!ctx) return;
    secure_free_string(&ctx->path);
    secure_free_string(&ctx->key);
    secure_free_string(&ctx->carrier_path);
    g_free(ctx);
}

static void integrity_report_free(integrity_report_t *r) {
    if (!r) return;
    secure_free_string(&r->error);
    g_free(r);
}

static gboolean integrity_stat_matches(const integrity_task_ctx_t *ctx) {
    if (!ctx || !ctx->carrier_checked || !ctx->carrier_path) return TRUE;
    struct stat st;
    if (lstat(ctx->carrier_path, &st) != 0 || !S_ISREG(st.st_mode)) return FALSE;
    return st.st_dev == ctx->carrier_dev && st.st_ino == ctx->carrier_ino &&
        st.st_size == ctx->carrier_size && st.st_mtim.tv_sec == ctx->carrier_mtim.tv_sec &&
        st.st_mtim.tv_nsec == ctx->carrier_mtim.tv_nsec;
}

static void integrity_check_worker(GTask *task, gpointer source_object,
    gpointer task_data, GCancellable *cancellable)
{
    (void)source_object; (void)cancellable;
    integrity_task_ctx_t *ctx = task_data;
    integrity_report_t *r = g_new0(integrity_report_t, 1);
    if (!r) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_NO_SPACE,
            "Cannot allocate integrity report");
        return;
    }

    struct stat st;
    if (ctx && ctx->path && lstat(ctx->path, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == getuid() && (st.st_mode & 077) == 0)
        r->permissions_ok = TRUE;

    r->carrier_checked = ctx ? ctx->carrier_checked : FALSE;
    r->carrier_ok = integrity_stat_matches(ctx);

    char err[512] = "";
    db_manager_t *check = (ctx && ctx->path)
        ? db_manager_open(ctx->path, ctx->key, FALSE, FALSE, err, sizeof(err)) : NULL;
    if (!check) {
        r->error = xstrdup(err[0] ? err : "Cannot open database for integrity verification");
        g_task_return_pointer(task, r, (GDestroyNotify)integrity_report_free);
        return;
    }

    r->opened = TRUE;
    r->signature_ok = check->is_signed;
    r->pqc_encrypted = check->is_pqc_encrypted;
    r->policy_ok = !check->require_pqc || check->is_pqc_encrypted;
    r->commit_chain = check->has_commit_chain;
    r->rollback_ok = check->has_commit_chain && check->rollback_state_verified;
    r->entry_count = check->entry_count;
    r->filter_count = check->filter_count;
    r->history_count = check->history_count;
    r->generation = check->generation;

    char structure_err[512] = "";
    r->structure_ok = db_validate_loaded_integrity(check, structure_err, sizeof(structure_err)) == 0;
    if (!r->structure_ok)
        r->error = xstrdup(structure_err[0] ? structure_err : "Database structure verification failed");

    db_manager_clear(check);
    free(check);
    g_task_return_pointer(task, r, (GDestroyNotify)integrity_report_free);
}

static void integrity_check_done(GObject *source, GAsyncResult *res, gpointer user_data) {
    (void)source;
    GtkWidget *wait = GTK_WIDGET(user_data);
    GError *err = NULL;
    integrity_report_t *report = g_task_propagate_pointer(G_TASK(res), &err);
    if (!report) {
        report = g_new0(integrity_report_t, 1);
        if (report) report->error = xstrdup(err ? err->message : "Integrity check failed");
    }
    if (err) g_error_free(err);
    if (report)
        g_object_set_data_full(G_OBJECT(wait), "integrity-report", report,
            (GDestroyNotify)integrity_report_free);
    gtk_dialog_response(GTK_DIALOG(wait), GTK_RESPONSE_OK);
    g_object_unref(wait);
}

static void integrity_result_row(GtkBox *box, const char *title,
    const char *detail, int state)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_margin_top(row, 5);
    gtk_widget_set_margin_bottom(row, 5);
    GtkWidget *mark = gtk_label_new(state > 0 ? "✓" : state == 0 ? "⚠" : "✕");
    gtk_widget_set_valign(mark, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(mark),
        state > 0 ? "integrity-ok" : state == 0 ? "integrity-warn" : "integrity-bad");
    gtk_box_pack_start(GTK_BOX(row), mark, FALSE, FALSE, 0);
    GtkWidget *text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *ttl = gtk_label_new(title);
    gtk_label_set_xalign(GTK_LABEL(ttl), 0.0f);
    gtk_style_context_add_class(gtk_widget_get_style_context(ttl), "settings-row-title");
    gtk_box_pack_start(GTK_BOX(text), ttl, FALSE, FALSE, 0);
    if (detail && detail[0]) {
        GtkWidget *d = gtk_label_new(detail);
        gtk_label_set_xalign(GTK_LABEL(d), 0.0f);
        gtk_label_set_line_wrap(GTK_LABEL(d), TRUE);
        gtk_style_context_add_class(gtk_widget_get_style_context(d), "settings-row-desc");
        gtk_box_pack_start(GTK_BOX(text), d, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(row), text, TRUE, TRUE, 0);
    gtk_box_pack_start(box, row, FALSE, FALSE, 0);
}

static void show_integrity_report(GtkWindow *parent, const integrity_report_t *r) {
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("integrity_title"), parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    install_dialog_title(GTK_WINDOW(dlg), i18n("integrity_title"));
    gtk_window_set_default_size(GTK_WINDOW(dlg), 560, -1);
    GtkWidget *area = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_margin_start(box, 20); gtk_widget_set_margin_end(box, 20);
    gtk_widget_set_margin_top(box, 14); gtk_widget_set_margin_bottom(box, 10);
    gtk_box_pack_start(GTK_BOX(area), box, TRUE, TRUE, 0);

    if (!r || !r->opened) {
        integrity_result_row(GTK_BOX(box), i18n("integrity_container"),
            r && r->error ? r->error : i18n("integrity_failed"), -1);
    } else {
        integrity_result_row(GTK_BOX(box), i18n("integrity_container"),
            i18n("integrity_container_ok"), 1);
        integrity_result_row(GTK_BOX(box), i18n("integrity_signature"),
            r->signature_ok ? i18n("integrity_signature_ok") : i18n("integrity_signature_bad"),
            r->signature_ok ? 1 : -1);
        integrity_result_row(GTK_BOX(box), i18n("integrity_pqc"),
            r->pqc_encrypted ? i18n("integrity_pqc_ok") : i18n("integrity_pqc_legacy"),
            r->pqc_encrypted ? 1 : (r->policy_ok ? 0 : -1));
        integrity_result_row(GTK_BOX(box), i18n("integrity_commit"),
            r->commit_chain ? i18n("integrity_commit_ok") : i18n("integrity_commit_legacy"),
            r->commit_chain ? 1 : 0);
        integrity_result_row(GTK_BOX(box), i18n("integrity_rollback"),
            r->rollback_ok ? i18n("integrity_rollback_ok") : i18n("integrity_rollback_warn"),
            r->rollback_ok ? 1 : 0);
        integrity_result_row(GTK_BOX(box), i18n("integrity_structure"),
            r->structure_ok ? i18n("integrity_structure_ok") :
                (r->error ? r->error : i18n("integrity_structure_bad")),
            r->structure_ok ? 1 : -1);
        integrity_result_row(GTK_BOX(box), i18n("integrity_permissions"),
            r->permissions_ok ? i18n("integrity_permissions_ok") : i18n("integrity_permissions_warn"),
            r->permissions_ok ? 1 : 0);
        if (r->carrier_checked)
            integrity_result_row(GTK_BOX(box), i18n("integrity_carrier"),
                r->carrier_ok ? i18n("integrity_carrier_ok") : i18n("integrity_carrier_bad"),
                r->carrier_ok ? 1 : -1);

        char summary[256];
        snprintf(summary, sizeof(summary), "Entries: %d · filters: %d · history events: %d · generation: %llu",
            r->entry_count, r->filter_count, r->history_count,
            (unsigned long long)r->generation);
        GtkWidget *sum = gtk_label_new(summary);
        gtk_label_set_xalign(GTK_LABEL(sum), 0.0f);
        gtk_widget_set_margin_top(sum, 10);
        gtk_style_context_add_class(gtk_widget_get_style_context(sum), "settings-note");
        gtk_box_pack_start(GTK_BOX(box), sum, FALSE, FALSE, 0);
    }
    gtk_widget_show_all(dlg);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static void on_integrity_check_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!app_has_open_database() || !g_app.current_file) {
        show_save_error(i18n("integrity_open_required"));
        return;
    }

    integrity_task_ctx_t *ctx = g_new0(integrity_task_ctx_t, 1);
    if (!ctx) { show_save_error("Out of memory"); return; }
    ctx->path = xstrdup(g_app.current_file);
    ctx->key = xstrdup(g_app.db->recipient ? g_app.db->recipient : "");
    if (g_app.mounted_carrier_path && g_app.mounted_carrier_identity_valid) {
        ctx->carrier_checked = TRUE;
        ctx->carrier_path = xstrdup(g_app.mounted_carrier_path);
        ctx->carrier_dev = g_app.mounted_carrier_dev;
        ctx->carrier_ino = g_app.mounted_carrier_ino;
        ctx->carrier_size = g_app.mounted_carrier_size;
        ctx->carrier_mtim = g_app.mounted_carrier_mtim;
    }
    if (!ctx->path || !ctx->key || (ctx->carrier_checked && !ctx->carrier_path)) {
        integrity_task_ctx_free(ctx);
        show_save_error("Out of memory");
        return;
    }

    GtkWindow *parent = g_app.window;
    GtkWidget *top = gtk_widget_get_toplevel(GTK_WIDGET(btn));
    if (GTK_IS_WINDOW(top)) parent = GTK_WINDOW(top);
    GtkWidget *wait = gtk_dialog_new();
    gtk_window_set_transient_for(GTK_WINDOW(wait), parent);
    gtk_window_set_modal(GTK_WINDOW(wait), TRUE);
    gtk_window_set_deletable(GTK_WINDOW(wait), FALSE);
    install_dialog_title(GTK_WINDOW(wait), i18n("integrity_title"));
    GtkWidget *area = gtk_dialog_get_content_area(GTK_DIALOG(wait));
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(row), 20);
    GtkWidget *spinner = gtk_spinner_new();
    gtk_spinner_start(GTK_SPINNER(spinner));
    gtk_box_pack_start(GTK_BOX(row), spinner, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), gtk_label_new(i18n("integrity_running")), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(area), row, TRUE, TRUE, 0);
    gtk_widget_show_all(wait);

    GTask *task = g_task_new(NULL, NULL, integrity_check_done, g_object_ref(wait));
    g_task_set_task_data(task, ctx, (GDestroyNotify)integrity_task_ctx_free);
    g_task_run_in_thread(task, integrity_check_worker);
    g_object_unref(task);
    gtk_dialog_run(GTK_DIALOG(wait));
    integrity_report_t *report = g_object_steal_data(G_OBJECT(wait), "integrity-report");
    gtk_widget_destroy(wait);
    show_integrity_report(parent, report);
    integrity_report_free(report);
}

static const char *history_action_label(const char *action) {
    if (!action) return i18n("history_action_unknown");
    if (strcmp(action, "database_created") == 0) return i18n("history_action_database_created");
    if (strcmp(action, "entry_added") == 0) return i18n("history_action_entry_added");
    if (strcmp(action, "entry_updated") == 0) return i18n("history_action_entry_updated");
    if (strcmp(action, "entry_removed") == 0) return i18n("history_action_entry_removed");
    if (strcmp(action, "snapshot_updated") == 0) return i18n("history_action_snapshot_updated");
    if (strcmp(action, "smart_updated") == 0) return i18n("history_action_smart_updated");
    if (strcmp(action, "filter_added") == 0) return i18n("history_action_filter_added");
    if (strcmp(action, "filter_removed") == 0) return i18n("history_action_filter_removed");
    if (strcmp(action, "key_changed") == 0) return i18n("history_action_key_changed");
    if (strcmp(action, "batch_snapshot") == 0) return i18n("history_action_batch_snapshot");
    return i18n("history_action_unknown");
}

static void on_history_clicked(GtkButton *btn, gpointer user_data) {
    (void)user_data;
    if (!app_has_open_database()) {
        show_save_error(i18n("history_open_required"));
        return;
    }
    GtkWindow *parent = g_app.window;
    GtkWidget *top = gtk_widget_get_toplevel(GTK_WIDGET(btn));
    if (GTK_IS_WINDOW(top)) parent = GTK_WINDOW(top);
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("history_title"), parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    install_dialog_title(GTK_WINDOW(dlg), i18n("history_title"));
    gtk_window_set_default_size(GTK_WINDOW(dlg), 640, 500);
    GtkWidget *area = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(outer, 16); gtk_widget_set_margin_end(outer, 16);
    gtk_widget_set_margin_top(outer, 12); gtk_widget_set_margin_bottom(outer, 10);
    gtk_box_pack_start(GTK_BOX(area), outer, TRUE, TRUE, 0);

    char head[128];
    snprintf(head, sizeof(head), "Stored history events: %d / %d",
        g_app.db->history_count, DB_MAX_HISTORY);
    GtkWidget *headline = gtk_label_new(head);
    gtk_label_set_xalign(GTK_LABEL(headline), 0.0f);
    gtk_style_context_add_class(gtk_widget_get_style_context(headline), "settings-row-desc");
    gtk_box_pack_start(GTK_BOX(outer), headline, FALSE, FALSE, 0);

    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(sw, TRUE);
    GtkWidget *list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_container_add(GTK_CONTAINER(sw), list);
    gtk_box_pack_start(GTK_BOX(outer), sw, TRUE, TRUE, 0);

    if (g_app.db->history_count == 0) {
        GtkWidget *empty = gtk_label_new(i18n("history_empty"));
        gtk_widget_set_margin_top(empty, 24);
        gtk_widget_set_margin_bottom(empty, 24);
        gtk_container_add(GTK_CONTAINER(list), empty);
    } else {
        for (int i = g_app.db->history_count - 1; i >= 0; i--) {
            const db_history_event_t *ev = &g_app.db->history[i];
            GtkWidget *row = gtk_list_box_row_new();
            GtkWidget *rb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);
            gtk_widget_set_margin_start(rb, 10); gtk_widget_set_margin_end(rb, 10);
            gtk_widget_set_margin_top(rb, 8); gtk_widget_set_margin_bottom(rb, 8);
            GtkWidget *title = gtk_label_new(history_action_label(ev->action));
            gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
            gtk_style_context_add_class(gtk_widget_get_style_context(title), "settings-row-title");
            gtk_box_pack_start(GTK_BOX(rb), title, FALSE, FALSE, 0);

            if (ev->target && ev->target[0]) {
                char *target = g_strdup_printf("%s %s", i18n("history_target"), ev->target);
                GtkWidget *t = gtk_label_new(target ? target : ev->target);
                g_free(target);
                gtk_label_set_xalign(GTK_LABEL(t), 0.0f);
                gtk_label_set_ellipsize(GTK_LABEL(t), PANGO_ELLIPSIZE_MIDDLE);
                gtk_style_context_add_class(gtk_widget_get_style_context(t), "settings-row-desc");
                gtk_box_pack_start(GTK_BOX(rb), t, FALSE, FALSE, 0);
            }

            char timebuf[64] = "";
            time_t ts = (time_t)ev->timestamp;
            struct tm tmv;
            if (localtime_r(&ts, &tmv)) strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tmv);
            char meta[160];
            snprintf(meta, sizeof(meta), "%s · generation %llu",
                timebuf[0] ? timebuf : "?", (unsigned long long)ev->generation);
            GtkWidget *m = gtk_label_new(meta);
            gtk_label_set_xalign(GTK_LABEL(m), 0.0f);
            gtk_style_context_add_class(gtk_widget_get_style_context(m), "settings-row-desc");
            gtk_box_pack_start(GTK_BOX(rb), m, FALSE, FALSE, 0);
            gtk_container_add(GTK_CONTAINER(row), rb);
            gtk_container_add(GTK_CONTAINER(list), row);
        }
    }

    GtkWidget *note = gtk_label_new(i18n("history_note"));
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(note), "settings-note");
    gtk_box_pack_start(GTK_BOX(outer), note, FALSE, FALSE, 0);

    gtk_widget_show_all(dlg);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

/* Switching windows must not start a nested gtk_main() from an idle
 * handler: that can leave the main application apparently unresponsive. */
static void camouflage_calculator_finished(gboolean unlocked, gpointer user_data) {
    (void)user_data;
    if (!unlocked) {
        gtk_main_quit();
        return;
    }
    g_app.camouflage_key_valid = TRUE;
    if (!load_config()) {
        g_warning("DiskPass: protected configuration failed authentication");
        sodium_memzero(g_app.camouflage_config_key, sizeof(g_app.camouflage_config_key));
        g_app.camouflage_key_valid = FALSE;
        gtk_main_quit();
        return;
    }
    /* The real DiskPass window and launcher are visible again only while the
     * DiskPass interface is on screen. Calculator mode remains configured for
     * the next application start. */
    if (!diskpass_sync_launcher_icon(FALSE))
        g_warning("DiskPass: could not restore launcher icon");
    gtk_window_set_icon_name(g_app.window, "diskpass");
    gtk_window_set_title(g_app.window, "DiskPass");
    if (!gtk_icon_theme_has_icon(gtk_icon_theme_get_default(), "diskpass") && icon_pb)
        gtk_window_set_icon(g_app.window, icon_pb);
    gtk_widget_show(GTK_WIDGET(g_app.window));
    gtk_window_present(g_app.window);
}

/* Run only after the settings dialog has been destroyed. The database is
 * locked and both clipboards are cleared before the first calculator frame. */
static gboolean camouflage_activate_idle(gpointer user_data) {
    (void)user_data;
    if (!g_app.camouflage_enabled || !g_app.window) return G_SOURCE_REMOVE;
    on_lock_clicked(NULL, NULL);
    gtk_widget_hide(GTK_WIDGET(g_app.window));
    if (!diskpass_calculator_show_async(g_app.camouflage_hash,
            g_app.camouflage_salt, g_app.camouflage_config_key,
            camouflage_calculator_finished, NULL)) {
        /* If the calculator cannot be shown, do not leave DiskPass hidden. */
        g_warning("DiskPass: calculator window could not be opened");
        gtk_widget_show(GTK_WIDGET(g_app.window));
        gtk_window_present(g_app.window);
        (void)diskpass_sync_launcher_icon(FALSE);
    }
    return G_SOURCE_REMOVE;
}

static gboolean camouflage_valid_pin(const char *pin) {
    gsize len = pin ? strlen(pin) : 0;
    if (len < 8 || len > 32) return FALSE;
    for (gsize i = 0; i < len; i++)
        if (!g_ascii_isdigit(pin[i])) return FALSE;
    return TRUE;
}

static void camouflage_show_error(GtkWindow *parent, const char *message) {
    GtkWidget *alert = gtk_message_dialog_new(parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "%s", message);
    gtk_dialog_run(GTK_DIALOG(alert));
    gtk_widget_destroy(alert);
}

/* The access code is collected only when the calculator switch is turned on.
 * Keep its hash temporary until the parent Settings dialog is saved. */
typedef struct {
    GtkWindow *settings_window;
    char pending_hash[crypto_pwhash_STRBYTES];
    unsigned char pending_salt[crypto_pwhash_SALTBYTES];
    unsigned char pending_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    gboolean asking;
} camouflage_switch_ctx_t;

static gboolean camouflage_ask_new_pin(GtkWindow *parent,
                                       char out_hash[crypto_pwhash_STRBYTES],
                                       unsigned char out_salt[crypto_pwhash_SALTBYTES],
                                       unsigned char out_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]) {
    GtkWidget *dlg = gtk_dialog_new_with_buttons("Код доступа к DiskPass", parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        "Установить код", GTK_RESPONSE_ACCEPT, NULL);
    install_dialog_title(GTK_WINDOW(dlg), "Код доступа к DiskPass");
    gtk_window_set_default_size(GTK_WINDOW(dlg), 430, 250);
    gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_ACCEPT);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 16);
    GtkWidget *fields = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_box_pack_start(GTK_BOX(content), fields, TRUE, TRUE, 0);

    GtkWidget *explanation = gtk_label_new(
        "Задайте отдельный код из 8–32 цифр. В калькуляторе введите его и нажмите =, чтобы открыть DiskPass.");
    gtk_label_set_xalign(GTK_LABEL(explanation), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(explanation), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(explanation), 45);
    gtk_box_pack_start(GTK_BOX(fields), explanation, FALSE, FALSE, 0);

    GtkWidget *pin_label = gtk_label_new("Новый код");
    gtk_label_set_xalign(GTK_LABEL(pin_label), 0.0f);
    gtk_box_pack_start(GTK_BOX(fields), pin_label, FALSE, FALSE, 0);
    GtkWidget *pin = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(pin), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(pin), GTK_INPUT_PURPOSE_PIN);
    gtk_entry_set_max_length(GTK_ENTRY(pin), 32);
    gtk_entry_set_placeholder_text(GTK_ENTRY(pin), "8–32 цифры");
    gtk_box_pack_start(GTK_BOX(fields), pin, FALSE, FALSE, 0);

    GtkWidget *confirm_label = gtk_label_new("Подтвердите код");
    gtk_label_set_xalign(GTK_LABEL(confirm_label), 0.0f);
    gtk_box_pack_start(GTK_BOX(fields), confirm_label, FALSE, FALSE, 0);
    GtkWidget *confirm = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(confirm), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(confirm), GTK_INPUT_PURPOSE_PIN);
    gtk_entry_set_max_length(GTK_ENTRY(confirm), 32);
    gtk_entry_set_placeholder_text(GTK_ENTRY(confirm), "Повторите код");
    gtk_box_pack_start(GTK_BOX(fields), confirm, FALSE, FALSE, 0);

    gboolean succeeded = FALSE;
    gtk_widget_show_all(dlg);
    gtk_widget_grab_focus(pin);
    while (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        const char *first = gtk_entry_get_text(GTK_ENTRY(pin));
        const char *second = gtk_entry_get_text(GTK_ENTRY(confirm));
        size_t len = strlen(first);
        if (!camouflage_valid_pin(first) || len != strlen(second) ||
            sodium_memcmp(first, second, len) != 0) {
            camouflage_show_error(GTK_WINDOW(dlg),
                "Коды должны совпадать и содержать от 8 до 32 цифр.");
            gtk_widget_grab_focus(pin);
            continue;
        }
        char hash[crypto_pwhash_STRBYTES] = {0};
        if (crypto_pwhash_str(hash, first, (unsigned long long)len,
                crypto_pwhash_OPSLIMIT_MODERATE,
                crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
            camouflage_show_error(GTK_WINDOW(dlg), "Не удалось защитить секретный код.");
            sodium_memzero(hash, sizeof(hash));
            continue;
        }
        randombytes_buf(out_salt, crypto_pwhash_SALTBYTES);
        if (crypto_pwhash(out_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                first, (unsigned long long)len, out_salt,
                crypto_pwhash_OPSLIMIT_MODERATE,
                crypto_pwhash_MEMLIMIT_MODERATE,
                crypto_pwhash_ALG_ARGON2ID13) != 0) {
            camouflage_show_error(GTK_WINDOW(dlg), "Не удалось получить ключ шифрования настроек.");
            sodium_memzero(hash, sizeof(hash));
            sodium_memzero(out_salt, crypto_pwhash_SALTBYTES);
            sodium_memzero(out_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
            continue;
        }
        memcpy(out_hash, hash, sizeof(hash));
        sodium_memzero(hash, sizeof(hash));
        succeeded = TRUE;
        break;
    }
    /* Clear both GTK buffers before destroying the transient dialog. */
    gtk_entry_set_text(GTK_ENTRY(pin), "");
    gtk_entry_set_text(GTK_ENTRY(confirm), "");
    gtk_widget_destroy(dlg);
    return succeeded;
}

static void camouflage_switch_changed(GObject *object, GParamSpec *pspec,
                                      gpointer user_data) {
    (void)pspec;
    camouflage_switch_ctx_t *ctx = user_data;
    if (ctx->asking) return;

    GtkSwitch *sw = GTK_SWITCH(object);
    if (!gtk_switch_get_active(sw)) {
        sodium_memzero(ctx->pending_hash, sizeof(ctx->pending_hash));
        sodium_memzero(ctx->pending_salt, sizeof(ctx->pending_salt));
        sodium_memzero(ctx->pending_key, sizeof(ctx->pending_key));
        return;
    }

    ctx->asking = TRUE;
    sodium_memzero(ctx->pending_hash, sizeof(ctx->pending_hash));
    sodium_memzero(ctx->pending_salt, sizeof(ctx->pending_salt));
    sodium_memzero(ctx->pending_key, sizeof(ctx->pending_key));
    gboolean ok = camouflage_ask_new_pin(ctx->settings_window, ctx->pending_hash,
                                          ctx->pending_salt, ctx->pending_key);
    ctx->asking = FALSE;
    if (!ok) {
        /* Cancelling the code dialog must not enable calculator mode. */
        sodium_memzero(ctx->pending_hash, sizeof(ctx->pending_hash));
        sodium_memzero(ctx->pending_salt, sizeof(ctx->pending_salt));
        sodium_memzero(ctx->pending_key, sizeof(ctx->pending_key));
        gtk_switch_set_active(sw, FALSE);
    }
}

static void on_security_settings_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("security_settings"), g_app.window,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("save"), GTK_RESPONSE_ACCEPT, NULL);
    install_dialog_title(GTK_WINDOW(dlg), i18n("security_settings"));
    gtk_window_set_default_size(GTK_WINDOW(dlg), 670, 620);
    gtk_window_set_resizable(GTK_WINDOW(dlg), TRUE);
    gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_ACCEPT);

    GtkWidget *area = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(area), 12);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(area), scroll, TRUE, TRUE, 0);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(scroll), box);

    GtkWidget *screen_sw = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(screen_sw), g_app.screenshot_guard);
    gtk_box_pack_start(GTK_BOX(box), settings_row_new(i18n("screenshot_guard"),
        i18n("screenshot_guard_desc"), screen_sw), FALSE, FALSE, 0);

    GtkWidget *focus_sw = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(focus_sw), g_app.lock_on_focus_loss);
    gtk_box_pack_start(GTK_BOX(box), settings_row_new(i18n("lock_on_focus_loss"),
        i18n("lock_on_focus_loss_desc"), focus_sw), FALSE, FALSE, 0);

    GtkWidget *camouflage_sw = gtk_switch_new();
    camouflage_switch_ctx_t camouflage_ctx = { .settings_window = GTK_WINDOW(dlg) };
    /* Set the initial value before connecting so reopening Settings does not
     * trigger a password prompt. Each later OFF -> ON change does. */
    gtk_switch_set_active(GTK_SWITCH(camouflage_sw), g_app.camouflage_enabled);
    g_signal_connect(camouflage_sw, "notify::active",
        G_CALLBACK(camouflage_switch_changed), &camouflage_ctx);
    gtk_box_pack_start(GTK_BOX(box), settings_row_new("Режим калькулятора",
        "При включении задаётся код. Настройки шифруются этим кодом; ярлык скрывается только из меню GNOME.",
        camouflage_sw), FALSE, FALSE, 0);

    GtkWidget *autolock = gtk_combo_box_text_new();
    combo_append_seconds(GTK_COMBO_BOX_TEXT(autolock), 0, i18n("never"));
    combo_append_seconds(GTK_COMBO_BOX_TEXT(autolock), 60, i18n("one_minute"));
    combo_append_seconds(GTK_COMBO_BOX_TEXT(autolock), 120, i18n("two_minutes"));
    combo_append_seconds(GTK_COMBO_BOX_TEXT(autolock), 300, i18n("five_minutes"));
    combo_append_seconds(GTK_COMBO_BOX_TEXT(autolock), 600, i18n("ten_minutes"));
    combo_append_seconds(GTK_COMBO_BOX_TEXT(autolock), 900, i18n("fifteen_minutes"));
    combo_append_seconds(GTK_COMBO_BOX_TEXT(autolock), 1800, i18n("thirty_minutes"));
    char aid[24]; snprintf(aid, sizeof(aid), "%u", g_app.autolock_seconds);
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(autolock), aid))
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(autolock), "300");
    gtk_box_pack_start(GTK_BOX(box), settings_row_new(i18n("autolock_timeout"),
        i18n("autolock_timeout_desc"), autolock), FALSE, FALSE, 0);

    GtkWidget *clip = gtk_combo_box_text_new();
    combo_append_seconds(GTK_COMBO_BOX_TEXT(clip), 15, i18n("fifteen_seconds"));
    combo_append_seconds(GTK_COMBO_BOX_TEXT(clip), 30, i18n("thirty_seconds"));
    combo_append_seconds(GTK_COMBO_BOX_TEXT(clip), 60, i18n("one_minute"));
    combo_append_seconds(GTK_COMBO_BOX_TEXT(clip), 120, i18n("two_minutes"));
    char cid[24]; snprintf(cid, sizeof(cid), "%u", g_app.clipboard_clear_seconds);
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(clip), cid))
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(clip), "30");
    gtk_box_pack_start(GTK_BOX(box), settings_row_new(i18n("clipboard_timeout"),
        i18n("clipboard_timeout_desc"), clip), FALSE, FALSE, 0);

    GtkWidget *always = gtk_label_new(i18n("always_on"));
    gtk_style_context_add_class(gtk_widget_get_style_context(always), "settings-always-on");
    gtk_box_pack_start(GTK_BOX(box), settings_row_new(i18n("system_lock_protection"),
        i18n("system_lock_protection_desc"), always), FALSE, FALSE, 0);

    GtkWidget *tools_sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_margin_top(tools_sep, 10); gtk_widget_set_margin_bottom(tools_sep, 4);
    gtk_box_pack_start(GTK_BOX(box), tools_sep, FALSE, FALSE, 0);

    GtkWidget *integrity_btn = gtk_button_new_with_label(i18n("check_now"));
    gtk_widget_set_sensitive(integrity_btn, app_has_open_database());
    g_signal_connect(integrity_btn, "clicked", G_CALLBACK(on_integrity_check_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(box), settings_row_new(i18n("integrity_check"),
        i18n("integrity_check_desc"), integrity_btn), FALSE, FALSE, 0);

    GtkWidget *history_btn = gtk_button_new_with_label(i18n("open_history"));
    gtk_widget_set_sensitive(history_btn, app_has_open_database());
    g_signal_connect(history_btn, "clicked", G_CALLBACK(on_history_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(box), settings_row_new(i18n("change_history"),
        i18n("change_history_desc"), history_btn), FALSE, FALSE, 0);

    GtkWidget *note = gtk_label_new(i18n("screenshot_guard_note"));
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_widget_set_margin_top(note, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(note), "settings-note");
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);

    gtk_widget_show_all(dlg);
    gboolean accepted = FALSE;
    while (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        gboolean enable_camouflage = gtk_switch_get_active(GTK_SWITCH(camouflage_sw));
        if (enable_camouflage && !g_app.camouflage_hash[0] &&
            !camouflage_ctx.pending_hash[0]) {
            camouflage_show_error(GTK_WINDOW(dlg),
                "Для включения режима калькулятора необходимо задать код доступа.");
            continue;
        }
        /* Keep previous state so a failed write never enables an unusable mode. */
        gboolean old_enabled = g_app.camouflage_enabled;
        gboolean old_key_valid = g_app.camouflage_key_valid;
        char old_hash[crypto_pwhash_STRBYTES];
        unsigned char old_salt[crypto_pwhash_SALTBYTES];
        unsigned char old_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
        memcpy(old_hash, g_app.camouflage_hash, sizeof(old_hash));
        memcpy(old_salt, g_app.camouflage_salt, sizeof(old_salt));
        memcpy(old_key, g_app.camouflage_config_key, sizeof(old_key));
        if (enable_camouflage && camouflage_ctx.pending_hash[0]) {
            memcpy(g_app.camouflage_hash, camouflage_ctx.pending_hash,
                   sizeof(g_app.camouflage_hash));
            memcpy(g_app.camouflage_salt, camouflage_ctx.pending_salt,
                   sizeof(g_app.camouflage_salt));
            memcpy(g_app.camouflage_config_key, camouflage_ctx.pending_key,
                   sizeof(g_app.camouflage_config_key));
            g_app.camouflage_key_valid = TRUE;
        }
        g_app.camouflage_enabled = enable_camouflage;
        g_app.screenshot_guard = gtk_switch_get_active(GTK_SWITCH(screen_sw));
        g_app.lock_on_focus_loss = gtk_switch_get_active(GTK_SWITCH(focus_sw));
        g_app.autolock_seconds = combo_active_seconds(GTK_COMBO_BOX(autolock), 300);
        g_app.clipboard_clear_seconds = combo_active_seconds(GTK_COMBO_BOX(clip), 30);
        if (!save_config()) {
            g_app.camouflage_enabled = old_enabled;
            memcpy(g_app.camouflage_hash, old_hash, sizeof(old_hash));
            memcpy(g_app.camouflage_salt, old_salt, sizeof(old_salt));
            memcpy(g_app.camouflage_config_key, old_key, sizeof(old_key));
            g_app.camouflage_key_valid = old_key_valid;
            camouflage_show_error(GTK_WINDOW(dlg),
                "Не удалось безопасно сохранить настройки. Режим не изменён.");
            sodium_memzero(old_hash, sizeof(old_hash));
            sodium_memzero(old_salt, sizeof(old_salt));
            sodium_memzero(old_key, sizeof(old_key));
            continue;
        }
        sodium_memzero(old_hash, sizeof(old_hash));
        sodium_memzero(old_salt, sizeof(old_salt));
        sodium_memzero(old_key, sizeof(old_key));
        if (!enable_camouflage) {
            sodium_memzero(g_app.camouflage_hash, sizeof(g_app.camouflage_hash));
            sodium_memzero(g_app.camouflage_salt, sizeof(g_app.camouflage_salt));
            sodium_memzero(g_app.camouflage_config_key, sizeof(g_app.camouflage_config_key));
            g_app.camouflage_key_valid = FALSE;
        }
        if (!g_app.screenshot_guard) privacy_shield_set(FALSE);
        reset_autolock();
        if (!diskpass_sync_launcher_icon(g_app.camouflage_enabled))
            g_warning("DiskPass: could not update user launcher icon");
        accepted = TRUE;
        break;
    }
    sodium_memzero(camouflage_ctx.pending_hash, sizeof(camouflage_ctx.pending_hash));
    sodium_memzero(camouflage_ctx.pending_salt, sizeof(camouflage_ctx.pending_salt));
    sodium_memzero(camouflage_ctx.pending_key, sizeof(camouflage_ctx.pending_key));
    gtk_widget_destroy(dlg);
    if (accepted && g_app.camouflage_enabled)
        g_idle_add(camouflage_activate_idle, NULL);
}

static void on_schema_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!app_has_open_database()) return;
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

typedef struct {
    int idx;
    char *entry_label;
    char *folder;
    GtkWidget *wait;
} snapshot_task_ctx_t;

typedef struct {
    char *files;
    char *smart;
    char *uuid;
} snapshot_task_result_t;

static void snapshot_task_ctx_free(gpointer data) {
    snapshot_task_ctx_t *ctx = data;
    if (!ctx) return;
    secure_free_string(&ctx->entry_label);
    secure_g_free_string(&ctx->folder);
    g_free(ctx);
}

static void snapshot_task_result_free(gpointer data) {
    snapshot_task_result_t *r = data;
    if (!r) return;
    secure_g_free_string(&r->files);
    secure_free_string(&r->smart);
    secure_free_string(&r->uuid);
    g_free(r);
}

static void snapshot_scan_worker(GTask *task, gpointer source_object,
    gpointer task_data, GCancellable *cancellable)
{
    (void)source_object;
    snapshot_task_ctx_t *ctx = task_data;
    if (!ctx || (cancellable && g_cancellable_is_cancelled(cancellable))) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Snapshot scan cancelled");
        return;
    }

    snapshot_task_result_t *r = g_new0(snapshot_task_result_t, 1);
    r->files = scan_directory_recursive(ctx->folder);
    if (!cancellable || !g_cancellable_is_cancelled(cancellable))
        r->smart = collect_smart_data(ctx->folder);
    if (!cancellable || !g_cancellable_is_cancelled(cancellable))
        r->uuid = get_uuid_for_path(ctx->folder);

    if (cancellable && g_cancellable_is_cancelled(cancellable)) {
        snapshot_task_result_free(r);
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Snapshot scan cancelled");
        return;
    }
    g_task_return_pointer(task, r, snapshot_task_result_free);
}

static void snapshot_scan_done(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    (void)source_object; (void)user_data;
    GTask *task = G_TASK(res);
    snapshot_task_ctx_t *ctx = g_task_get_task_data(task);
    GError *task_err = NULL;
    snapshot_task_result_t *r = g_task_propagate_pointer(task, &task_err);

    if (ctx && ctx->wait && GTK_IS_WIDGET(ctx->wait)) {
        gtk_widget_destroy(ctx->wait);
        ctx->wait = NULL;
    }
    if (task_err) {
        if (task_err->code != G_IO_ERROR_CANCELLED)
            show_save_error(task_err->message);
        g_error_free(task_err);
        return;
    }
    if (!ctx || !r || !app_has_open_database() || ctx->idx < 0 || ctx->idx >= g_app.db->entry_count) {
        snapshot_task_result_free(r);
        return;
    }

    db_entry_t *e = &g_app.db->entries[ctx->idx];
    if (!e->label || strcmp(e->label, ctx->entry_label) != 0) {
        snapshot_task_result_free(r);
        show_save_error("The selected database entry changed while scanning");
        return;
    }

    char err_buf[256] = "";
    char *old_uuid = NULL;
    gboolean uuid_changed = FALSE;
    if ((!e->uuid || !e->uuid[0]) && r->uuid && r->uuid[0]) {
        old_uuid = e->uuid;
        e->uuid = xstrdup(r->uuid);
        uuid_changed = TRUE;
    }

    if (db_set_entry_snapshot(g_app.db, ctx->entry_label, r->files, r->smart,
            err_buf, sizeof(err_buf)) == 0) {
        if (uuid_changed) secure_free_string(&old_uuid);
        char msg[512];
        char health_buf[32] = "";
        if (r->smart) {
            cJSON *smart = cJSON_Parse(r->smart);
            if (smart) {
                cJSON *h = cJSON_GetObjectItem(smart, "health");
                if (h && cJSON_IsString(h))
                    snprintf(health_buf, sizeof(health_buf), "%s", h->valuestring);
                cJSON_Delete(smart);
            }
        }
        int indexed_count = e->file_count;
        if (health_buf[0])
            snprintf(msg, sizeof(msg), "%s: %d · SMART %s",
                i18n("indexed_files"), indexed_count, health_buf);
        else
            snprintf(msg, sizeof(msg), "%s: %d · %s",
                i18n("indexed_files"), indexed_count, i18n("smart_unavailable"));

        GtkWidget *info = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
            GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", msg);
        gtk_dialog_run(GTK_DIALOG(info));
        gtk_widget_destroy(info);
    } else {
        if (uuid_changed) {
            secure_free_string(&e->uuid);
            e->uuid = old_uuid;
            old_uuid = NULL;
        }
        secure_free_string(&old_uuid);
        show_save_error(err_buf);
    }

    snapshot_task_result_free(r);
    g_app.current_entry_idx = -1;
    refresh_entry_list();
    GtkListBoxRow *new_row = gtk_list_box_get_row_at_index(g_app.listbox, ctx->idx);
    if (new_row) gtk_list_box_select_row(g_app.listbox, new_row);
}

static void on_attach_snapshot_clicked(GtkButton *btn, gpointer user_data) {
    if (app_has_open_database() && g_app.db->legacy_read_only) return;
    (void)btn; (void)user_data;
    if (!app_has_open_database() || g_app.db->legacy_read_only || g_carrier_running) return;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;

    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        i18n("snapshot_title"), g_app.window, GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("scan"), GTK_RESPONSE_OK, NULL);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) != GTK_RESPONSE_OK) {
        gtk_widget_destroy(dlg);
        return;
    }

    gchar *folder = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
    char *entry_label = xstrdup(g_app.db->entries[idx].label);
    gtk_widget_destroy(dlg);
    if (!folder || !entry_label) {
        secure_g_free_string(&folder);
        secure_free_string(&entry_label);
        show_save_error("Unable to allocate snapshot task");
        return;
    }

    GtkWidget *wait = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
        GTK_MESSAGE_INFO, GTK_BUTTONS_NONE, "%s", i18n("scanning"));
    gtk_window_set_deletable(GTK_WINDOW(wait), FALSE);
    gtk_widget_show_all(wait);

    snapshot_task_ctx_t *ctx = g_new0(snapshot_task_ctx_t, 1);
    ctx->idx = idx;
    ctx->entry_label = entry_label;
    ctx->folder = folder;
    ctx->wait = wait;

    GTask *task = g_task_new(NULL, NULL, snapshot_scan_done, NULL);
    g_task_set_task_data(task, ctx, snapshot_task_ctx_free);
    g_task_run_in_thread(task, snapshot_scan_worker);
    g_object_unref(task);
}

static gboolean block_close(GtkWidget *w, GdkEvent *e, gpointer u) {
    (void)w; (void)e; (void)u;
    return TRUE;
}

typedef struct {
    int entry_idx;
    char *label;
    char *uuid;
} batch_scan_job_t;

typedef struct {
    int entry_idx;
    char *label;
    char *files;
    char *smart;
    gboolean skipped;
    gboolean failed;
} batch_scan_item_t;

typedef struct {
    int count;
    batch_scan_item_t *items;
} batch_scan_result_t;

typedef struct {
    GtkWidget *dlg;
    GtkWidget *prog;
    GtkWidget *lbl;
    gulong block_close_handler_id;
    guint pulse_id;
    int job_count;
    batch_scan_job_t *jobs;
} batch_task_ctx_t;

static void batch_task_ctx_free(gpointer data) {
    batch_task_ctx_t *ctx = data;
    if (!ctx) return;
    for (int i = 0; i < ctx->job_count; i++) {
        secure_free_string(&ctx->jobs[i].label);
        secure_free_string(&ctx->jobs[i].uuid);
    }
    free(ctx->jobs);
    g_free(ctx);
}

static void batch_scan_result_free(gpointer data) {
    batch_scan_result_t *r = data;
    if (!r) return;
    for (int i = 0; i < r->count; i++) {
        secure_free_string(&r->items[i].label);
        secure_g_free_string(&r->items[i].files);
        secure_free_string(&r->items[i].smart);
    }
    free(r->items);
    g_free(r);
}

static gboolean batch_progress_pulse(gpointer data) {
    batch_task_ctx_t *ctx = data;
    if (!ctx || !ctx->prog || !GTK_IS_PROGRESS_BAR(ctx->prog)) return G_SOURCE_REMOVE;
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(ctx->prog));
    return G_SOURCE_CONTINUE;
}

static void batch_scan_worker(GTask *task, gpointer source_object,
    gpointer task_data, GCancellable *cancellable)
{
    (void)source_object;
    batch_task_ctx_t *ctx = task_data;
    if (!ctx) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_FAILED, "Batch task is missing context");
        return;
    }

    int nd = 0;
    disk_info_t *disks = list_disks(&nd);
    batch_scan_result_t *result = g_new0(batch_scan_result_t, 1);
    result->count = ctx->job_count;
    result->items = calloc((size_t)result->count, sizeof(*result->items));
    if (!result->items) {
        free_disk_list(disks, nd);
        g_free(result);
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_NO_SPACE, "Out of memory while scanning disks");
        return;
    }

    for (int i = 0; i < ctx->job_count; i++) {
        if (cancellable && g_cancellable_is_cancelled(cancellable)) {
            free_disk_list(disks, nd);
            batch_scan_result_free(result);
            g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Batch scan cancelled");
            return;
        }

        batch_scan_item_t *item = &result->items[i];
        batch_scan_job_t *job = &ctx->jobs[i];
        item->entry_idx = job->entry_idx;
        item->label = xstrdup(job->label);

        const char *mp = NULL;
        for (int k = 0; k < nd; k++) {
            if (disks[k].uuid && strcmp(disks[k].uuid, job->uuid) == 0 && disks[k].mountpoint) {
                mp = disks[k].mountpoint;
                break;
            }
        }
        if (!mp) {
            item->skipped = TRUE;
            continue;
        }

        item->files = scan_directory_recursive(mp);
        if (!item->files) {
            item->failed = TRUE;
            continue;
        }
        if (!cancellable || !g_cancellable_is_cancelled(cancellable))
            item->smart = collect_smart_data(mp);
    }

    free_disk_list(disks, nd);
    g_task_return_pointer(task, result, batch_scan_result_free);
}

static void batch_scan_done(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    (void)source_object; (void)user_data;
    GTask *task = G_TASK(res);
    batch_task_ctx_t *ctx = g_task_get_task_data(task);
    GError *task_err = NULL;
    batch_scan_result_t *result = g_task_propagate_pointer(task, &task_err);

    if (ctx && ctx->pulse_id) {
        g_source_remove(ctx->pulse_id);
        ctx->pulse_id = 0;
    }

    int total_done = 0, total_skip = 0, total_err = 0;
    if (task_err) {
        if (task_err->code != G_IO_ERROR_CANCELLED)
            show_save_error(task_err->message);
        g_error_free(task_err);
        total_err = ctx ? ctx->job_count : 1;
    } else if (result && g_app.db) {
        db_snapshot_backup_t *backups = calloc((size_t)g_app.db->entry_count, sizeof(*backups));
        if (!backups) {
            total_err = result->count;
            show_save_error("Out of memory while committing batch reindex");
        } else {
            for (int i = 0; i < result->count; i++) {
                batch_scan_item_t *item = &result->items[i];
                if (item->skipped) { total_skip++; continue; }
                if (item->failed || item->entry_idx < 0 || item->entry_idx >= g_app.db->entry_count) {
                    total_err++;
                    continue;
                }
                db_entry_t *e = &g_app.db->entries[item->entry_idx];
                if (!e->label || strcmp(e->label, item->label) != 0) {
                    total_err++;
                    continue;
                }
                char err[256] = "";
                if (db_set_entry_snapshot_nosave(g_app.db, item->label, item->files, item->smart,
                        &backups[item->entry_idx], err, sizeof(err)) == 0)
                    total_done++;
                else
                    total_err++;
            }

            if (total_done > 0) {
                char save_err[256] = "";
                char history_target[64];
                snprintf(history_target, sizeof(history_target), "%d", total_done);
                int history_before = g_app.db->history_count;
                if (db_history_mark(g_app.db, "batch_snapshot", history_target,
                        &history_before, save_err, sizeof(save_err)) != 0) {
                    for (int i = 0; i < g_app.db->entry_count; i++)
                        db_snapshot_backup_rollback(&backups[i]);
                    total_err += total_done;
                    total_done = 0;
                    show_save_error(save_err);
                } else if (db_save(g_app.db, save_err, sizeof(save_err)) == 0) {
                    for (int i = 0; i < g_app.db->entry_count; i++)
                        db_snapshot_backup_commit(&backups[i]);
                } else {
                    db_history_restore_count(g_app.db, history_before);
                    for (int i = 0; i < g_app.db->entry_count; i++)
                        db_snapshot_backup_rollback(&backups[i]);
                    total_err += total_done;
                    total_done = 0;
                    show_save_error(save_err);
                }
            }
            free(backups);
        }
    }

    batch_scan_result_free(result);
    g_batch_running = FALSE;

    if (!ctx || !ctx->dlg || !GTK_IS_WIDGET(ctx->dlg)) return;
    if (g_autolock_pending) {
        g_autolock_pending = FALSE;
        gtk_widget_destroy(ctx->dlg);
        ctx->dlg = NULL;
        if (app_has_open_database()) on_lock_clicked(NULL, NULL);
        return;
    }

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ctx->prog), 1.0);
    char done[128];
    snprintf(done, sizeof(done), "Updated: %d, skipped: %d, errors: %d",
        total_done, total_skip, total_err);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ctx->prog), done);
    gtk_label_set_text(GTK_LABEL(ctx->lbl), done);

    g_app.current_entry_idx = -1;
    refresh_entry_list();

    if (ctx->block_close_handler_id) {
        g_signal_handler_disconnect(ctx->dlg, ctx->block_close_handler_id);
        ctx->block_close_handler_id = 0;
    }
    gtk_dialog_set_response_sensitive(GTK_DIALOG(ctx->dlg), GTK_RESPONSE_CLOSE, TRUE);
    gtk_dialog_run(GTK_DIALOG(ctx->dlg));
    gtk_widget_destroy(ctx->dlg);
    ctx->dlg = NULL;
}

static void on_batch_reindex_clicked(GtkButton *btn, gpointer user_data) {
    if (app_has_open_database() && g_app.db->legacy_read_only) return;
    (void)btn; (void)user_data;
    if (!app_has_open_database() || g_batch_running || g_carrier_running) return;

    int total = 0;
    for (int i = 0; i < g_app.db->entry_count; i++)
        if (g_app.db->entries[i].uuid && g_app.db->entries[i].uuid[0]) total++;

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
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(prog), i18n("scanning"));
    gtk_progress_bar_set_pulse_step(GTK_PROGRESS_BAR(prog), 0.04);
    gtk_box_pack_start(GTK_BOX(content), prog, FALSE, FALSE, 0);
    GtkWidget *lbl = gtk_label_new(i18n("scanning"));
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
    gtk_box_pack_start(GTK_BOX(content), lbl, FALSE, FALSE, 0);
    gtk_widget_show_all(dlg);

    if (total == 0) {
        gtk_label_set_text(GTK_LABEL(lbl), i18n("no_connected"));
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        return;
    }

    batch_task_ctx_t *ctx = g_new0(batch_task_ctx_t, 1);
    ctx->dlg = dlg;
    ctx->prog = prog;
    ctx->lbl = lbl;
    ctx->job_count = total;
    ctx->jobs = calloc((size_t)total, sizeof(*ctx->jobs));
    if (!ctx->jobs) {
        gtk_widget_destroy(dlg);
        g_free(ctx);
        show_save_error("Out of memory while preparing batch reindex");
        return;
    }

    int n = 0;
    for (int i = 0; i < g_app.db->entry_count; i++) {
        db_entry_t *e = &g_app.db->entries[i];
        if (!e->uuid || !e->uuid[0]) continue;
        ctx->jobs[n].entry_idx = i;
        ctx->jobs[n].label = xstrdup(e->label);
        ctx->jobs[n].uuid = xstrdup(e->uuid);
        n++;
    }

    gtk_dialog_set_response_sensitive(GTK_DIALOG(dlg), GTK_RESPONSE_CLOSE, FALSE);
    ctx->block_close_handler_id = g_signal_connect(dlg, "delete-event", G_CALLBACK(block_close), NULL);
    ctx->pulse_id = g_timeout_add(100, batch_progress_pulse, ctx);

    g_batch_running = TRUE;
    reset_autolock();

    GTask *task = g_task_new(NULL, NULL, batch_scan_done, NULL);
    g_task_set_task_data(task, ctx, batch_task_ctx_free);
    g_task_run_in_thread(task, batch_scan_worker);
    g_object_unref(task);
}

static void check_new_disks(void);

typedef struct {
    int idx;
    char *label;
    char *uuid;
    GtkWidget *wait;
} smart_task_ctx_t;

static void smart_task_ctx_free(gpointer data) {
    smart_task_ctx_t *ctx = data;
    if (!ctx) return;
    secure_free_string(&ctx->label);
    secure_free_string(&ctx->uuid);
    g_free(ctx);
}

static void smart_refresh_worker(GTask *task, gpointer source_object,
    gpointer task_data, GCancellable *cancellable)
{
    (void)source_object;
    smart_task_ctx_t *ctx = task_data;
    if (!ctx || (cancellable && g_cancellable_is_cancelled(cancellable))) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_CANCELLED, "SMART refresh cancelled");
        return;
    }

    int nd = 0;
    disk_info_t *disks = list_disks(&nd);
    const char *mp = NULL;
    for (int i = 0; i < nd; i++) {
        if (disks[i].uuid && disks[i].mountpoint && strcmp(disks[i].uuid, ctx->uuid) == 0) {
            mp = disks[i].mountpoint;
            break;
        }
    }
    if (!mp) {
        free_disk_list(disks, nd);
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "SMART device is not connected");
        return;
    }

    char *smart = collect_smart_data(mp);
    free_disk_list(disks, nd);
    if (!smart) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_FAILED, "SMART data is unavailable");
        return;
    }
    g_task_return_pointer(task, smart, secure_free_cb);
}

static void smart_refresh_done(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    (void)source_object; (void)user_data;
    GTask *task = G_TASK(res);
    smart_task_ctx_t *ctx = g_task_get_task_data(task);
    GError *task_err = NULL;
    char *smart = g_task_propagate_pointer(task, &task_err);

    if (ctx && ctx->wait && GTK_IS_WIDGET(ctx->wait)) {
        gtk_widget_destroy(ctx->wait);
        ctx->wait = NULL;
    }
    if (task_err) {
        if (task_err->code == G_IO_ERROR_NOT_FOUND)
            show_save_error(i18n("smart_no_device"));
        else if (task_err->code != G_IO_ERROR_CANCELLED)
            show_save_error(i18n("smart_unavailable"));
        g_error_free(task_err);
        return;
    }
    if (!ctx || !smart || !app_has_open_database() || ctx->idx < 0 || ctx->idx >= g_app.db->entry_count) {
        secure_free_string(&smart);
        return;
    }

    db_entry_t *e = &g_app.db->entries[ctx->idx];
    if (!e->label || strcmp(e->label, ctx->label) != 0) {
        secure_free_string(&smart);
        show_save_error("The selected database entry changed while refreshing SMART");
        return;
    }

    char err[256] = "";
    if (db_set_entry_smart(g_app.db, ctx->label, smart, err, sizeof(err)) != 0) {
        secure_free_string(&smart);
        show_save_error(err);
        return;
    }
    secure_free_string(&smart);
    g_app.current_entry_idx = ctx->idx;
    show_entry_details(ctx->idx);
    show_toast(i18n("smart_refresh_done"), 5000, ctx->idx);
}

static void on_refresh_smart_clicked(GtkButton *b, gpointer u) {
    if (app_has_open_database() && g_app.db->legacy_read_only) return;
    (void)b; (void)u;
    if (!app_has_open_database() || g_app.db->legacy_read_only || g_carrier_running) return;
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

    GtkWidget *wait = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
        GTK_MESSAGE_INFO, GTK_BUTTONS_NONE, "%s", i18n("scanning"));
    gtk_window_set_deletable(GTK_WINDOW(wait), FALSE);
    gtk_widget_show_all(wait);

    smart_task_ctx_t *ctx = g_new0(smart_task_ctx_t, 1);
    ctx->idx = idx;
    ctx->label = xstrdup(e->label);
    ctx->uuid = xstrdup(e->uuid);
    ctx->wait = wait;

    GTask *task = g_task_new(NULL, NULL, smart_refresh_done, NULL);
    g_task_set_task_data(task, ctx, smart_task_ctx_free);
    g_task_run_in_thread(task, smart_refresh_worker);
    g_object_unref(task);
}

static void on_refresh_connections_clicked(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    if (!app_has_open_database()) return;
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
    if (!db) return NULL;
    const uint64_t max_cached_paths = 250000U;
    uint64_t indexed_paths = 0;
    for (int i = 0; i < db->entry_count; i++) {
        const db_entry_t *e = &db->entries[i];
        if (e->file_count <= 0) continue;
        if ((uint64_t)e->file_count > max_cached_paths - indexed_paths) return NULL;
        indexed_paths += (uint64_t)e->file_count;
    }
    GHashTable *h = g_hash_table_new_full(g_str_hash, g_str_equal,
        secure_g_free_cb, free_str_list);
    if (!h) return NULL;
    for (int i = 0; i < db->entry_count; i++) {
        db_entry_t *e = &db->entries[i];
        if (!e->files || !e->files[0]) continue;
        const char *disp = (e->alias && e->alias[0]) ? e->alias : e->label;
        const char *p = e->files;
        while (*p) {
            const char *line_end = strchr(p, '\n');
            if (!line_end) line_end = p + strlen(p);
            const char *tab = memchr(p, '\t', (size_t)(line_end - p));
            const char *path_end = tab ? tab : line_end;
            size_t path_len = (size_t)(path_end - p);
            if (path_len > 0) {
                char *path = g_strndup(p, path_len);
                GList *lst = g_hash_table_lookup(h, path);
                gboolean dup = FALSE;
                for (GList *q = lst; q; q = q->next)
                    if (strcmp((char *)q->data, disp) == 0) { dup = TRUE; break; }
                if (!dup) {
                    if (lst) {
                        GList *updated = g_list_append(lst, g_strdup(disp));
                        if (updated != lst) {
                            g_hash_table_steal(h, path);
                            g_hash_table_insert(h, path, updated);
                        } else {
                            g_free(path);
                        }
                    } else {
                        lst = g_list_append(NULL, g_strdup(disp));
                        g_hash_table_insert(h, path, lst);
                        path = NULL;
                    }
                } else {
                    g_free(path);
                }
            }
            if (!*line_end) break;
            p = line_end + 1;
        }
    }
    return h;
}

static void on_filter_chip_clicked(GtkToggleButton *btn, gpointer user_data);
static gboolean on_filter_chip_press(GtkWidget *w, GdkEventButton *e, gpointer u);
static void on_filter_add_clicked(GtkButton *b, gpointer u);
static void rebuild_filt_box(GtkBox *fb, GtkSearchEntry *se, db_manager_t *db);

static gboolean ascii_contains_ci_n(const char *haystack, size_t hay_len, const char *needle) {
    if (!haystack || !needle) return FALSE;
    if (!*needle) return TRUE;
    size_t nlen = strlen(needle);
    if (nlen > hay_len) return FALSE;
    for (size_t pos = 0; pos + nlen <= hay_len; pos++) {
        size_t i = 0;
        while (i < nlen &&
               g_ascii_tolower((guchar)haystack[pos + i]) ==
               g_ascii_tolower((guchar)needle[i]))
            i++;
        if (i == nlen) return TRUE;
    }
    return FALSE;
}

static gboolean path_matches_ext_filter_n(const char *path, size_t path_len, const char *filter) {
    if (!filter || !filter[0]) return TRUE;
    if (!path || path_len == 0) return FALSE;

    const char *base = path;
    for (size_t i = 0; i < path_len; i++)
        if (path[i] == '/') base = path + i + 1;
    const char *dot = NULL;
    for (const char *p = base; p < path + path_len; p++)
        if (*p == '.') dot = p;
    if (!dot || dot + 1 >= path + path_len) return FALSE;
    const char *ext = dot + 1;
    size_t ext_len = (size_t)((path + path_len) - ext);

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

    uint64_t total_files = 0;
    int total_disks = 0;
    const int per_disk_limit = 200;

    for (int i = 0; i < db->entry_count; i++) {
        db_entry_t *e = &db->entries[i];
        if (!e->files || !e->files[0]) continue;

        GPtrArray *paths = g_ptr_array_new_with_free_func(secure_g_free_cb);
        GArray *sizes = g_array_sized_new(FALSE, FALSE, sizeof(long long), per_disk_limit);
        int match_count = 0;

        const char *p = e->files;
        while (*p) {
            const char *line_end = strchr(p, '\n');
            if (!line_end) line_end = p + strlen(p);
            const char *tab = memchr(p, '\t', (size_t)(line_end - p));
            const char *path_end = tab ? tab : line_end;
            size_t path_len = (size_t)(path_end - p);
            long long sz = -1;
            if (tab && tab + 1 < line_end) {
                char *endp = NULL;
                errno = 0;
                long long parsed = g_ascii_strtoll(tab + 1, &endp, 10);
                if (errno == 0 && endp && endp <= line_end) sz = parsed;
            }

            gboolean q_match = !q[0] || ascii_contains_ci_n(p, path_len, q);
            gboolean ext_match = !ext_filter || path_matches_ext_filter_n(p, path_len, ext_filter);
            if (path_len > 0 && q_match && ext_match) {
                match_count++;
                if ((int)paths->len < per_disk_limit) {
                    g_ptr_array_add(paths, g_strndup(p, path_len));
                    g_array_append_val(sizes, sz);
                }
            }

            if (!*line_end) break;
            p = line_end + 1;
        }

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
            snprintf(buf, sizeof(buf), "%llu %s · %d %s",
                (unsigned long long)total_files, i18n("files_found"), total_disks, i18n("disks_found"));
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
    gtk_widget_set_sensitive(add_btn, !db->legacy_read_only);
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
    if (app_has_open_database() && g_app.db->legacy_read_only) return;
    if (g_carrier_running) return;
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
    int history_before = db->history_count;
    if (db_history_mark(db, "filter_removed", removed.name ? removed.name : "",
            &history_before, err_buf, sizeof(err_buf)) != 0) {
        memmove(&db->filters[idx + 1], &db->filters[idx],
            (db->filter_count - idx) * sizeof(search_filter_t));
        db->filters[idx] = removed;
        db->filter_count++;
        show_save_error(err_buf);
        return;
    }
    if (db_save(db, err_buf, sizeof(err_buf)) != 0) {
        db_history_restore_count(db, history_before);
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
    gtk_widget_set_sensitive(mi, !g_app.db || !g_app.db->legacy_read_only);
    g_object_set_data(G_OBJECT(mi), "filter_idx", GINT_TO_POINTER(idx));
    g_signal_connect(mi, "activate", G_CALLBACK(on_filter_delete_activate), user_data);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);
    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent*)ev);
    return TRUE;
}

static void on_filter_add_clicked(GtkButton *b, gpointer user_data) {
    if (app_has_open_database() && g_app.db->legacy_read_only) return;
    (void)b;
    if (g_carrier_running) return;
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
            int history_before = db->history_count;
            if (db_history_mark(db, "filter_added", nm, &history_before,
                    err_buf, sizeof(err_buf)) != 0) {
                db->filter_count--;
                secure_free_string(&db->filters[db->filter_count].name);
                secure_free_string(&db->filters[db->filter_count].exts);
                show_save_error(err_buf);
            } else if (db_save(db, err_buf, sizeof(err_buf)) != 0) {
                db_history_restore_count(db, history_before);
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
    if (app_has_open_database() && g_app.db->legacy_read_only) return;
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
        if (!save_config()) g_warning("DiskPass: configuration could not be saved");
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
    g_app.btn_open_stego = gtk_button_new_with_label(i18n("carrier_open_hidden_short"));
    g_signal_connect(g_app.btn_open_stego, "clicked", G_CALLBACK(on_open_stego_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_open_stego, FALSE, FALSE, 0);
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
    g_app.unlock_status = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.unlock_status), "dim-label");
    gtk_box_pack_start(GTK_BOX(box), g_app.unlock_status, FALSE, FALSE, 0);
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
    if (!app_has_open_database() || g_app.current_entry_idx < 0 ||
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
    if (idx >= 0 && app_has_open_database() && idx < g_app.db->entry_count) {
        GtkListBoxRow *row = gtk_list_box_get_row_at_index(g_app.listbox, idx);
        if (row) {
            gtk_list_box_select_row(g_app.listbox, row);
            gtk_widget_grab_focus(GTK_WIDGET(g_app.listbox));
        }
    }
    return TRUE;
}

typedef struct {
    disk_info_t *disks;
    int count;
} connection_scan_result_t;

static gboolean g_connection_check_running = FALSE;

static void process_new_disks(disk_info_t *disks, int n) {
    if (!app_has_open_database() || !disks) return;

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
    g_uuids_initialized = TRUE;
}

static void check_new_disks(void) {
    if (!app_has_open_database()) return;
    int n = 0;
    disk_info_t *disks = list_disks(&n);
    if (!disks) return;
    process_new_disks(disks, n);
    free_disk_list(disks, n);
}

static void connection_scan_result_free(gpointer data) {
    connection_scan_result_t *r = data;
    if (!r) return;
    free_disk_list(r->disks, r->count);
    g_free(r);
}

static void connection_scan_worker(GTask *task, gpointer source_object,
    gpointer task_data, GCancellable *cancellable)
{
    (void)source_object; (void)task_data;
    if (cancellable && g_cancellable_is_cancelled(cancellable)) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Connection scan cancelled");
        return;
    }
    connection_scan_result_t *r = g_new0(connection_scan_result_t, 1);
    r->disks = list_disks(&r->count);
    g_task_return_pointer(task, r, connection_scan_result_free);
}

static void connection_scan_done(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    (void)source_object; (void)user_data;
    GTask *task = G_TASK(res);
    GError *err = NULL;
    connection_scan_result_t *r = g_task_propagate_pointer(task, &err);
    g_connection_check_running = FALSE;
    if (err) {
        g_error_free(err);
        return;
    }
    if (r && app_has_open_database() && r->disks)
        process_new_disks(r->disks, r->count);
    connection_scan_result_free(r);
}

static gboolean connection_check_cb(gpointer user_data) {
    (void)user_data;
    if (!app_has_open_database() || g_connection_check_running) return G_SOURCE_CONTINUE;
    g_connection_check_running = TRUE;
    GTask *task = g_task_new(NULL, NULL, connection_scan_done, NULL);
    g_task_run_in_thread(task, connection_scan_worker);
    g_object_unref(task);
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

    g_app.btn_carrier = gtk_button_new_from_icon_name("mail-attachment-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_carrier), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_carrier, i18n("carrier_tools"));
    g_signal_connect(g_app.btn_carrier, "clicked", G_CALLBACK(on_carrier_tools_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_carrier, FALSE, FALSE, 0);

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

    g_app.btn_settings = gtk_button_new_from_icon_name("preferences-system-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_settings), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_settings, i18n("security_settings"));
    g_signal_connect(g_app.btn_settings, "clicked", G_CALLBACK(on_security_settings_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(toolbar), g_app.btn_settings, FALSE, FALSE, 0);
    g_app.btn_about = gtk_button_new();
    GIcon *about_icon = NULL;
    char *about_path = find_icon_path();
    if (about_path) {
        GFile *file = g_file_new_for_path(about_path);
        about_icon = g_file_icon_new(file);
        g_object_unref(file);
        g_free(about_path);
    }
    GtkWidget *about_image = about_icon
        ? gtk_image_new_from_gicon(about_icon, GTK_ICON_SIZE_BUTTON)
        : gtk_image_new_from_icon_name("diskpass", GTK_ICON_SIZE_BUTTON);
    gtk_image_set_pixel_size(GTK_IMAGE(about_image), 28);
    gtk_widget_set_halign(about_image, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(about_image, GTK_ALIGN_CENTER);
    gtk_button_set_image(GTK_BUTTON(g_app.btn_about), about_image);
    if (about_icon) g_object_unref(about_icon);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_about), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_about, i18n("about_diskpass"));
    g_signal_connect(g_app.btn_about, "clicked", G_CALLBACK(on_about_diskpass), NULL);
    gtk_box_pack_end(GTK_BOX(toolbar), g_app.btn_about, FALSE, FALSE, 0);


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

    g_app.tree_store = gtk_tree_store_new(4, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_STRING, G_TYPE_BOOLEAN);
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
        ".carrier-current-db { color: #8f8f8f; font-size: 11px; }"
        ".carrier-dialog-title { font-size: 14px; font-weight: 600; color: #f2f2f2; }"
        ".carrier-dialog-subtitle { font-size: 10px; color: #8f8f8f; }"
        ".carrier-db-badge { font-size: 9px; color: #a8d8cf; background-color: #17221f; border: 1px solid #29463f; border-radius: 7px; padding: 2px 7px; }"
        ".carrier-choice {"
        "  background-color: #1e1e1e; border: 1px solid #333333; border-radius: 4px;"
        "  padding: 5px 8px; min-height: 24px; }"
        ".carrier-choice:hover { background-color: #222222; border-color: #444444; }"
        ".carrier-choice-primary { border-color: #31564d; background-color: #19211f; }"
        ".carrier-choice-primary:hover { border-color: #4a7f72; background-color: #1d2926; }"
        ".carrier-choice:active { background-color: #272727; }"
        ".carrier-choice-icon { color: #cfcfcf; min-width: 22px; }"
        ".carrier-choice-title { font-size: 12px; font-weight: 500; color: #e8e8e8; }"
        ".carrier-choice-desc { font-size: 10px; color: #8a8a8a; }"
        ".carrier-choice-arrow { color: #777777; }"
        ".carrier-expander { color: #b8b8b8; padding: 1px 0; font-size: 11px; }"
        ".carrier-format-name { font-size: 10px; font-weight: 600; color: #bdbdbd; }"
        ".carrier-format-value { font-size: 10px; color: #858585; }"
        ".carrier-note { font-size: 9px; color: #707070; }"
        ".flat-btn {"
        "  border: none; background: transparent;"
        "  padding: 3px 6px;"
        "  color: #a0a0a0;"
        "  font-size: 11px; }"
        ".flat-btn:hover { background-color: #262626; color: #ffffff; }"
        ".flat-btn:disabled { color: #4a4a4a; }"
        ".main-toolbar .flat-btn {"
        "  color: #8d8d8d;"
        "  border-radius: 6px;"
        "  padding: 4px 7px; }"
        ".main-toolbar .flat-btn:hover {"
        "  background-color: #1b2422;"
        "  color: #4ec9b0; }"
        ".main-toolbar .flat-btn:hover image { color: #4ec9b0; }"
        ".main-toolbar .flat-btn:active, .main-toolbar .flat-btn:checked {"
        "  background-color: #21302c;"
        "  color: #65d8c2; }"
        ".main-toolbar .flat-btn:active image, .main-toolbar .flat-btn:checked image { color: #65d8c2; }"
        ".main-toolbar .flat-btn:disabled {"
        "  background-color: transparent;"
        "  color: #464646; }"
        ".main-toolbar .flat-btn:disabled image { color: #464646; }"
        ".privacy-shield { background-color: rgba(13,13,13,0.985); }"
        ".privacy-shield-title { color: #eeeeee; font-size: 17px; font-weight: 600; }"
        ".privacy-shield-desc { color: #8e8e8e; font-size: 11px; }"
        ".privacy-shield-icon { color: #4ec9b0; }";
    static const char css2b[] =
        ".settings-head-icon { color: #4ec9b0; }"
        ".settings-title { color: #eeeeee; font-size: 16px; font-weight: 600; }"
        ".settings-row-title { color: #e8e8e8; font-size: 12px; font-weight: 500; }"
        ".settings-row-desc { color: #8a8a8a; font-size: 10px; }"
        ".settings-note { color: #707070; font-size: 10px; }"
        ".settings-always-on { color: #4ec9b0; font-size: 10px; font-weight: 600; }"
        ".integrity-ok { color: #4ec9b0; font-size: 15px; font-weight: 700; }"
        ".integrity-warn { color: #d7aa58; font-size: 15px; font-weight: 700; }"
        ".integrity-bad { color: #ff7b72; font-size: 15px; font-weight: 700; }"
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

    GString *css = g_string_sized_new(sizeof(css1) + sizeof(css2) + sizeof(css2b) + sizeof(css3));
    if (!css) return;
    g_string_append(css, css1);
    g_string_append(css, css2);
    g_string_append(css, css2b);
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
    if (g_app.privacy_shield_timer_id) { g_source_remove(g_app.privacy_shield_timer_id); g_app.privacy_shield_timer_id = 0; }
    if (g_app.focus_lock_timer_id) { g_source_remove(g_app.focus_lock_timer_id); g_app.focus_lock_timer_id = 0; }

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
    gtk_widget_add_accelerator(g_app.btn_settings, "clicked", accel,
        GDK_KEY_comma, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
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

static gboolean about_binary_draw(GtkWidget *widget, cairo_t *cr, gpointer data) {
    (void)data;
    int w = gtk_widget_get_allocated_width(widget);
    int h = gtk_widget_get_allocated_height(widget);
    cairo_set_source_rgb(cr, 0.055, 0.065, 0.065);
    cairo_paint(cr);
    PangoLayout *layout = gtk_widget_create_pango_layout(widget, NULL);
    PangoFontDescription *font = pango_font_description_from_string("Monospace 10");
    pango_layout_set_font_description(layout, font);
    pango_font_description_free(font);
    cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.065);
    for (int y = 10; y < h; y += 24) {
        pango_layout_set_text(layout, (y / 24) % 2
            ? "01001001 00110010 10100101 01011010 00101101 10100110 01010101 00110011"
            : "10110010 01001101 00110101 10100110 11010010 01011001 10101010 11001100", -1);
        cairo_move_to(cr, 12, y);
        pango_cairo_show_layout(cr, layout);
    }
    (void)w;
    g_object_unref(layout);
    return FALSE;
}

static GtkWidget *about_text(const char *text, gboolean heading) {
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    gtk_widget_set_can_focus(label, FALSE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.5);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_line_wrap_mode(GTK_LABEL(label), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_max_width_chars(GTK_LABEL(label), 48);
    gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_CENTER);
    if (heading) {
        PangoAttrList *attrs = pango_attr_list_new();
        pango_attr_list_insert(attrs, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
        pango_attr_list_insert(attrs, pango_attr_foreground_new(0xffff, 0xffff, 0xffff));
        gtk_label_set_attributes(GTK_LABEL(label), attrs);
        pango_attr_list_unref(attrs);
    }
    return label;
}

static void on_about_diskpass(GtkButton *item, gpointer data) {
    (void)item; (void)data;
    GtkWidget *dialog = gtk_dialog_new_with_buttons(i18n("about_diskpass"), g_app.window,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("close_window"), GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 500, 400);
    GtkWidget *overlay = gtk_overlay_new();
    GtkWidget *background = gtk_drawing_area_new();
    g_signal_connect(background, "draw", G_CALLBACK(about_binary_draw), NULL);
    gtk_container_add(GTK_CONTAINER(overlay), background);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 24);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), box);
    int scale = gtk_widget_get_scale_factor(GTK_WIDGET(g_app.window));
    GdkPixbuf *logo = load_icon(96 * MAX(scale, 1));
    if (logo) {
        cairo_surface_t *surface = gdk_cairo_surface_create_from_pixbuf(logo, MAX(scale, 1), NULL);
        GtkWidget *image = gtk_image_new_from_surface(surface);
        gtk_box_pack_start(GTK_BOX(box), image, FALSE, FALSE, 0);
        cairo_surface_destroy(surface);
        gtk_window_set_icon(GTK_WINDOW(dialog), logo);
        g_object_unref(logo);
    }
    GtkWidget *title = about_text("DiskPass", TRUE);
    gtk_label_set_xalign(GTK_LABEL(title), 0.5);
    PangoAttrList *attrs = pango_attr_list_new();
    pango_attr_list_insert(attrs, pango_attr_scale_new(1.85));
    pango_attr_list_insert(attrs, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
    gtk_label_set_attributes(GTK_LABEL(title), attrs);
    pango_attr_list_unref(attrs);
    gtk_box_pack_start(GTK_BOX(box), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), about_text(i18n("about_short_description"), FALSE), FALSE, FALSE, 0);
    GtkWidget *link = gtk_link_button_new_with_label("https://github.com/Sergei768/Diskpass", "GitHub · DiskPass");
    gtk_widget_set_halign(link, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), link, FALSE, FALSE, 8);
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), overlay, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}
