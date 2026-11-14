/* SPDX-License-Identifier: GPL-3.0-or-later
 * Полное окно в стиле GNOME Calculator: режимы Базовый, Расширенный,
 * Финансовый, Программирование, Клавиатурный и Конвертация (тёмная тема). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#if defined(CALC_DEBUG_MODE) || defined(CALC_SCRIPT)
#error "Scripted calculator input is forbidden in production"
#endif
#include "calculator-widget.h"
#include "calc-eval.h"
#include "calc-units.h"
#include "diskpass_calculator.h"
#include "diskpass_icon.h"
#include <sodium.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

 

 


#define CALC_THROTTLE_FILE "calc.throttle"
#define CALC_THROTTLE_KEY_FILE "calc.throttle.key"
#define CALC_THROTTLE_DOMAIN "DP-calc-throttle-v2"
#define CALC_THROTTLE_MSG_BYTES (12U + sizeof(CALC_THROTTLE_DOMAIN) - 1U)
#define CALC_THROTTLE_RECORD_BYTES (CALC_THROTTLE_MSG_BYTES + crypto_auth_BYTES)
#define CALC_PIN_LEGACY_MIN 8U
#define CALC_PIN_MAX 32U
#define CALC_MAX_INPUT 65536U

static guint g_calc_failed_attempts;
static gint64 g_calc_next_allowed_us;  
static gint64 g_calc_retry_after;      

static gboolean calc_pin_candidate(const char *text) {
    size_t len = text ? strlen(text) : 0;
    if (len < CALC_PIN_LEGACY_MIN || len > CALC_PIN_MAX) return FALSE;
    for (size_t i = 0; i < len; i++) if (!g_ascii_isdigit(text[i])) return FALSE;
    return TRUE;
}

static gboolean calc_write_all(int fd, const unsigned char *buf, size_t len) {
    while (len) {
        ssize_t n = write(fd, buf, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return FALSE;
        buf += n; len -= (size_t)n;
    }
    return TRUE;
}

 

static int calc_throttle_open_dir(gboolean create) {
    const char *override = g_getenv("DISKPASS_PRIVATE_DIR");
    gboolean explicit_dir = override && override[0] == '/';
    char *dir = explicit_dir ? g_strdup(override) :
        g_build_filename(g_get_home_dir(), ".diskpass", NULL);
    if (!dir) return -1;
    if (create && g_mkdir_with_parents(dir, 0700) != 0) { g_free(dir); return -1; }
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    g_free(dir);
    if (fd < 0) return -1;
    struct stat st;
    gboolean safe = fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid();
    if (safe && (st.st_mode & 077) != 0)
        safe = !explicit_dir && fchmod(fd, 0700) == 0;
    if (!safe) { close(fd); return -1; }
    return fd;
}

static gboolean calc_throttle_device_key(int dirfd, unsigned char key[crypto_auth_KEYBYTES],
                                         gboolean create) {
    int fd = openat(dirfd, CALC_THROTTLE_KEY_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0) {
        struct stat st;
        gboolean ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
            st.st_uid == geteuid() && (st.st_mode & 077) == 0 && st.st_size == crypto_auth_KEYBYTES;
        size_t off = 0;
        while (ok && off < crypto_auth_KEYBYTES) {
            ssize_t n = read(fd, key + off, crypto_auth_KEYBYTES - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ok = FALSE; break; }
            off += (size_t)n;
        }
        close(fd);
        if (!ok) sodium_memzero(key, crypto_auth_KEYBYTES);
        return ok;
    }
    if (!create || errno != ENOENT) return FALSE;
    randombytes_buf(key, crypto_auth_KEYBYTES);
    fd = openat(dirfd, CALC_THROTTLE_KEY_FILE, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { sodium_memzero(key, crypto_auth_KEYBYTES); return FALSE; }
    gboolean ok = fchmod(fd, 0600) == 0 && calc_write_all(fd, key, crypto_auth_KEYBYTES) && fsync(fd) == 0;
    if (close(fd) != 0) ok = FALSE;
    if (!ok) { (void)unlinkat(dirfd, CALC_THROTTLE_KEY_FILE, 0); sodium_memzero(key, crypto_auth_KEYBYTES); }
    else (void)fsync(dirfd);
    return ok;
}

static gboolean calc_throttle_persist(gint64 real_deadline_us, guint failures) {
    if (real_deadline_us < 0 || failures >= 5) return FALSE;
    int dirfd = calc_throttle_open_dir(TRUE);
    if (dirfd < 0) return FALSE;
    unsigned char key[crypto_auth_KEYBYTES], buf[CALC_THROTTLE_RECORD_BYTES];
    if (!calc_throttle_device_key(dirfd, key, TRUE)) { close(dirfd); return FALSE; }
    for (unsigned i = 0; i < 8; i++) buf[i] = (unsigned char)((uint64_t)real_deadline_us >> (8 * i));
    for (unsigned i = 0; i < 4; i++) buf[8 + i] = (unsigned char)((uint32_t)failures >> (8 * i));
    memcpy(buf + 12, CALC_THROTTLE_DOMAIN, sizeof(CALC_THROTTLE_DOMAIN) - 1);
    crypto_auth(buf + CALC_THROTTLE_MSG_BYTES, buf, CALC_THROTTLE_MSG_BYTES, key);
    unsigned char rnd[12]; char hex[sizeof(rnd) * 2 + 1], tmp[80];
    randombytes_buf(rnd, sizeof(rnd)); sodium_bin2hex(hex, sizeof(hex), rnd, sizeof(rnd));
    g_snprintf(tmp, sizeof(tmp), ".calc.throttle.%s.tmp", hex);
    int fd = openat(dirfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    gboolean ok = fd >= 0;
    if (ok) {
        ok = fchmod(fd, 0600) == 0 && calc_write_all(fd, buf, sizeof(buf)) && fsync(fd) == 0;
        if (close(fd) != 0) ok = FALSE;
        if (ok) ok = renameat(dirfd, tmp, dirfd, CALC_THROTTLE_FILE) == 0;
        if (!ok) (void)unlinkat(dirfd, tmp, 0);
        else (void)fsync(dirfd);
    }
    sodium_memzero(key, sizeof(key)); sodium_memzero(buf, sizeof(buf));
    close(dirfd);
    return ok;
}

static gint64 calc_throttle_load(guint *failures) {
    *failures = 0;
    int dirfd = calc_throttle_open_dir(FALSE);
    if (dirfd < 0) return 0;
    unsigned char buf[CALC_THROTTLE_RECORD_BYTES], key[crypto_auth_KEYBYTES];
    int fd = openat(dirfd, CALC_THROTTLE_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { close(dirfd); return 0; }
    struct stat st;
    gboolean ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
        st.st_uid == geteuid() && (st.st_mode & 077) == 0 && st.st_size == (off_t)sizeof(buf);
    size_t off = 0;
    while (ok && off < sizeof(buf)) {
        ssize_t n = read(fd, buf + off, sizeof(buf) - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = FALSE; break; }
        off += (size_t)n;
    }
    close(fd);
    if (ok) ok = calc_throttle_device_key(dirfd, key, FALSE);
    close(dirfd);
    if (ok) ok = memcmp(buf + 12, CALC_THROTTLE_DOMAIN, sizeof(CALC_THROTTLE_DOMAIN) - 1) == 0 &&
        crypto_auth_verify(buf + CALC_THROTTLE_MSG_BYTES, buf, CALC_THROTTLE_MSG_BYTES, key) == 0;
    sodium_memzero(key, sizeof(key));
    if (!ok) return 0;
    uint64_t deadline = 0; uint32_t count = 0;
    for (unsigned i = 0; i < 8; i++) deadline |= (uint64_t)buf[i] << (8 * i);
    for (unsigned i = 0; i < 4; i++) count |= (uint32_t)buf[8 + i] << (8 * i);
    if (deadline > G_MAXINT64 || count >= 5) return 0;
    *failures = count;
    return (gint64)deadline;
}

 

static gint64 calc_throttle_monotonic_deadline(gint64 real_deadline, gint64 real_now,
                                               gint64 monotonic_now) {
    if (real_deadline <= real_now) return 0;
    return monotonic_now + MIN(real_deadline - real_now, (gint64)30 * G_USEC_PER_SEC);
}

static void calc_secret_string_free(gpointer data) {
    char *text = data;
    if (text) { sodium_memzero(text, strlen(text)); g_free(text); }
}

static const char window_css[] =
"window.calc { background-color: #222226; }\n"
"window.calc.csd { border-radius: 12px; box-shadow: 0 2px 8px 1px rgba(0,0,0,.5), 0 0 0 1px rgba(255,255,255,.08); }\n"
"window.narrow .embedded-calculator { box-shadow: inset 0 3px 4px -2px rgba(0,0,0,.35); }\n"
"headerbar.calc-header { background-image: none; background-color: #2e2e32; color: #fff;\n"
"  border: none; border-bottom: 1px solid #2c2c2f; box-shadow: none; min-height: 46px;\n"
"  border-radius: 12px 12px 0 0; padding: 0 6px; }\n"
"headerbar.calc-header separator { background: none; background-color: transparent; min-width: 0; min-height: 0; margin: 0; padding: 0; border: none; }\n"
"headerbar.calc-header button { background-image: none; background-color: transparent; border: none;\n"
"  box-shadow: none; color: #fff; text-shadow: none; -gtk-icon-shadow: none; border-radius: 8px; min-height: 34px; min-width: 0; padding: 0 9px; margin: 0; }\n"
"headerbar.calc-header button:hover { background-color: rgba(255,255,255,.08); }\n"
"headerbar.calc-header button:disabled { color: rgba(255,255,255,.3); }\n"
"headerbar.calc-header button.image-button { padding: 0; min-width: 34px; }\n"
"headerbar.calc-header button.titlebutton { background-color: #434347; border-radius: 50%;\n"
"  min-width: 28px; min-height: 28px; padding: 0; margin: 0 1px; }\n"
"headerbar.calc-header button.titlebutton:hover { background-color: #4e4e53; }\n"
"headerbar.calc-header .mode-label { font-weight: bold; }\n"
"headerbar.calc-header button.calc-mode { padding: 0 6px; }\n"
".calc-history { background-color: #3e3e41; }\n"
".calc-history viewport { background: transparent; }\n"
"window.wide .calc-history { border-radius: 12px 12px 0 0; }\n"
".calc-history-row { background-color: #343437; border-top: 1px solid #2a2a2e; padding: 8px 12px; }\n"
".calc-history-row label { color: #fff; }\n"
".calc-history-row label.answer { font-weight: bold; }\n"
".calc-history-row label.equals { color: rgba(255,255,255,.6); }\n"
".calc-sep { background-color: #212125; min-height: 1px; }\n"
".calc-bottom { background-color: #343437; }\n"
"window.wide .calc-bottom { border-radius: 0 0 12px 12px; }\n"
".calc-entry-area label.expression { font-size: 1.2em; font-weight: bold; color: #fff; }\n"
".calc-entry-area button { background-image: none; background-color: transparent; border: none;\n"
"  box-shadow: none; color: #fff; min-width: 0; min-height: 0; padding: 4px 6px; }\n"
".calc-entry-area button:hover { background-color: rgba(255,255,255,.08); }\n"
".calc-bits { border-top: 1px solid #2a2a2e; }\n"
".calc-bits label { color: #fff; font-weight: bold; }\n"
".calc-bits label.idx { color: rgba(255,255,255,.55); font-weight: normal; }\n"
".calc-conv { background-color: #333336; }\n"
".calc-conv label.conv-value { font-size: 2em; font-weight: bold; color: #fff; }\n"
".calc-conv button { background-image: none; background-color: transparent; border: none; box-shadow: none;\n"
"  color: #fff; font-weight: bold; min-height: 0; min-width: 0; padding: 4px 10px; border-radius: 8px; }\n"
".calc-conv button:hover { background-color: rgba(255,255,255,.08); }\n"
"popover, popover.background { background-color: #2e2e32; background-image: none; color: #fff; border: 1px solid #1e1e22; border-radius: 12px; }\n"
"popover button, popover modelbutton { background-image: none; background-color: transparent; color: #fff; border: none; box-shadow: none; text-shadow: none; border-radius: 8px; }\n"
"popover button:hover, popover modelbutton:hover { background-color: rgba(255,255,255,.1); }\n"
"popover label { color: #fff; }\n";

typedef enum { M_BASIC, M_ADV, M_FIN, M_PROG, M_KBD, M_CONV, M_COUNT } Mode;
static const struct { const char *id, *label; gboolean wide; } MODES[M_COUNT] = {
    {"basic", "Базовый", FALSE}, {"advanced", "Расширенный", TRUE}, {"financial", "Финансовый", TRUE},
    {"programming", "Программирование", TRUE}, {"keyboard", "Клавиатурный", TRUE}, {"conversion", "Конвертация", FALSE},
};
static const struct { gint v; const char *label; } BASES[] = {
    {2, "Двоичный"}, {8, "Восьмеричный"}, {10, "Десятичный"}, {16, "Шестнадцатеричный"} };
static const struct { gint v; const char *label; } WORDS[] = {
    {8, "8-бит"}, {16, "16-бит"}, {32, "32-бита"}, {64, "64-бита"} };
static const char *const ANGLES[] = { "Deg", "Rad", "Grad" };

typedef struct CalcSession CalcSession;

typedef struct {
    CalcSession *session;
    GtkWidget *window, *header, *mode_btn, *empty_title, *undo, *redo, *more;
    GtkWidget *display_box, *scroller, *history_box, *expr, *bits_panel, *bits_lbl[2][8];
    GtkWidget *stack, *panels[M_COUNT], *conv_view;
    GtkWidget *mode_items[M_COUNT], *mode_label;
    GtkWidget *vars_pop, *funcs_pop, *base_pop, *bits_pop;
    GString *text;
    GPtrArray *states;            
    guint idx;
    double complex ans;
    CalcSettings cfg;
    Mode mode;
     
    GtkWidget *cv_cat, *cv_u1, *cv_u2, *cv_val1, *cv_val2, *cv_cat_l, *cv_u1_l, *cv_u2_l;
    guint cat, from, to;
    GString *cin;
} App;

 

struct CalcSession {
    App app;
    GtkSettings *settings;
    gboolean previous_dark;
    gchar *previous_decorations;
    GtkCssProvider *css;
    DiskpassCalculatorFinished on_finished;
    gpointer finished_data;
    gboolean asynchronous;
    guint references;  
    gboolean closed;
    gboolean verification_pending;
    gboolean unlocked;
    char unlock_hash[crypto_pwhash_STRBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char *out_key;  
};

static gboolean g_calc_active;

static void calculator_session_destroy(GtkWidget *window, gpointer user_data);
static gboolean calculator_finish_async(gpointer user_data);
static void calculator_session_unref(CalcSession *session);

 
static GtkWidget *panel_of(App *a)
{
    return a->panels[a->mode == M_KBD ? M_BASIC : a->mode];
}

 
static void update_bits(App *a)
{
    double complex v = 0;
    if (a->mode != M_PROG) return;
    if (!a->text->len || !calc_eval_full(&a->cfg, a->text->str, a->ans, &v)) v = 0;
    guint64 bits = calc_to_bits(&a->cfg, v);
    for (int r = 0; r < 2; r++)
        for (int g = 0; g < 8; g++) {
            char t[64] = "<span letter_spacing=\"4096\">";
            gsize n = strlen(t);
            for (int k = 0; k < 4; k++) {
                int bit = 63 - (r * 32 + (g % 8) * 4 + k);
                t[n++] = ((bits >> bit) & 1) ? '1' : '0';
            }
            t[n] = 0;
            g_strlcat(t, "</span>", sizeof t);
            gtk_label_set_markup(GTK_LABEL(a->bits_lbl[r][g]), t);
        }
}
static void sync_ui(App *a)
{
    gtk_label_set_text(GTK_LABEL(a->expr), a->text->str);
    gtk_widget_set_sensitive(a->undo, a->idx > 0);
    gtk_widget_set_sensitive(a->redo, a->idx + 1 < a->states->len);
    update_bits(a);
}
static void commit(App *a)
{
    if (!strcmp(a->text->str, g_ptr_array_index(a->states, a->idx))) { sync_ui(a); return; }
    g_ptr_array_set_size(a->states, a->idx + 1);
    g_ptr_array_add(a->states, g_strdup(a->text->str));
    a->idx++;
    sync_ui(a);
}
static void on_undo(GtkButton *b, App *a)
{
    (void)b;
    if (a->session->closed || a->session->verification_pending) return;
    if (!a->idx) return;
    g_string_assign(a->text, g_ptr_array_index(a->states, --a->idx));
    sync_ui(a);
}
static void on_redo(GtkButton *b, App *a)
{
    (void)b;
    if (a->session->closed || a->session->verification_pending) return;
    if (a->idx + 1 >= a->states->len) return;
    g_string_assign(a->text, g_ptr_array_index(a->states, ++a->idx));
    sync_ui(a);
}

 
static void scroll_bottom(GtkWidget *w, GdkRectangle *r, GtkScrolledWindow *sw)
{
    GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(sw);
    (void)w; (void)r;
    gtk_adjustment_set_value(adj, gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj));
}
static GtkWidget *styled_label(const char *text, const char *cls, GtkAlign align)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_style_context_add_class(gtk_widget_get_style_context(l), cls);
    gtk_widget_set_halign(l, align);
    return l;
}
static void add_history(App *a, const char *eq, const char *ans)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    GtkWidget *l1 = styled_label(eq, "equation", GTK_ALIGN_START);
    GtkWidget *l2 = styled_label("=", "equals", GTK_ALIGN_CENTER);
    GtkWidget *l3 = styled_label(ans, "answer", GTK_ALIGN_END);
    gtk_style_context_add_class(gtk_widget_get_style_context(row), "calc-history-row");
    gtk_label_set_ellipsize(GTK_LABEL(l1), PANGO_ELLIPSIZE_START);
    gtk_box_pack_start(GTK_BOX(row), l1, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(row), l2, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(row), l3, TRUE, TRUE, 0);
    gtk_widget_show_all(row);
    gtk_box_pack_start(GTK_BOX(a->history_box), row, FALSE, FALSE, 0);
}

 
typedef enum { CH_MODE, CH_BASE, CH_BITS, CH_CAT, CH_FROM, CH_TO } ChoiceKind;
typedef struct { App *app; ChoiceKind kind; gint idx; GtkWidget *pop; } Choice;
static void apply_mode(App *a, Mode m);
static void conv_refresh(App *a);
static void conv_rebuild_units(App *a);
static void set_base(App *a, gint base);
static void set_bits(App *a, gint bits);

static void on_choice(GtkButton *b, Choice *c)
{
    App *a = c->app;
    (void)b;
    if (a->session->closed || a->session->verification_pending) return;
    gtk_popover_popdown(GTK_POPOVER(c->pop));
    switch (c->kind) {
    case CH_MODE: apply_mode(a, (Mode)c->idx); break;
    case CH_BASE: set_base(a, c->idx); break;
    case CH_BITS: set_bits(a, c->idx); break;
    case CH_CAT: a->cat = c->idx; a->from = 0; a->to = 1; conv_rebuild_units(a); conv_refresh(a); break;
    case CH_FROM: a->from = c->idx; conv_refresh(a); break;
    case CH_TO: a->to = c->idx; conv_refresh(a); break;
    }
}
 
static GtkWidget *choice_popover(App *a, ChoiceKind kind, const char *const *labels, const gint *values, guint n, GtkWidget **items_out)
{
    GtkWidget *pop = gtk_popover_new(NULL), *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_set_border_width(GTK_CONTAINER(box), 6);
    for (guint i = 0; i < n; i++) {
        GtkWidget *item = gtk_model_button_new();
        Choice *c = g_new0(Choice, 1);
        c->app = a; c->kind = kind; c->idx = values ? values[i] : (gint)i; c->pop = pop;
        g_object_set(item, "text", labels[i], NULL);
        g_object_set_data_full(G_OBJECT(item), "choice", c, g_free);
        g_signal_connect(item, "clicked", G_CALLBACK(on_choice), c);
        gtk_box_pack_start(GTK_BOX(box), item, FALSE, FALSE, 0);
        if (items_out) items_out[i] = item;
    }
    gtk_container_add(GTK_CONTAINER(pop), box);
    gtk_widget_show_all(box);
    return pop;
}

 
static void insert_text(App *a, const char *t) {
    if (!t || (a->session && a->session->verification_pending)) return;
    size_t len = strlen(t);
    if (len > CALC_MAX_INPUT || a->text->len > CALC_MAX_INPUT - len) return;
    g_string_append(a->text, t); commit(a);
}

static void backspace(App *a)
{
    if (a->session->closed || a->session->verification_pending || !a->text->len) return;
    if (g_str_has_suffix(a->text->str, " mod ")) g_string_truncate(a->text, a->text->len - 5);
    else g_string_truncate(a->text, g_utf8_prev_char(a->text->str + a->text->len) - a->text->str);
    commit(a);
}
 
static void calculator_clear_secret_input(App *a) {
    sodium_memzero(a->text->str, a->text->allocated_len);
    g_string_truncate(a->text, 0);
    g_ptr_array_set_size(a->states, 0);
    g_ptr_array_add(a->states, g_strdup(""));
    a->idx = 0;
    if (!a->session->closed) sync_ui(a);
}

typedef struct {
    char pin[CALC_PIN_MAX + 1];
    char hash[crypto_pwhash_STRBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    gboolean verified, kdf_ok;
} CalcVerifyJob;

static void calculator_verify_job_free(gpointer data) {
    if (data) { sodium_memzero(data, sizeof(CalcVerifyJob)); sodium_free(data); }
}

 
static void calculator_verify_worker(GTask *task, gpointer source_object,
                                      gpointer task_data, GCancellable *cancellable) {
    (void)source_object; (void)cancellable;
    CalcVerifyJob *job = task_data;
    size_t len = strlen(job->pin);
    job->verified = crypto_pwhash_str_verify(job->hash, job->pin, (unsigned long long)len) == 0;
     

    job->kdf_ok = crypto_pwhash(job->key, sizeof(job->key), job->pin,
        (unsigned long long)len, job->salt, crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_ARGON2ID13) == 0;
    sodium_memzero(job->pin, sizeof(job->pin));
    g_task_return_boolean(task, TRUE);
}

static void calculator_verify_done(GObject *source, GAsyncResult *result, gpointer user_data) {
    (void)source;
    CalcSession *session = user_data;
    CalcVerifyJob *job = g_task_get_task_data(G_TASK(result));
    (void)g_task_propagate_boolean(G_TASK(result), NULL);
    session->verification_pending = FALSE;
    if (!session->closed) {
        App *a = &session->app;
        gtk_widget_set_sensitive(a->window, TRUE);
        if (job->verified && job->kdf_ok) {
            memcpy(session->out_key, job->key, sizeof(job->key));
            session->unlocked = TRUE;
            g_calc_failed_attempts = 0;
            g_calc_retry_after = g_calc_next_allowed_us = 0;
            (void)calc_throttle_persist(0, 0);
            gtk_widget_destroy(a->window);
        } else if (job->verified) {
            g_warning("DiskPass: could not derive protected configuration key");
        } else {
            gint64 delay = G_USEC_PER_SEC;
            if (++g_calc_failed_attempts >= 5) {
                g_calc_failed_attempts = 0;
                delay = (gint64)30 * G_USEC_PER_SEC;
            }
            g_calc_next_allowed_us = g_get_monotonic_time() + delay;
            g_calc_retry_after = g_calc_next_allowed_us;
            (void)calc_throttle_persist(g_get_real_time() + delay, g_calc_failed_attempts);
        }
    }
     

    calculator_session_unref(session);
}

static void calculator_begin_verify(App *a) {
    CalcSession *session = a->session;
    CalcVerifyJob *job = sodium_malloc(sizeof(*job));
    if (!job) {
        calculator_clear_secret_input(a);
        g_warning("DiskPass: out of secure memory for access-code verification");
        return;
    }
    memset(job, 0, sizeof(*job));
    g_strlcpy(job->pin, a->text->str, sizeof(job->pin));
    memcpy(job->hash, session->unlock_hash, sizeof(job->hash));
    memcpy(job->salt, session->salt, sizeof(job->salt));
    calculator_clear_secret_input(a);
    session->verification_pending = TRUE;
    gtk_widget_set_sensitive(a->window, FALSE);
    session->references++;
    GTask *task = g_task_new(NULL, NULL, calculator_verify_done, session);
    g_task_set_task_data(task, job, calculator_verify_job_free);
    g_task_run_in_thread(task, calculator_verify_worker);
    g_object_unref(task);
}

static void solve(App *a) {
    CalcSession *session = a->session;
    if (!a->text->len || session->closed || session->verification_pending) return;
    if (session->unlock_hash[0] && calc_pin_candidate(a->text->str)) {
         

        if (a->mode != M_BASIC) return;
        gint64 now = g_get_monotonic_time();
        if (now < g_calc_retry_after || now < g_calc_next_allowed_us) {
            calculator_clear_secret_input(a);
            return;
        }
        calculator_begin_verify(a);  
        return;
    }
    double complex v;
    GString *e = g_string_new(a->text->str);
    gint open = 0;
    for (const char *p = e->str; *p; p++) open += (*p == '(') - (*p == ')');
    gchar *shown = g_strdup(e->str);
    while (open-- > 0) g_string_append_c(e, ')');
    if (calc_eval_full(&a->cfg, e->str, a->ans, &v)) {
        gchar *res = calc_format_full(&a->cfg, v);
        add_history(a, shown, res);
        a->ans = v;
        g_string_assign(a->text, res);
        g_free(res);
    } else add_history(a, shown, "Ошибка");
    commit(a);
    g_free(shown);
    g_string_free(e, TRUE);
}
static void set_base(App *a, gint base)
{
    double complex v;
    gboolean keep_pin = a->session->unlock_hash[0] && calc_pin_candidate(a->text->str);
    gboolean ok = !keep_pin && a->text->len && calc_eval_full(&a->cfg, a->text->str, a->ans, &v);
    a->cfg.base = base;
    for (guint i = 0; i < G_N_ELEMENTS(BASES); i++)
        if (BASES[i].v == base) calculator_widget_set_button_label(CALCULATOR_WIDGET(a->panels[M_PROG]), "cal.show-base", BASES[i].label);
    calculator_widget_set_base(CALCULATOR_WIDGET(a->panels[M_PROG]), base);
    if (ok) { gchar *t = calc_format_full(&a->cfg, v); g_string_assign(a->text, t); g_free(t); }
    else if (!keep_pin) g_string_truncate(a->text, 0);
    commit(a);
}
static void set_bits(App *a, gint bits)
{
    a->cfg.bits = bits;
    for (guint i = 0; i < G_N_ELEMENTS(WORDS); i++)
        if (WORDS[i].v == bits) calculator_widget_set_button_label(CALCULATOR_WIDGET(a->panels[M_PROG]), "cal.show-bits", WORDS[i].label);
    sync_ui(a);
}
static void show_menu(App *a, GtkWidget *pop, const char *action)
{
    GtkWidget *btn = calculator_widget_get_button(CALCULATOR_WIDGET(panel_of(a)), action, NULL);
    if (!btn) return;
    gtk_popover_set_relative_to(GTK_POPOVER(pop), btn);
    gtk_popover_popup(GTK_POPOVER(pop));
}
static void do_action(App *a, const char *name, const char *target)
{
    if (a->session->closed || a->session->verification_pending) return;
    if (!strcmp(name, "cal.clear")) { g_string_truncate(a->text, 0); commit(a); }
    else if (!strcmp(name, "cal.insert-digit") || !strcmp(name, "cal.insert-general") || !strcmp(name, "cal.insert-function") || !strcmp(name, "raw")) insert_text(a, target);
    else if (!strcmp(name, "cal.insert-alpha")) insert_text(a, " mod ");
    else if (!strcmp(name, "cal.subtract")) insert_text(a, "−");
    else if (!strcmp(name, "cal.insert-numeric-point")) insert_text(a, ",");
    else if (!strcmp(name, "cal.insert-brackets")) {
        gint open = 0; for (const char *p = a->text->str; *p; p++) open += (*p == '(') - (*p == ')');
        gchar last = a->text->len ? a->text->str[a->text->len - 1] : 0;
        insert_text(a, open > 0 && (g_ascii_isalnum(last) || last == ')' || last == '!' || last == '%') ? ")" : "(");
    }
    else if (!strcmp(name, "cal.solve")) solve(a);
    else if (!strcmp(name, "cal.show-variables")) show_menu(a, a->vars_pop, "cal.show-variables");
    else if (!strcmp(name, "cal.show-functions")) show_menu(a, a->funcs_pop, "cal.show-functions");
    else if (!strcmp(name, "cal.show-base")) show_menu(a, a->base_pop, "cal.show-base");
    else if (!strcmp(name, "cal.show-bits")) show_menu(a, a->bits_pop, "cal.show-bits");
    else if (!strcmp(name, "cal.cycle-angle")) {
        a->cfg.angle = (a->cfg.angle + 1) % 3;
        calculator_widget_set_button_label(CALCULATOR_WIDGET(a->panels[M_ADV]), "cal.cycle-angle", ANGLES[a->cfg.angle]);
    }
    else if (!strcmp(name, "cal.convert-currency")) apply_mode(a, M_CONV);
     
}

 
static void set_menu_label(GtkWidget *label, const char *text) { gtk_label_set_text(GTK_LABEL(label), text); }
static void conv_refresh(App *a)
{
    double v = g_ascii_strtod(a->cin->len ? a->cin->str : "0", NULL);    
    double r = calc_units_convert(a->cat, a->from, a->to, v);
    gchar *out = calc_format(r), *in = g_strdup(a->cin->len ? a->cin->str : "0");
    for (char *c = in; *c; c++) if (*c == '.') *c = ',';
    gtk_label_set_text(GTK_LABEL(a->cv_val1), in);
    gtk_label_set_text(GTK_LABEL(a->cv_val2), out);
    set_menu_label(a->cv_cat_l, calc_units_category_name(a->cat));
    set_menu_label(a->cv_u1_l, calc_units_name(a->cat, a->from));
    set_menu_label(a->cv_u2_l, calc_units_name(a->cat, a->to));
    g_free(out); g_free(in);
}
static void conv_rebuild_units(App *a)
{
    guint n = calc_units_n(a->cat);
    const char **names = g_new0(const char *, n);
    for (guint i = 0; i < n; i++) names[i] = calc_units_name(a->cat, i);
    gtk_menu_button_set_popover(GTK_MENU_BUTTON(a->cv_u1), choice_popover(a, CH_FROM, names, NULL, n, NULL));
    gtk_menu_button_set_popover(GTK_MENU_BUTTON(a->cv_u2), choice_popover(a, CH_TO, names, NULL, n, NULL));
    g_free(names);
}
static void conv_action(App *a, const char *name, const char *target)
{
    if (!strcmp(name, "cal.insert-digit")) {
        if (!strcmp(a->cin->str, "0")) g_string_truncate(a->cin, 0);
        if (a->cin->len < 18) g_string_append(a->cin, target);
    } else if (!strcmp(name, "cal.insert-numeric-point")) {
        if (!strchr(a->cin->str, '.')) g_string_append(a->cin, a->cin->len ? "." : "0.");
    } else if (!strcmp(name, "cal.clear")) g_string_truncate(a->cin, 0);
    else if (!strcmp(name, "cal.backspace")) { if (a->cin->len) g_string_truncate(a->cin, a->cin->len - 1); }
    else if (!strcmp(name, "cal.swap-units")) { guint t = a->from; a->from = a->to; a->to = t; }
    conv_refresh(a);
}
static GtkWidget *conv_menu_button(GtkWidget **label_out)
{
    GtkWidget *btn = gtk_menu_button_new(), *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *label = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), gtk_image_new_from_icon_name("pan-down-symbolic", GTK_ICON_SIZE_BUTTON), FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(btn), box);
    *label_out = label;
    return btn;
}
static GtkWidget *build_conv_view(App *a)
{
    GtkWidget *wrap = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0), *fixed = gtk_fixed_new();
    gtk_style_context_add_class(gtk_widget_get_style_context(wrap), "calc-conv");
    gtk_box_pack_start(GTK_BOX(wrap), fixed, TRUE, TRUE, 0);
    a->cv_cat = conv_menu_button(&a->cv_cat_l);
    a->cv_u1 = conv_menu_button(&a->cv_u1_l);
    a->cv_u2 = conv_menu_button(&a->cv_u2_l);
    a->cv_val1 = styled_label("0", "conv-value", GTK_ALIGN_START);
    a->cv_val2 = styled_label("0", "conv-value", GTK_ALIGN_START);
    gtk_label_set_xalign(GTK_LABEL(a->cv_val1), 0); gtk_label_set_xalign(GTK_LABEL(a->cv_val2), 0);
    gtk_label_set_ellipsize(GTK_LABEL(a->cv_val1), PANGO_ELLIPSIZE_START);
    gtk_label_set_ellipsize(GTK_LABEL(a->cv_val2), PANGO_ELLIPSIZE_END);
    gtk_widget_set_size_request(a->cv_val1, 330, 34);
    gtk_widget_set_size_request(a->cv_val2, 330, 34);
    gtk_fixed_put(GTK_FIXED(fixed), a->cv_cat, 12, 15);
    gtk_fixed_put(GTK_FIXED(fixed), a->cv_val1, 22, 87);
    gtk_fixed_put(GTK_FIXED(fixed), a->cv_u1, 12, 130);
    gtk_fixed_put(GTK_FIXED(fixed), a->cv_val2, 22, 199);
    gtk_fixed_put(GTK_FIXED(fixed), a->cv_u2, 12, 242);
    guint n = calc_units_n_categories();
    const char **names = g_new0(const char *, n);
    for (guint i = 0; i < n; i++) names[i] = calc_units_category_name(i);
    gtk_menu_button_set_popover(GTK_MENU_BUTTON(a->cv_cat), choice_popover(a, CH_CAT, names, NULL, n, NULL));
    g_free(names);
    a->cat = 0; a->from = 0; a->to = 1;
    conv_rebuild_units(a);
    conv_refresh(a);
    return wrap;
}

 
static void place_mode_button(App *a, gboolean wide)
{
    g_object_ref(a->mode_btn);
    gtk_container_remove(GTK_CONTAINER(a->header), a->mode_btn);
    if (wide) gtk_header_bar_set_custom_title(GTK_HEADER_BAR(a->header), a->mode_btn);
    else {
        gtk_header_bar_set_custom_title(GTK_HEADER_BAR(a->header), a->empty_title);
        gtk_header_bar_pack_start(GTK_HEADER_BAR(a->header), a->mode_btn);
    }
    g_object_unref(a->mode_btn);
}
 


static gboolean g_in_apply_mode = FALSE;

static void apply_mode(App *a, Mode m)
{
    if (g_in_apply_mode) return;
    g_in_apply_mode = TRUE;

    GtkStyleContext *wc = gtk_widget_get_style_context(a->window);
    gboolean wide = MODES[m].wide;
    a->mode = m;
    gtk_label_set_text(GTK_LABEL(a->mode_label), MODES[m].label);
    for (int i = 0; i < M_COUNT; i++) g_object_set(a->mode_items[i], "active", i == (int)m, NULL);

    gtk_style_context_remove_class(wc, wide ? "narrow" : "wide");
    gtk_style_context_add_class(wc, wide ? "wide" : "narrow");
    place_mode_button(a, wide);
    gtk_widget_set_margin_start(a->mode_btn, m == M_CONV ? 54 : 0);

    gtk_widget_set_visible(a->undo, m != M_CONV);
    gtk_widget_set_visible(a->redo, m != M_CONV);
    gtk_widget_set_visible(a->display_box, m != M_CONV);
    gtk_widget_set_visible(a->conv_view, m == M_CONV);
    gtk_widget_set_visible(a->bits_panel, m == M_PROG);
    gtk_widget_set_visible(a->stack, m != M_KBD);
    if (m != M_KBD) gtk_stack_set_visible_child_name(GTK_STACK(a->stack), MODES[m].id);

    gtk_widget_set_margin_start(a->display_box, wide ? 12 : 0);
    gtk_widget_set_margin_end(a->display_box, wide ? 12 : 0);
    gtk_widget_set_margin_top(a->display_box, wide ? 12 : 0);
    gtk_widget_set_margin_bottom(a->display_box, m == M_KBD ? 12 : 0);

    gtk_window_resize(GTK_WINDOW(a->window), wide ? 700 : 360, 569);
    sync_ui(a);

    g_in_apply_mode = FALSE;
}

 
static gboolean on_key(GtkWidget *w, GdkEventKey *e, App *a)
{
    (void)w;
    if (a->session->closed || a->session->verification_pending) return TRUE;
    if (e->state & (GDK_CONTROL_MASK | GDK_MOD1_MASK)) return FALSE;
    gboolean conv = a->mode == M_CONV;
    switch (e->keyval) {
    case GDK_KEY_Return: case GDK_KEY_KP_Enter: case GDK_KEY_equal: if (!conv) solve(a); return TRUE;
    case GDK_KEY_BackSpace: if (conv) conv_action(a, "cal.backspace", ""); else backspace(a); return TRUE;
    case GDK_KEY_Escape: if (conv) conv_action(a, "cal.clear", ""); else do_action(a, "cal.clear", ""); return TRUE;
    }
    gunichar c = gdk_keyval_to_unicode(e->keyval);
    if (conv) {
        if (c >= '0' && c <= '9') { char t[2] = { (char)c, 0 }; conv_action(a, "cal.insert-digit", t); return TRUE; }
        if (c == ',' || c == '.') { conv_action(a, "cal.insert-numeric-point", ""); return TRUE; }
        return FALSE;
    }
    if (a->cfg.base == 16 && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
        char t[2] = { (char)g_ascii_toupper((gchar)c), 0 };
        do_action(a, "cal.insert-digit", t);
        return TRUE;
    }
    if (c >= '0' && c <= '9') { char t[2] = { (char)c, 0 }; do_action(a, "cal.insert-digit", t); return TRUE; }
    switch (c) {
    case '+': do_action(a, "cal.insert-general", "+"); return TRUE;
    case '-': do_action(a, "cal.subtract", ""); return TRUE;
    case '*': do_action(a, "cal.insert-general", "×"); return TRUE;
    case '/': do_action(a, "cal.insert-general", "÷"); return TRUE;
    case '%': do_action(a, "cal.insert-general", "%"); return TRUE;
    case ',': case '.': do_action(a, "cal.insert-numeric-point", ""); return TRUE;
    case '(': case ')': do_action(a, "raw", c == '(' ? "(" : ")"); return TRUE;
    case '^': do_action(a, "raw", "^"); return TRUE;
    case '!': do_action(a, "raw", "!"); return TRUE;
    case ';': do_action(a, "raw", ";"); return TRUE;
    }
    return FALSE;
}
static void on_action(CalculatorWidget *panel, const gchar *name, const gchar *target, App *a)
{
    (void)panel;
    if (a->mode == M_CONV) conv_action(a, name, target); else do_action(a, name, target);
}
static void on_backspace(GtkButton *b, App *a) { (void)b; backspace(a); }

 
typedef struct { const char *label, *insert; } Item;
typedef struct { App *app; const char *insert; GtkWidget *pop; } ItemData;
static void on_item(GtkButton *b, ItemData *d)
{
    (void)b;
    insert_text(d->app, d->insert);
    gtk_popover_popdown(GTK_POPOVER(d->pop));
}
static GtkWidget *make_item_popover(App *a, const Item *items, guint n, guint cols)
{
    GtkWidget *pop = gtk_popover_new(NULL), *grid = gtk_grid_new();
    gtk_container_set_border_width(GTK_CONTAINER(grid), 6);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 2);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 2);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    for (guint i = 0; i < n; i++) {
        GtkWidget *b = gtk_button_new_with_label(items[i].label);
        ItemData *d = g_new0(ItemData, 1);
        d->app = a; d->insert = items[i].insert; d->pop = pop;
        g_object_set_data_full(G_OBJECT(b), "item", d, g_free);
        gtk_button_set_relief(GTK_BUTTON(b), GTK_RELIEF_NONE);
        gtk_widget_set_size_request(b, 56, 36);
        g_signal_connect(b, "clicked", G_CALLBACK(on_item), d);
        gtk_grid_attach(GTK_GRID(grid), b, i % cols, i / cols, 1, 1);
    }
    gtk_container_add(GTK_CONTAINER(pop), grid);
    gtk_widget_show_all(grid);
    return pop;
}
static const Item vars_items[] = { {"π", "π"}, {"e", "e"}, {"φ", "φ"}, {"i", "i"}, {"Ans", "Ans"} };
static const Item funcs_items[] = {
    {"sin", "sin("}, {"cos", "cos("}, {"tan", "tan("}, {"√x", "√("},
    {"sin⁻¹", "asin("}, {"cos⁻¹", "acos("}, {"tan⁻¹", "atan("}, {"x²", "²"},
    {"sinh", "sinh("}, {"cosh", "cosh("}, {"tanh", "tanh("}, {"xʸ", "^"},
    {"ln", "ln("}, {"log", "log("}, {"eˣ", "exp("}, {"x!", "!"},
    {"|x|", "abs("}, {"⌊x⌋", "floor("}, {"⌈x⌉", "ceil("}, {"mod", " mod "},
};

 
static GtkWidget *make_popover(const char *const *items)
{
    GtkWidget *pop = gtk_popover_new(NULL);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_set_border_width(GTK_CONTAINER(box), 6);
    for (; *items; items++) {
        GtkWidget *item = gtk_model_button_new();
        g_object_set(item, "text", *items, NULL);
        gtk_box_pack_start(GTK_BOX(box), item, FALSE, FALSE, 0);
    }
    gtk_container_add(GTK_CONTAINER(pop), box);
    gtk_widget_show_all(box);
    return pop;
}
static GtkWidget *flat_icon(const char *icon)
{
    GtkWidget *b = gtk_button_new_from_icon_name(icon, GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_focus_on_click(b, FALSE);
    return b;
}
 
static gboolean draw_dots(GtkWidget *w, cairo_t *cr, gpointer d)
{
    GdkRGBA c;
    gint width = gtk_widget_get_allocated_width(w), height = gtk_widget_get_allocated_height(w);
    (void)d;
    gtk_style_context_get_color(gtk_widget_get_style_context(w), gtk_widget_get_state_flags(w), &c);
    gdk_cairo_set_source_rgba(cr, &c);
    for (int i = -1; i <= 1; i++) { cairo_arc(cr, width / 2.0 + i * 5.0, height / 2.0, 1.6, 0, 6.2832); cairo_fill(cr); }
    return FALSE;
}
static GtkWidget *bits_row(App *a, int row, const char *first, const char *mid, const char *last)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
    const char *idx[3] = { first, mid, last };
    int g = 0;
    for (int part = 0; part < 3; part++) {
        gtk_box_pack_start(GTK_BOX(box), styled_label(idx[part], "idx", GTK_ALIGN_CENTER), FALSE, FALSE, 0);
        if (part == 2) break;
        for (int k = 0; k < 4; k++, g++) {
            a->bits_lbl[row][g] = styled_label("0000", "bits", GTK_ALIGN_CENTER);
            gtk_box_pack_start(GTK_BOX(box), a->bits_lbl[row][g], FALSE, FALSE, 0);
        }
    }
    gtk_widget_set_margin_start(box, 19);
    return box;
}

static CalcSession *calculator_session_create(const char *unlock_hash,
                                               const unsigned char *salt,
                                               unsigned char *out_key,
                                               gboolean asynchronous,
                                               DiskpassCalculatorFinished finished,
                                               gpointer user_data)
{
    if (g_calc_active || !unlock_hash || !*unlock_hash ||
        strlen(unlock_hash) >= crypto_pwhash_STRBYTES || !salt || !out_key) return NULL;
    CalcSession *session = g_new0(CalcSession, 1);
    App *a = &session->app;
    session->references = 1;
    a->session = session;
    session->out_key = out_key;
    sodium_memzero(out_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    g_strlcpy(session->unlock_hash, unlock_hash, sizeof(session->unlock_hash));
    memcpy(session->salt, salt, sizeof(session->salt));
    session->asynchronous = asynchronous;
    session->on_finished = finished;
    session->finished_data = user_data;
    g_calc_active = TRUE;
    guint persisted_failures = 0;
    gint64 persisted = calc_throttle_load(&persisted_failures);
    g_calc_failed_attempts = persisted_failures;
    g_calc_retry_after = calc_throttle_monotonic_deadline(persisted,
        g_get_real_time(), g_get_monotonic_time());
    g_calc_next_allowed_us = g_calc_retry_after;
    session->settings = gtk_settings_get_default();
    g_object_get(session->settings,
                 "gtk-application-prefer-dark-theme", &session->previous_dark,
                 "gtk-decoration-layout", &session->previous_decorations, NULL);
    g_object_set(session->settings, "gtk-application-prefer-dark-theme", TRUE,
                 "gtk-decoration-layout", ":minimize,maximize,close", NULL);
    session->css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(session->css, window_css, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
                 GTK_STYLE_PROVIDER(session->css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
    a->text = g_string_sized_new(CALC_MAX_INPUT);
    a->cin = g_string_sized_new(CALC_MAX_INPUT);
    a->cfg = (CalcSettings)CALC_SETTINGS_DEFAULT;
    a->states = g_ptr_array_new_with_free_func(calc_secret_string_free);
    g_ptr_array_add(a->states, g_strdup(""));

     
    diskpass_set_default_icon(TRUE);
    a->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_style_context_add_class(gtk_widget_get_style_context(a->window), "calc");
    gtk_window_set_title(GTK_WINDOW(a->window), "Калькулятор");
    diskpass_bind_window_launcher(GTK_WINDOW(a->window));
    diskpass_set_window_icon(GTK_WINDOW(a->window), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(a->window), 360, 569);

     
    a->header = gtk_header_bar_new();
    gtk_style_context_add_class(gtk_widget_get_style_context(a->header), "calc-header");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(a->header), TRUE);
    a->undo = flat_icon("edit-undo-symbolic"); a->redo = flat_icon("edit-redo-symbolic");
    g_signal_connect(a->undo, "clicked", G_CALLBACK(on_undo), a);
    g_signal_connect(a->redo, "clicked", G_CALLBACK(on_redo), a);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(a->header), a->undo);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(a->header), a->redo);

    a->mode_btn = gtk_menu_button_new();
    gtk_style_context_add_class(gtk_widget_get_style_context(a->mode_btn), "calc-mode");
    GtkWidget *mbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    a->mode_label = gtk_label_new("Базовый");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->mode_label), "mode-label");
    gtk_box_pack_start(GTK_BOX(mbox), a->mode_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mbox), gtk_image_new_from_icon_name("pan-down-symbolic", GTK_ICON_SIZE_BUTTON), FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(a->mode_btn), mbox);
    {
        const char *labels[M_COUNT];
        for (int i = 0; i < M_COUNT; i++) labels[i] = MODES[i].label;
        GtkWidget *pop = choice_popover(a, CH_MODE, labels, NULL, M_COUNT, a->mode_items);
        for (int i = 0; i < M_COUNT; i++) g_object_set(a->mode_items[i], "role", GTK_BUTTON_ROLE_RADIO, NULL);
        gtk_menu_button_set_popover(GTK_MENU_BUTTON(a->mode_btn), pop);
    }
    a->empty_title = g_object_ref_sink(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0));
    gtk_header_bar_pack_start(GTK_HEADER_BAR(a->header), a->mode_btn);
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(a->header), a->empty_title);

    a->more = gtk_menu_button_new();
    GtkWidget *dots = gtk_drawing_area_new();
    gtk_widget_set_size_request(dots, 18, 18);
    g_signal_connect(dots, "draw", G_CALLBACK(draw_dots), NULL);
    gtk_container_add(GTK_CONTAINER(a->more), dots);
    gtk_style_context_add_class(gtk_widget_get_style_context(a->more), "image-button");
    static const char *const opts[] = { "Новое окно", "Очистить историю", "Параметры", "Комбинации клавиш", "Справка", "О программе «Калькулятор»", NULL };
    gtk_menu_button_set_popover(GTK_MENU_BUTTON(a->more), make_popover(opts));
    gtk_header_bar_pack_end(GTK_HEADER_BAR(a->header), a->more);
    gtk_window_set_titlebar(GTK_WINDOW(a->window), a->header);

     
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(a->window), root);

    a->display_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    a->scroller = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(a->scroller), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_style_context_add_class(gtk_widget_get_style_context(a->scroller), "calc-history");
    a->history_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_valign(a->history_box, GTK_ALIGN_END);
    g_signal_connect(a->history_box, "size-allocate", G_CALLBACK(scroll_bottom), a->scroller);
    gtk_container_add(GTK_CONTAINER(a->scroller), a->history_box);
    gtk_box_pack_start(GTK_BOX(a->display_box), a->scroller, TRUE, TRUE, 0);

    GtkWidget *sep = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(sep), "calc-sep");
    gtk_box_pack_start(GTK_BOX(a->display_box), sep, FALSE, FALSE, 0);

    GtkWidget *bottom = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(bottom), "calc-bottom");
    GtkWidget *entry_area = gtk_overlay_new();
    GtkWidget *entry_wrap = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(entry_wrap), "calc-entry-area");
    gtk_widget_set_size_request(entry_wrap, -1, 70);
    gtk_box_pack_start(GTK_BOX(entry_wrap), entry_area, TRUE, TRUE, 0);
    a->expr = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->expr), "expression");
    gtk_label_set_xalign(GTK_LABEL(a->expr), 0);
    gtk_label_set_ellipsize(GTK_LABEL(a->expr), PANGO_ELLIPSIZE_START);
    gtk_widget_set_halign(a->expr, GTK_ALIGN_FILL);
    gtk_widget_set_valign(a->expr, GTK_ALIGN_START);
    gtk_widget_set_margin_start(a->expr, 12); gtk_widget_set_margin_end(a->expr, 48);
    gtk_widget_set_margin_top(a->expr, 15);
    gtk_container_add(GTK_CONTAINER(entry_area), a->expr);
    GtkWidget *bs = gtk_button_new_from_icon_name("edit-clear-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_focus_on_click(bs, FALSE);
    gtk_widget_set_halign(bs, GTK_ALIGN_END); gtk_widget_set_valign(bs, GTK_ALIGN_START);
    gtk_widget_set_margin_end(bs, 6); gtk_widget_set_margin_top(bs, 10);
    g_signal_connect(bs, "clicked", G_CALLBACK(on_backspace), a);
    gtk_overlay_add_overlay(GTK_OVERLAY(entry_area), bs);
    gtk_box_pack_start(GTK_BOX(bottom), entry_wrap, FALSE, FALSE, 0);

    a->bits_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(a->bits_panel), "calc-bits");
    gtk_widget_set_size_request(a->bits_panel, -1, 64);
    gtk_widget_set_valign(a->bits_panel, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(a->bits_panel), bits_row(a, 0, "63", "47", "32"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(a->bits_panel), bits_row(a, 1, "31", "15", "0"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bottom), a->bits_panel, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(a->display_box), bottom, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), a->display_box, TRUE, TRUE, 0);

    a->conv_view = build_conv_view(a);
    gtk_box_pack_start(GTK_BOX(root), a->conv_view, TRUE, TRUE, 0);

    a->stack = gtk_stack_new();
    gtk_stack_set_hhomogeneous(GTK_STACK(a->stack), FALSE);
    gtk_stack_set_vhomogeneous(GTK_STACK(a->stack), FALSE);
    for (int i = 0; i < M_COUNT; i++) {
        if (i == M_KBD) continue;
        a->panels[i] = calculator_widget_new_for_mode(MODES[i].id);
        g_signal_connect(a->panels[i], "action", G_CALLBACK(on_action), a);
        gtk_stack_add_named(GTK_STACK(a->stack), a->panels[i], MODES[i].id);
    }
    gtk_box_pack_start(GTK_BOX(root), a->stack, FALSE, FALSE, 0);

    a->vars_pop = g_object_ref_sink(make_item_popover(a, vars_items, G_N_ELEMENTS(vars_items), 5));
    a->funcs_pop = g_object_ref_sink(make_item_popover(a, funcs_items, G_N_ELEMENTS(funcs_items), 4));
    {
        const char *bl[G_N_ELEMENTS(BASES)]; gint bv[G_N_ELEMENTS(BASES)];
        for (guint i = 0; i < G_N_ELEMENTS(BASES); i++) { bl[i] = BASES[i].label; bv[i] = BASES[i].v; }
        a->base_pop = g_object_ref_sink(choice_popover(a, CH_BASE, bl, bv, G_N_ELEMENTS(BASES), NULL));
        const char *wl[G_N_ELEMENTS(WORDS)]; gint wv[G_N_ELEMENTS(WORDS)];
        for (guint i = 0; i < G_N_ELEMENTS(WORDS); i++) { wl[i] = WORDS[i].label; wv[i] = WORDS[i].v; }
        a->bits_pop = g_object_ref_sink(choice_popover(a, CH_BITS, wl, wv, G_N_ELEMENTS(WORDS), NULL));
    }
    g_signal_connect(a->window, "key-press-event", G_CALLBACK(on_key), a);
    g_signal_connect(a->window, "destroy", G_CALLBACK(calculator_session_destroy), session);
    gtk_widget_show_all(a->window);
    apply_mode(a, M_BASIC);
    return session;
}

 

static void calculator_session_destroy(GtkWidget *window, gpointer user_data)
{
    (void)window;
    CalcSession *session = user_data;
    if (session->closed) return;
    session->closed = TRUE;
    session->app.window = NULL;
    if (!session->unlocked && session->out_key)
        sodium_memzero(session->out_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    session->out_key = NULL;
    if (session->asynchronous)
        g_idle_add(calculator_finish_async, session);
    else
        gtk_main_quit();
}

static void calculator_session_unref(CalcSession *session)
{
    if (--session->references) return;
    App *a = &session->app;
    GtkWidget **popovers[] = { &a->vars_pop, &a->funcs_pop, &a->base_pop, &a->bits_pop };
    for (guint i = 0; i < G_N_ELEMENTS(popovers); i++) {
        if (*popovers[i]) {
            gtk_widget_destroy(*popovers[i]);
            g_clear_object(popovers[i]);
        }
    }
    if (a->empty_title) {
        gtk_widget_destroy(a->empty_title);
        g_clear_object(&a->empty_title);
    }
    sodium_memzero(a->text->str, a->text->allocated_len);
    g_string_free(a->text, TRUE);
    sodium_memzero(a->cin->str, a->cin->allocated_len);
    g_string_free(a->cin, TRUE);
    for (guint i = 0; i < a->states->len; ++i) {
        char *snapshot = g_ptr_array_index(a->states, i);
        if (snapshot) sodium_memzero(snapshot, strlen(snapshot));
    }
    g_ptr_array_free(a->states, TRUE);
    gtk_style_context_remove_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(session->css));
    g_object_unref(session->css);
    g_object_set(session->settings,
                 "gtk-application-prefer-dark-theme", session->previous_dark,
                 "gtk-decoration-layout", session->previous_decorations, NULL);
    g_free(session->previous_decorations);
    g_calc_active = FALSE;
    sodium_memzero(session, sizeof(*session));
    g_free(session);
}

static gboolean calculator_finish_async(gpointer user_data)
{
    CalcSession *session = user_data;
    gboolean unlocked = session->unlocked;
    DiskpassCalculatorFinished finished = session->on_finished;
    gpointer data = session->finished_data;
    calculator_session_unref(session);
     
    if (finished) finished(unlocked, data);
    return G_SOURCE_REMOVE;
}

gboolean diskpass_calculator_show_async(const char *unlock_hash,
                                        const unsigned char salt[crypto_pwhash_SALTBYTES],
                                        unsigned char out_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES],
                                        DiskpassCalculatorFinished on_finished,
                                        gpointer user_data)
{
    if (!on_finished) return FALSE;
    return calculator_session_create(unlock_hash, salt, out_key,
                                     TRUE, on_finished, user_data) != NULL;
}

gboolean diskpass_calculator_run(const char *unlock_hash,
                                  const unsigned char salt[crypto_pwhash_SALTBYTES],
                                  unsigned char out_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES])
{
    CalcSession *session = calculator_session_create(unlock_hash, salt, out_key,
                                                     FALSE, NULL, NULL);
    if (!session) return FALSE;
    gtk_main();
    gboolean unlocked = session->unlocked;
    if (!session->closed && session->app.window)
        gtk_widget_destroy(session->app.window);
    calculator_session_unref(session);
    return unlocked;
}
