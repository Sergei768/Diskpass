#define _GNU_SOURCE
#include "diskpass.h"

#include <gtk/gtk.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <pango/pangocairo.h>
#include <lzma.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define E11_PLUGIN_ID      "e11-printer-native"
#define E11_PLUGIN_VERSION "2.4.1"

#define E11_SERVICE_UUID "0000fee7-0000-1000-8000-00805f9b34fb"
#define E11_CHAR_UUID    "0000fec1-0000-1000-8000-00805f9b34fb"

#define CMD_CHECK_DEVICE 0x12u
#define CMD_INQUIRY_STA  0x11u
#define CMD_START_PRINT  0x13u
#define CMD_STOP_PRINT   0x14u
#define CMD_NEXT_ZIPPED  0x5Cu
#define CMD_BUF_FULL     0x10u

#define DOTS_PER_MM 8
#define HEAD_DOTS   96
#define MARGIN_DOTS 8
#define MAX_DATA    4074
#define BUF_SIZE    4096
#define HDR_SIZE    14
#define PAYLOAD     500
#define BLE_CHUNK   20

#define E11_TEXT_MAX        4096
#define E11_DISCOVERY_MS   12000
#define E11_CONNECT_MS     15000
#define E11_SERVICES_MS    15000
#define E11_REPLY_MS        4000

static const guint8 SRGB_TO_LINEAR[256] = {
    0,50,58,63,67,70,72,74,76,78,80,82,83,85,86,88,
    89,90,92,93,95,96,97,98,100,101,102,103,105,106,107,108,
    109,110,112,113,114,115,116,117,118,119,120,121,122,123,124,125,
    126,127,128,129,130,131,132,133,134,135,135,136,137,138,139,140,
    141,142,142,143,144,145,146,147,148,148,149,150,151,152,152,153,
    154,155,156,156,157,158,159,159,160,161,162,162,163,164,165,165,
    166,167,167,168,169,170,170,171,172,172,173,174,174,175,176,177,
    177,178,179,179,180,181,181,182,183,183,184,184,185,186,186,187,
    188,188,189,190,190,191,191,192,193,193,194,195,195,196,196,197,
    198,198,199,199,200,201,201,202,202,203,203,204,205,205,206,206,
    207,207,208,209,209,210,210,211,211,212,213,213,214,214,215,215,
    216,216,217,217,218,219,219,220,220,221,221,222,222,223,223,224,
    224,225,225,226,226,227,227,228,228,229,230,230,231,231,232,232,
    233,233,234,234,235,235,236,236,237,237,238,238,238,239,239,240,
    240,241,241,242,242,243,243,244,244,245,245,246,246,247,247,248,
    248,249,249,249,250,250,251,251,252,252,253,253,254,254,255,255,
};

static const guint8 BAYER4[4][4] = {
    {8,136,40,168},
    {200,72,232,104},
    {56,184,24,152},
    {248,120,216,88}
};

typedef struct {
    gboolean buf_full;
    gboolean printing;
    gboolean busy;
    gboolean err;
    gboolean cover_open;
    gboolean low_battery;
    gboolean label_end;
    gboolean ribbon_end;
    gboolean head_hot;
} E11Status;

typedef struct {
    GtkWidget *dialog;
    GtkWidget *address;
    GtkWidget *auto_detect;
    GtkWidget *text_view;
    GtkWidget *font_size;
    GtkWidget *width_mm;
    GtkWidget *length_mm;
    GtkWidget *density;
    GtkWidget *speed;
} E11Dialog;

typedef struct {
    char *address;
    char *text;
    int font_size;
    int width_mm;
    int length_mm;
    int density;
    int speed;
    gboolean auto_detect;
    GCancellable *cancel;
} E11PrintParams;

typedef struct {
    gboolean success;
    char *message;
    char *device_address;
} E11Result;

typedef struct {
    GDBusConnection *bus;
    GDBusProxy *characteristic;
    char *device_path;
    GAsyncQueue *notifications;
    GMainContext *context;
    GCancellable *cancel;
    gboolean notify_started;
} E11Bluez;

typedef struct {
    GThread *thread;
    GCancellable *cancel;
    guint completion_source;
    guint status_source;
    gboolean shutting_down;
} E11JobState;

static const DiskPassPluginHost *g_host = NULL;
static GMutex g_job_mutex;
static E11JobState g_job = {0};

static gboolean host_api_at_least(long need)
{
    if (!g_host || !g_host->app_version) return FALSE;
    char *end = NULL;
    long v = strtol(g_host->app_version, &end, 10);
    return end != g_host->app_version && v >= need;
}

static const char *tr(const char *key, const char *fallback)
{
    if (host_api_at_least(5) && g_host->translate && key) {
        const char *value = g_host->translate(key);
        if (value && value[0] && strcmp(value, key) != 0) return value;
    }
    return fallback ? fallback : (key ? key : "");
}

static void show_message(const char *title, const char *message)
{
    if (g_host && g_host->show_message)
        g_host->show_message(title ? title : "E11", message ? message : "");
}

static gboolean host_api_v4(void)
{
    return host_api_at_least(4);
}

typedef struct {
    char *text;
    guint timeout_ms;
} E11StatusUpdate;

static void status_update_free(E11StatusUpdate *u)
{
    if (!u) return;
    g_free(u->text);
    g_free(u);
}

static gboolean status_update_on_main(gpointer user_data)
{
    E11StatusUpdate *u = user_data;
    g_mutex_lock(&g_job_mutex);
    g_job.status_source = 0;
    gboolean shutting_down = g_job.shutting_down;
    g_mutex_unlock(&g_job_mutex);
    if (!shutting_down && host_api_v4() && g_host->set_status)
        g_host->set_status(u->text, u->timeout_ms);
    return G_SOURCE_REMOVE;
}

static void post_status(const char *text, guint timeout_ms)
{
    if (!host_api_v4() || !g_host->set_status) return;
    E11StatusUpdate *u = g_new0(E11StatusUpdate, 1);
    if (!u) return;
    u->text = g_strdup(text ? text : "");
    u->timeout_ms = timeout_ms;
    if (!u->text) { g_free(u); return; }

    g_mutex_lock(&g_job_mutex);
    if (g_job.shutting_down) {
        g_mutex_unlock(&g_job_mutex);
        status_update_free(u);
        return;
    }
    if (g_job.status_source) {
        g_source_remove(g_job.status_source);
        g_job.status_source = 0;
    }
    g_job.status_source = g_idle_add_full(G_PRIORITY_DEFAULT,
        status_update_on_main, u, (GDestroyNotify)status_update_free);
    g_mutex_unlock(&g_job_mutex);
}

static char *dup_selected_disk_label(void)
{
    if (!host_api_v4() || !g_host->dup_selected_disk_label) return NULL;
    return g_host->dup_selected_disk_label();
}

static GtkWindow *find_parent_window(void)
{
    GList *wins = gtk_window_list_toplevels();
    GtkWindow *result = NULL;
    for (GList *l = wins; l; l = l->next) {
        if (GTK_IS_WINDOW(l->data) && gtk_widget_get_visible(GTK_WIDGET(l->data))) {
            result = GTK_WINDOW(l->data);
            break;
        }
    }
    g_list_free(wins);
    return result;
}

static gboolean cancelled(GCancellable *c, GError **error)
{
    if (c && g_cancellable_is_cancelled(c)) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled");
        return TRUE;
    }
    return FALSE;
}

static void put_le16(guint8 *p, guint16 v)
{
    p[0] = (guint8)(v & 0xFFu);
    p[1] = (guint8)((v >> 8) & 0xFFu);
}

static void put_le64(guint8 *p, guint64 v)
{
    for (unsigned i = 0; i < 8; i++)
        p[i] = (guint8)((v >> (8u * i)) & 0xFFu);
}

static gboolean normalize_mac(const char *src, char out[18])
{
    if (!src) return FALSE;
    char hex[13];
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p; p++) {
        if (*p == ':' || *p == '-' || g_ascii_isspace(*p)) continue;
        if (!g_ascii_isxdigit(*p) || n >= 12) return FALSE;
        hex[n++] = (char)g_ascii_toupper(*p);
    }
    if (n != 12) return FALSE;
    hex[12] = '\0';
    g_snprintf(out, 18, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
               hex[0], hex[1], hex[2], hex[3], hex[4], hex[5],
               hex[6], hex[7], hex[8], hex[9], hex[10], hex[11]);
    return TRUE;
}

static char *text_view_dup_text(GtkTextView *view)
{
    GtkTextBuffer *buf = gtk_text_view_get_buffer(view);
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buf, &start, &end);
    return gtk_text_buffer_get_text(buf, &start, &end, FALSE);
}

static gboolean e11_read_private_file(const char *path, char **out, gsize *out_len);
static gboolean e11_write_private_file(const char *path, const char *data, gsize len);

static char *config_path(void)
{
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

    char *path = g_build_filename(dir, "e11-printer.conf", NULL);
    if (!path) {
        g_free(dir);
        return NULL;
    }

    if (g_lstat(path, &st) != 0 && errno == ENOENT) {
        char *old_path = g_build_filename(g_get_user_config_dir(), "diskpass", "e11-printer.conf", NULL);
        char *data = NULL;
        gsize len = 0;
        if (old_path && e11_read_private_file(old_path, &data, &len))
            (void)e11_write_private_file(path, data, len);
        if (data) { memset(data, 0, len); g_free(data); }
        g_free(old_path);
    }

    g_free(dir);
    return path;
}

static gboolean e11_write_all(int fd, const void *data, size_t len)
{
    const unsigned char *p = data;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return FALSE;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return TRUE;
}

static gboolean e11_read_private_file(const char *path, char **out, gsize *out_len)
{
    if (!path || !out || !out_len) return FALSE;
    *out = NULL;
    *out_len = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return FALSE;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) || st.st_size < 0 || st.st_size > 1024 * 1024) {
        close(fd);
        return FALSE;
    }
    gsize len = (gsize)st.st_size;
    char *data = g_malloc(len + 1);
    if (!data) { close(fd); return FALSE; }
    gsize off = 0;
    while (off < len) {
        ssize_t n = read(fd, data + off, len - off);
        if (n > 0) off += (gsize)n;
        else if (n < 0 && errno == EINTR) continue;
        else { g_free(data); close(fd); return FALSE; }
    }
    close(fd);
    data[len] = '\0';
    if (!g_utf8_validate(data, (gssize)len, NULL)) { g_free(data); return FALSE; }
    *out = data;
    *out_len = len;
    return TRUE;
}

static gboolean e11_write_private_file(const char *path, const char *data, gsize len)
{
    if (!path || !data) return FALSE;
    char *tmp = g_strdup_printf("%s.tmp.XXXXXX", path);
    if (!tmp) return FALSE;
    int fd = g_mkstemp_full(tmp, O_WRONLY | O_CLOEXEC, 0600);
    gboolean ok = fd >= 0;
    if (ok && fchmod(fd, 0600) != 0) ok = FALSE;
    if (ok && !e11_write_all(fd, data, len)) ok = FALSE;
    if (ok && fsync(fd) != 0) ok = FALSE;
    if (fd >= 0 && close(fd) != 0) ok = FALSE;
    if (ok && rename(tmp, path) != 0) ok = FALSE;
    if (!ok) unlink(tmp);
    if (ok) {
        char *dir = g_path_get_dirname(path);
        if (dir) {
            int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
            g_free(dir);
        }
    }
    g_free(tmp);
    return ok;
}

static void load_settings(E11Dialog *d)
{
    char *path = config_path();
    if (!path) return;
    char *data = NULL;
    gsize len = 0;
    GKeyFile *kf = g_key_file_new();
    if (e11_read_private_file(path, &data, &len) &&
        g_key_file_load_from_data(kf, data, len, G_KEY_FILE_NONE, NULL)) {
        char *address = g_key_file_get_string(kf, "printer", "address", NULL);
        char mac[18];
        if (address && normalize_mac(address, mac)) gtk_entry_set_text(GTK_ENTRY(d->address), mac);
        g_free(address);
        struct { const char *key; GtkWidget *widget; gint min; gint max; } items[] = {
            {"font_size", d->font_size, 6, 160}, {"width_mm", d->width_mm, 6, 24},
            {"length_mm", d->length_mm, 10, 300}, {"density", d->density, 0, 15},
            {"speed", d->speed, 1, 100}
        };
        for (guint i = 0; i < G_N_ELEMENTS(items); i++) {
            GError *err = NULL;
            gint v = g_key_file_get_integer(kf, "printer", items[i].key, &err);
            if (!err && v >= items[i].min && v <= items[i].max)
                gtk_spin_button_set_value(GTK_SPIN_BUTTON(items[i].widget), v);
            g_clear_error(&err);
        }
        GError *auto_err = NULL;
        gboolean auto_detect = g_key_file_get_boolean(kf, "printer", "auto_detect", &auto_err);
        if (!auto_err) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->auto_detect), auto_detect);
        g_clear_error(&auto_err);
    }
    if (data) { memset(data, 0, len); g_free(data); }
    g_key_file_unref(kf);
    g_free(path);
}

static void save_settings(const char *address, int font_size, int width_mm,
                          int length_mm, int density, int speed, gboolean auto_detect)
{
    char *path = config_path();
    if (!path) return;
    GKeyFile *kf = g_key_file_new();
    char *old = NULL;
    gsize old_len = 0;
    if (e11_read_private_file(path, &old, &old_len))
        (void)g_key_file_load_from_data(kf, old, old_len, G_KEY_FILE_NONE, NULL);
    if (old) { memset(old, 0, old_len); g_free(old); }
    char mac[18];
    if (address && normalize_mac(address, mac)) g_key_file_set_string(kf, "printer", "address", mac);
    g_key_file_set_integer(kf, "printer", "font_size", CLAMP(font_size, 6, 160));
    g_key_file_set_integer(kf, "printer", "width_mm", CLAMP(width_mm, 6, 24));
    g_key_file_set_integer(kf, "printer", "length_mm", CLAMP(length_mm, 10, 300));
    g_key_file_set_integer(kf, "printer", "density", CLAMP(density, 0, 15));
    g_key_file_set_integer(kf, "printer", "speed", CLAMP(speed, 1, 100));
    g_key_file_set_boolean(kf, "printer", "auto_detect", auto_detect);
    gsize len = 0;
    char *data = g_key_file_to_data(kf, &len, NULL);
    if (data) {
        (void)e11_write_private_file(path, data, len);
        memset(data, 0, len);
        g_free(data);
    }
    g_key_file_unref(kf);
    g_free(path);
}

static gboolean render_centered_raster(const char *text, int width_mm, int length_mm,
                                        int font_size, GByteArray **out_centered,
                                        int *out_cols, int *out_bpl, GError **error)
{
    g_return_val_if_fail(out_centered != NULL, FALSE);
    *out_centered = NULL;

    if (!text || !*text || width_mm <= 0 || length_mm <= 0 || font_size <= 0) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Invalid render parameters");
        return FALSE;
    }

    const int rw = length_mm * DOTS_PER_MM;
    const int rh = width_mm * DOTS_PER_MM;
    if (rw <= 0 || rh <= 0 || rw > 4096 || rh > 512) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Label dimensions are out of range");
        return FALSE;
    }

    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, rw, rh);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Cairo surface: %s",
                    cairo_status_to_string(cairo_surface_status(surface)));
        cairo_surface_destroy(surface);
        return FALSE;
    }
    cairo_t *cr = cairo_create(surface);
    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_paint(cr);

    PangoLayout *layout = pango_cairo_create_layout(cr);
    PangoFontDescription *font = pango_font_description_new();
    pango_font_description_set_family(font, "DejaVu Sans");
    pango_font_description_set_absolute_size(font, (double)font_size * PANGO_SCALE);
    pango_layout_set_font_description(layout, font);
    pango_layout_set_text(layout, text, -1);
    pango_layout_set_alignment(layout, PANGO_ALIGN_CENTER);
    pango_layout_set_spacing(layout, 2 * PANGO_SCALE);

    PangoRectangle ink = {0}, logical = {0};
    pango_layout_get_pixel_extents(layout, &ink, &logical);
    const double x = ((double)rw - ink.width) / 2.0 - ink.x;
    const double y = ((double)rh - ink.height) / 2.0 - ink.y;
    cairo_move_to(cr, x, y);
    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
    pango_cairo_show_layout(cr, layout);

    g_object_unref(layout);
    pango_font_description_free(font);
    cairo_destroy(cr);
    cairo_surface_flush(surface);

    guint8 *pixels = cairo_image_surface_get_data(surface);
    const int stride = cairo_image_surface_get_stride(surface);

    const int w = rh;
    const int h = rw;
    const int raster_bpr = (w + 7) / 8;
    gsize raster_len = (gsize)raster_bpr * (gsize)h;
    guint8 *raster = g_try_malloc0(raster_len);
    if (!raster) {
        cairo_surface_destroy(surface);
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NO_SPACE, "Out of memory while rasterizing label");
        return FALSE;
    }

    for (int yy = 0; yy < h; yy++) {
        const guint8 *src_row_base = NULL;
        for (int xx = 0; xx < w; xx++) {
            const int src_x = rw - 1 - yy;
            const int src_y = xx;
            src_row_base = pixels + (gsize)src_y * (gsize)stride;
            const guint8 gray = src_row_base[(gsize)src_x * 4u];
            const int mx = w - 1 - xx;
            if (SRGB_TO_LINEAR[gray] < BAYER4[yy & 3][mx & 3])
                raster[(gsize)yy * raster_bpr + (gsize)mx / 8u] |= (guint8)(0x80u >> (mx & 7));
        }
    }
    cairo_surface_destroy(surface);

    const int bpl = (HEAD_DOTS + 7) / 8;
    GByteArray *centered = g_byte_array_sized_new((guint)((gsize)h * bpl));
    g_byte_array_set_size(centered, (guint)((gsize)h * bpl));
    memset(centered->data, 0, centered->len);

    const int input_bpr = (w + 7) / 8;
    const int off = MAX(0, (HEAD_DOTS - w) / 2);
    const int copy_width = MIN(w, HEAD_DOTS);
    for (int c = 0; c < h; c++) {
        for (int d = 0; d < copy_width; d++) {
            const gsize ibyte = (gsize)c * input_bpr + (gsize)d / 8u;
            if ((raster[ibyte] >> (7 - (d & 7))) & 1u) {
                const int od = off + d;
                if (od < HEAD_DOTS)
                    centered->data[(gsize)c * bpl + (gsize)od / 8u] |= (guint8)(1u << (od & 7));
            }
        }
    }
    g_free(raster);

    *out_centered = centered;
    if (out_cols) *out_cols = h;
    if (out_bpl) *out_bpl = bpl;
    return TRUE;
}

static void build_print_buffer(guint8 out[BUF_SIZE], const guint8 *data, int bpl,
                               int cols, gboolean first, gboolean last, int density)
{
    memset(out, 0, BUF_SIZE);
    out[2] = (guint8)((first ? 0x02 : 0) | (last ? 0x04 : 0) | (last ? 0x08 : 0));
    out[3] = (guint8)(((density & 0x0F) << 2) | (1 << 6));
    put_le16(out + 4, (guint16)cols);
    out[6] = (guint8)bpl;
    put_le16(out + 8, MARGIN_DOTS);
    put_le16(out + 10, MARGIN_DOTS);
    out[12] = (guint8)MIN(density, 15);

    gsize payload_len = (gsize)cols * (gsize)bpl;
    if (payload_len > BUF_SIZE - HDR_SIZE) payload_len = BUF_SIZE - HDR_SIZE;
    if (payload_len > 0 && data) memcpy(out + HDR_SIZE, data, payload_len);

    const int data_end = cols * bpl + HDR_SIZE;
    guint32 cs = 0;
    for (int i = 2; i < 14; i++) cs += out[i];
    for (int i = 1; i <= data_end / 256; i++) {
        const int idx = i * 256 - 1;
        if (idx < BUF_SIZE) cs += out[idx];
    }
    put_le16(out, (guint16)(cs & 0xFFFFu));
}

static gboolean build_raw_buffers(const GByteArray *centered, int bpl, int total_cols,
                                  int density, GByteArray **out_raw, GError **error)
{
    *out_raw = NULL;
    if (!centered || bpl <= 0 || total_cols <= 2 * MARGIN_DOTS) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Label is too short");
        return FALSE;
    }
    const int max_cols = MAX_DATA / bpl;
    const int image_cols = total_cols - MARGIN_DOTS - MARGIN_DOTS;
    if (max_cols <= 0 || image_cols <= 0) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Invalid E11 raster geometry");
        return FALSE;
    }

    GByteArray *raw = g_byte_array_new();
    int cc = 0;
    while (cc < image_cols) {
        const int c = MIN(max_cols, image_cols - cc);
        const gboolean first = (cc == 0);
        const gboolean last = (cc + c >= image_cols);
        const gsize start = (gsize)(MARGIN_DOTS + cc) * (gsize)bpl;
        const gsize needed = (gsize)c * (gsize)bpl;
        if (start > centered->len || needed > centered->len - start) {
            g_byte_array_unref(raw);
            g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Raster buffer bounds error");
            return FALSE;
        }
        guint8 buf[BUF_SIZE];
        build_print_buffer(buf, centered->data + start, bpl, c, first, last, density);
        g_byte_array_append(raw, buf, BUF_SIZE);
        cc += c;
    }
    *out_raw = raw;
    return TRUE;
}

static gboolean lzma_compress_alone(const guint8 *raw, gsize raw_len,
                                    GByteArray **out_comp, GError **error)
{
    *out_comp = NULL;
    lzma_options_lzma opt;
    if (lzma_lzma_preset(&opt, 6)) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Cannot initialize LZMA options");
        return FALSE;
    }
    opt.dict_size = 8192;
    opt.lc = 3;
    opt.lp = 0;
    opt.pb = 2;
    opt.nice_len = 128;

    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret lr = lzma_alone_encoder(&strm, &opt);
    if (lr != LZMA_OK) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "LZMA encoder init failed (%d)", (int)lr);
        return FALSE;
    }

    GByteArray *out = g_byte_array_sized_new((guint)MIN((gsize)65536, raw_len + 128));
    strm.next_in = raw;
    strm.avail_in = raw_len;
    guint8 chunk[4096];

    do {
        strm.next_out = chunk;
        strm.avail_out = sizeof(chunk);
        lr = lzma_code(&strm, LZMA_FINISH);
        const gsize produced = sizeof(chunk) - strm.avail_out;
        if (produced) g_byte_array_append(out, chunk, (guint)produced);
    } while (lr == LZMA_OK);

    lzma_end(&strm);
    if (lr != LZMA_STREAM_END) {
        g_byte_array_unref(out);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "LZMA compression failed (%d)", (int)lr);
        return FALSE;
    }
    if (out->len < 13) {
        g_byte_array_unref(out);
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid LZMA-alone output");
        return FALSE;
    }

    put_le64(out->data + 5, raw_len);
    *out_comp = out;
    return TRUE;
}

static gboolean prepare_label(const E11PrintParams *p, GByteArray **out_comp,
                              guint16 *out_raw_len, GError **error)
{
    GByteArray *centered = NULL, *raw = NULL, *comp = NULL;
    int cols = 0, bpl = 0;
    if (!render_centered_raster(p->text, p->width_mm, p->length_mm, p->font_size,
                                &centered, &cols, &bpl, error))
        goto fail;
    if (!build_raw_buffers(centered, bpl, cols, p->density, &raw, error))
        goto fail;
    if (raw->len > G_MAXUINT16) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NO_SPACE, "E11 raw print job exceeds 65535 bytes");
        goto fail;
    }
    if (!lzma_compress_alone(raw->data, raw->len, &comp, error))
        goto fail;
    if ((comp->len + PAYLOAD - 1) / PAYLOAD > 255) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NO_SPACE, "Compressed E11 job needs more than 255 frames");
        goto fail;
    }

    *out_raw_len = (guint16)raw->len;
    *out_comp = comp;
    g_byte_array_unref(centered);
    g_byte_array_unref(raw);
    return TRUE;

fail:
    if (centered) g_byte_array_unref(centered);
    if (raw) g_byte_array_unref(raw);
    if (comp) g_byte_array_unref(comp);
    return FALSE;
}

static gboolean remote_error_is(GError *error, const char *name)
{
    if (!error || !g_dbus_error_is_remote_error(error)) return FALSE;
    char *remote = g_dbus_error_get_remote_error(error);
    gboolean same = remote && strcmp(remote, name) == 0;
    g_free(remote);
    return same;
}

static GVariant *bluez_get_objects(GDBusConnection *bus, GCancellable *cancel, GError **error)
{
    return g_dbus_connection_call_sync(bus, "org.bluez", "/",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects",
        NULL, G_VARIANT_TYPE("(a{oa{sa{sv}}})"),
        G_DBUS_CALL_FLAGS_NONE, 10000, cancel, error);
}

static char *bluez_find_first_adapter(GDBusConnection *bus, GCancellable *cancel)
{
    GError *err = NULL;
    GVariant *reply = bluez_get_objects(bus, cancel, &err);
    if (!reply) { g_clear_error(&err); return NULL; }
    GVariant *objects = g_variant_get_child_value(reply, 0);
    GVariantIter it;
    const char *path = NULL;
    GVariant *ifaces = NULL;
    char *found = NULL;
    g_variant_iter_init(&it, objects);
    while (g_variant_iter_next(&it, "{&o@a{sa{sv}}}", &path, &ifaces)) {
        GVariant *props = g_variant_lookup_value(ifaces, "org.bluez.Adapter1", G_VARIANT_TYPE("a{sv}"));
        if (props) {
            found = g_strdup(path);
            g_variant_unref(props);
            g_variant_unref(ifaces);
            break;
        }
        g_variant_unref(ifaces);
    }
    g_variant_unref(objects);
    g_variant_unref(reply);
    return found;
}

static gboolean bluez_props_has_uuid(GVariant *props, const char *wanted_uuid)
{
    if (!props || !wanted_uuid) return FALSE;
    GVariant *uuids = g_variant_lookup_value(props, "UUIDs", G_VARIANT_TYPE("as"));
    if (!uuids) return FALSE;
    gboolean found = FALSE;
    GVariantIter it;
    const char *uuid = NULL;
    g_variant_iter_init(&it, uuids);
    while (g_variant_iter_next(&it, "&s", &uuid)) {
        if (uuid && g_ascii_strcasecmp(uuid, wanted_uuid) == 0) {
            found = TRUE;
            break;
        }
    }
    g_variant_unref(uuids);
    return found;
}

static char *bluez_find_e11_address_once(GDBusConnection *bus,
                                         GCancellable *cancel,
                                         GError **error)
{
    GVariant *reply = bluez_get_objects(bus, cancel, error);
    if (!reply) return NULL;

    GVariant *objects = g_variant_get_child_value(reply, 0);
    GHashTable *device_addresses = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    GPtrArray *service_devices = g_ptr_array_new_with_free_func(g_free);
    char *found = NULL;

    GVariantIter it;
    const char *path = NULL;
    GVariant *ifaces = NULL;
    g_variant_iter_init(&it, objects);
    while (g_variant_iter_next(&it, "{&o@a{sa{sv}}}", &path, &ifaces)) {
        GVariant *dev = g_variant_lookup_value(ifaces, "org.bluez.Device1", G_VARIANT_TYPE("a{sv}"));
        if (dev) {
            const char *addr = NULL;
            if (g_variant_lookup(dev, "Address", "&s", &addr) && addr) {
                char normalized[18];
                if (normalize_mac(addr, normalized)) {
                    g_hash_table_replace(device_addresses, g_strdup(path), g_strdup(normalized));
                    if (bluez_props_has_uuid(dev, E11_SERVICE_UUID) && !found)
                        found = g_strdup(normalized);
                }
            }
            g_variant_unref(dev);
        }

        GVariant *svc = g_variant_lookup_value(ifaces, "org.bluez.GattService1", G_VARIANT_TYPE("a{sv}"));
        if (svc) {
            const char *uuid = NULL;
            if (g_variant_lookup(svc, "UUID", "&s", &uuid) && uuid &&
                g_ascii_strcasecmp(uuid, E11_SERVICE_UUID) == 0) {
                const char *m = strstr(path, "/service");
                if (m && m > path)
                    g_ptr_array_add(service_devices, g_strndup(path, (gsize)(m - path)));
            }
            g_variant_unref(svc);
        }
        g_variant_unref(ifaces);
        if (found) break;
    }

    if (!found) {
        for (guint i = 0; i < service_devices->len; i++) {
            const char *dev_path = g_ptr_array_index(service_devices, i);
            const char *addr = g_hash_table_lookup(device_addresses, dev_path);
            if (addr) {
                found = g_strdup(addr);
                break;
            }
        }
    }

    g_ptr_array_unref(service_devices);
    g_hash_table_destroy(device_addresses);
    g_variant_unref(objects);
    g_variant_unref(reply);
    return found;
}

static char *bluez_auto_detect_e11(GCancellable *cancel, GError **error)
{
    GDBusConnection *bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, cancel, error);
    if (!bus) return NULL;

    char *found = bluez_find_e11_address_once(bus, cancel, error);
    if (found || (error && *error)) {
        g_object_unref(bus);
        return found;
    }

    char *adapter = bluez_find_first_adapter(bus, cancel);
    if (!adapter) {
        g_object_unref(bus);
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                            "No BlueZ Bluetooth adapter found");
        return NULL;
    }

    gboolean stop_discovery = FALSE;
    GError *start_err = NULL;
    GVariant *r = g_dbus_connection_call_sync(bus, "org.bluez", adapter,
        "org.bluez.Adapter1", "StartDiscovery", NULL, NULL,
        G_DBUS_CALL_FLAGS_NONE, 5000, cancel, &start_err);
    if (r) {
        g_variant_unref(r);
        stop_discovery = TRUE;
    } else if (remote_error_is(start_err, "org.bluez.Error.InProgress")) {
        g_clear_error(&start_err);
    } else {
        g_clear_error(&start_err);
    }

    const gint64 deadline = g_get_monotonic_time() + (gint64)E11_DISCOVERY_MS * 1000;
    while (!found && g_get_monotonic_time() < deadline) {
        if (cancelled(cancel, error)) break;
        GError *find_err = NULL;
        found = bluez_find_e11_address_once(bus, cancel, &find_err);
        if (find_err) {
            if (error && !*error) *error = find_err;
            else g_clear_error(&find_err);
            break;
        }
        if (!found) g_usleep(250 * 1000);
    }

    if (stop_discovery) {
        GError *stop_err = NULL;
        GVariant *sr = g_dbus_connection_call_sync(bus, "org.bluez", adapter,
            "org.bluez.Adapter1", "StopDiscovery", NULL, NULL,
            G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &stop_err);
        if (sr) g_variant_unref(sr);
        g_clear_error(&stop_err);
    }

    g_free(adapter);
    g_object_unref(bus);

    if (found) return found;
    if (error && *error) return NULL;
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
        "Katasymbol E11 was not found. Power on the printer and keep it nearby.");
    return NULL;
}

static char *bluez_find_device(GDBusConnection *bus, const char *mac,
                               GCancellable *cancel, GError **error)
{
    GVariant *reply = bluez_get_objects(bus, cancel, error);
    if (!reply) return NULL;
    GVariant *objects = g_variant_get_child_value(reply, 0);
    GVariantIter it;
    const char *path = NULL;
    GVariant *ifaces = NULL;
    char *found = NULL;
    g_variant_iter_init(&it, objects);
    while (g_variant_iter_next(&it, "{&o@a{sa{sv}}}", &path, &ifaces)) {
        GVariant *props = g_variant_lookup_value(ifaces, "org.bluez.Device1", G_VARIANT_TYPE("a{sv}"));
        if (props) {
            const char *addr = NULL;
            if (g_variant_lookup(props, "Address", "&s", &addr) && addr && g_ascii_strcasecmp(addr, mac) == 0)
                found = g_strdup(path);
            g_variant_unref(props);
        }
        g_variant_unref(ifaces);
        if (found) break;
    }
    g_variant_unref(objects);
    g_variant_unref(reply);
    return found;
}

static char *bluez_find_characteristic(GDBusConnection *bus, const char *device_path,
                                       GCancellable *cancel, GError **error)
{
    GVariant *reply = bluez_get_objects(bus, cancel, error);
    if (!reply) return NULL;
    GVariant *objects = g_variant_get_child_value(reply, 0);
    GVariantIter it;
    const char *path = NULL;
    GVariant *ifaces = NULL;
    char *service_path = NULL;
    char *found = NULL;
    const gsize dev_len = strlen(device_path);

    g_variant_iter_init(&it, objects);
    while (g_variant_iter_next(&it, "{&o@a{sa{sv}}}", &path, &ifaces)) {
        if (strlen(path) > dev_len && strncmp(path, device_path, dev_len) == 0 && path[dev_len] == '/') {
            GVariant *props = g_variant_lookup_value(ifaces, "org.bluez.GattService1", G_VARIANT_TYPE("a{sv}"));
            if (props) {
                const char *uuid = NULL;
                if (g_variant_lookup(props, "UUID", "&s", &uuid) && uuid &&
                    g_ascii_strcasecmp(uuid, E11_SERVICE_UUID) == 0)
                    service_path = g_strdup(path);
                g_variant_unref(props);
            }
        }
        g_variant_unref(ifaces);
        if (service_path) break;
    }

    if (service_path) {
        g_variant_iter_init(&it, objects);
        while (g_variant_iter_next(&it, "{&o@a{sa{sv}}}", &path, &ifaces)) {
            GVariant *props = g_variant_lookup_value(ifaces, "org.bluez.GattCharacteristic1", G_VARIANT_TYPE("a{sv}"));
            if (props) {
                const char *uuid = NULL;
                const char *service = NULL;
                if (g_variant_lookup(props, "UUID", "&s", &uuid) &&
                    g_variant_lookup(props, "Service", "&o", &service) &&
                    uuid && service && strcmp(service, service_path) == 0 &&
                    g_ascii_strcasecmp(uuid, E11_CHAR_UUID) == 0)
                    found = g_strdup(path);
                g_variant_unref(props);
            }
            g_variant_unref(ifaces);
            if (found) break;
        }
    }

    g_free(service_path);
    g_variant_unref(objects);
    g_variant_unref(reply);
    return found;
}

static gboolean bluez_discover_device(E11Bluez *bz, const char *mac, char **out_device, GError **error)
{
    *out_device = bluez_find_device(bz->bus, mac, bz->cancel, error);
    if (*out_device) return TRUE;
    if (error && *error) return FALSE;

    char *adapter = bluez_find_first_adapter(bz->bus, bz->cancel);
    if (!adapter) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "No BlueZ Bluetooth adapter found");
        return FALSE;
    }

    gboolean stop_discovery = FALSE;
    GError *start_err = NULL;
    GVariant *r = g_dbus_connection_call_sync(bz->bus, "org.bluez", adapter,
        "org.bluez.Adapter1", "StartDiscovery", NULL, NULL,
        G_DBUS_CALL_FLAGS_NONE, 5000, bz->cancel, &start_err);
    if (r) {
        g_variant_unref(r);
        stop_discovery = TRUE;
    } else if (remote_error_is(start_err, "org.bluez.Error.InProgress")) {
        g_clear_error(&start_err);
    } else {
        g_clear_error(&start_err); 
    }

    const gint64 deadline = g_get_monotonic_time() + (gint64)E11_DISCOVERY_MS * 1000;
    while (g_get_monotonic_time() < deadline) {
        if (cancelled(bz->cancel, error)) break;
        GError *find_err = NULL;
        *out_device = bluez_find_device(bz->bus, mac, bz->cancel, &find_err);
        if (*out_device) {
            g_clear_error(&find_err);
            break;
        }
        if (find_err) {
            if (error && !*error) *error = find_err; else g_clear_error(&find_err);
            break;
        }
        g_usleep(250 * 1000);
    }

    if (stop_discovery) {
        GError *stop_err = NULL;
        GVariant *sr = g_dbus_connection_call_sync(bz->bus, "org.bluez", adapter,
            "org.bluez.Adapter1", "StopDiscovery", NULL, NULL,
            G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &stop_err);
        if (sr) g_variant_unref(sr);
        g_clear_error(&stop_err);
    }
    g_free(adapter);

    if (*out_device) return TRUE;
    if (error && *error) return FALSE;
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                "Bluetooth device %s was not found. Pair it or keep it powered on and nearby.", mac);
    return FALSE;
}

static void on_characteristic_properties(GDBusProxy *proxy, GVariant *changed,
                                         const gchar *const *invalidated, gpointer user_data)
{
    (void)proxy; (void)invalidated;
    E11Bluez *bz = user_data;
    GVariant *v = g_variant_lookup_value(changed, "Value", G_VARIANT_TYPE("ay"));
    if (!v) return;
    gsize n = 0;
    const guint8 *p = g_variant_get_fixed_array(v, &n, sizeof(guint8));
    if (p && n > 0 && n <= 4096)
        g_async_queue_push(bz->notifications, g_bytes_new(p, n));
    g_variant_unref(v);
}

static gboolean bluez_connect(E11Bluez *bz, const char *mac, GCancellable *cancel, GError **error)
{
    memset(bz, 0, sizeof(*bz));
    if (!cancel) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Print job has no cancellable");
        return FALSE;
    }
    bz->cancel = g_object_ref(cancel);
    bz->notifications = g_async_queue_new_full((GDestroyNotify)g_bytes_unref);
    bz->context = g_main_context_new();
    g_main_context_push_thread_default(bz->context);

    bz->bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, bz->cancel, error);
    if (!bz->bus) return FALSE;

    if (!bluez_discover_device(bz, mac, &bz->device_path, error)) return FALSE;

    GError *conn_err = NULL;
    GVariant *r = g_dbus_connection_call_sync(bz->bus, "org.bluez", bz->device_path,
        "org.bluez.Device1", "Connect", NULL, NULL,
        G_DBUS_CALL_FLAGS_NONE, E11_CONNECT_MS, bz->cancel, &conn_err);
    if (r) {
        g_variant_unref(r);
    } else if (remote_error_is(conn_err, "org.bluez.Error.AlreadyConnected") ||
               remote_error_is(conn_err, "org.bluez.Error.InProgress")) {
        g_clear_error(&conn_err);
    } else {
        g_propagate_prefixed_error(error, conn_err, "BlueZ Connect: ");
        return FALSE;
    }

    char *char_path = NULL;
    const gint64 deadline = g_get_monotonic_time() + (gint64)E11_SERVICES_MS * 1000;
    while (g_get_monotonic_time() < deadline) {
        if (cancelled(bz->cancel, error)) return FALSE;
        GError *find_err = NULL;
        char_path = bluez_find_characteristic(bz->bus, bz->device_path, bz->cancel, &find_err);
        if (char_path) { g_clear_error(&find_err); break; }
        if (find_err) {
            g_propagate_prefixed_error(error, find_err, "BlueZ services: ");
            return FALSE;
        }
        g_usleep(200 * 1000);
    }
    if (!char_path) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                    "E11 GATT characteristic %s was not found", E11_CHAR_UUID);
        return FALSE;
    }

    bz->characteristic = g_dbus_proxy_new_sync(bz->bus, G_DBUS_PROXY_FLAGS_NONE, NULL,
        "org.bluez", char_path, "org.bluez.GattCharacteristic1", bz->cancel, error);
    g_free(char_path);
    if (!bz->characteristic) return FALSE;
    g_signal_connect(bz->characteristic, "g-properties-changed",
                     G_CALLBACK(on_characteristic_properties), bz);

    r = g_dbus_proxy_call_sync(bz->characteristic, "StartNotify", NULL,
        G_DBUS_CALL_FLAGS_NONE, 5000, bz->cancel, error);
    if (!r) return FALSE;
    g_variant_unref(r);
    bz->notify_started = TRUE;
    return TRUE;
}

static void bluez_cleanup(E11Bluez *bz)
{
    if (!bz) return;
    if (bz->notify_started && bz->characteristic) {
        GError *err = NULL;
        GVariant *r = g_dbus_proxy_call_sync(bz->characteristic, "StopNotify", NULL,
            G_DBUS_CALL_FLAGS_NONE, 3000, NULL, &err);
        if (r) g_variant_unref(r);
        g_clear_error(&err);
    }
    if (bz->characteristic) g_object_unref(bz->characteristic);
    bz->characteristic = NULL;
    if (bz->bus) g_object_unref(bz->bus);
    bz->bus = NULL;
    if (bz->notifications) g_async_queue_unref(bz->notifications);
    bz->notifications = NULL;
    g_clear_pointer(&bz->device_path, g_free);
    if (bz->cancel) g_object_unref(bz->cancel);
    bz->cancel = NULL;
    if (bz->context) {
        g_main_context_pop_thread_default(bz->context);
        g_main_context_unref(bz->context);
        bz->context = NULL;
    }
}

static gboolean bluez_write(E11Bluez *bz, const guint8 *data, gsize len, GError **error)
{
    if (cancelled(bz->cancel, error)) return FALSE;
    GVariantBuilder opts;
    g_variant_builder_init(&opts, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&opts, "{sv}", "type", g_variant_new_string("command"));
    GVariant *arr = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, data, len, sizeof(guint8));
    GVariant *optv = g_variant_builder_end(&opts);
    GVariant *children[2] = { arr, optv };
    GVariant *params = g_variant_new_tuple(children, 2);
    GVariant *r = g_dbus_proxy_call_sync(bz->characteristic, "WriteValue", params,
        G_DBUS_CALL_FLAGS_NONE, 5000, bz->cancel, error);
    if (!r) return FALSE;
    g_variant_unref(r);
    return TRUE;
}

static GBytes *bluez_wait_packet(E11Bluez *bz, int want_cmd, int timeout_ms)
{
    const gint64 deadline = g_get_monotonic_time() + (gint64)timeout_ms * 1000;
    while (g_get_monotonic_time() < deadline) {
        if (g_cancellable_is_cancelled(bz->cancel)) return NULL;
        while (g_main_context_pending(bz->context))
            (void)g_main_context_iteration(bz->context, FALSE);
        GBytes *packet = g_async_queue_try_pop(bz->notifications);
        if (packet) {
            gsize n = 0;
            const guint8 *p = g_bytes_get_data(packet, &n);
            if (want_cmd < 0 || (n > 7 && p[7] == (guint8)want_cmd))
                return packet;
            g_bytes_unref(packet);
        }
        g_usleep(5 * 1000);
    }
    return NULL;
}

static void make_cmd(guint8 out[16], guint8 cmd, guint16 p1, guint16 p2)
{
    memset(out, 0, 16);
    const guint8 prefix[8] = {0x7E,0x5A,0x0C,0x00,0x10,0x01,0xAA,cmd};
    memcpy(out, prefix, sizeof(prefix));
    out[11] = 0x01;
    put_le16(out + 12, p1);
    put_le16(out + 14, p2);
    guint32 sum = 0;
    for (int i = 10; i < 16; i++) sum += out[i];
    put_le16(out + 8, (guint16)(sum & 0xFFFFu));
}

static GBytes *printer_cmd(E11Bluez *bz, guint8 cmd, guint16 p1, guint16 p2,
                           gboolean required, GError **error)
{
    guint8 packet[16];
    make_cmd(packet, cmd, p1, p2);
    if (!bluez_write(bz, packet, sizeof(packet), error)) return NULL;
    GBytes *reply = bluez_wait_packet(bz, cmd, E11_REPLY_MS);
    if (!reply && required) {
        if (cancelled(bz->cancel, error)) return NULL;
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "No reply to E11 command 0x%02X", cmd);
    }
    return reply;
}

static gboolean parse_status(GBytes *bytes, E11Status *out)
{
    if (!bytes || !out) return FALSE;
    gsize n = 0;
    const guint8 *b = g_bytes_get_data(bytes, &n);
    if (n < 20 || b[0] != 0x7E || b[1] != 0x5A) return FALSE;
    memset(out, 0, sizeof(*out));
    out->buf_full = (b[14] & 0x01u) != 0;
    out->err = (b[14] & 0x0Eu) != 0;
    out->label_end = (b[14] & 0x04u) != 0;
    out->ribbon_end = (b[14] & 0x20u) != 0;
    out->low_battery = (b[14] & 0x40u) != 0;
    out->busy = (b[15] & 0x04u) != 0;
    out->head_hot = (b[15] & 0x08u) != 0;
    out->cover_open = (b[16] & 0x08u) != 0;
    out->printing = (b[16] & 0x40u) != 0;
    return TRUE;
}

static gboolean status_has_error(const E11Status *s)
{
    return s && (s->err || s->cover_open || s->low_battery || s->label_end || s->ribbon_end || s->head_hot);
}

static gboolean printer_status(E11Bluez *bz, E11Status *out, GError **error)
{
    GBytes *r = printer_cmd(bz, CMD_INQUIRY_STA, 0, 0, TRUE, error);
    if (!r) return FALSE;
    gboolean ok = parse_status(r, out);
    g_bytes_unref(r);
    if (!ok) g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid E11 status packet");
    return ok;
}

static gboolean printer_wait_ready(E11Bluez *bz, GError **error)
{
    for (int i = 0; i < 60; i++) {
        E11Status s;
        if (!printer_status(bz, &s, error)) return FALSE;
        if (status_has_error(&s)) {
            g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "E11 reported an error before printing");
            return FALSE;
        }
        if (!s.busy && !s.printing) return TRUE;
        g_usleep(100 * 1000);
    }
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "E11 is not ready");
    return FALSE;
}

static gboolean printer_wait_printing(E11Bluez *bz, GError **error)
{
    for (int i = 0; i < 60; i++) {
        E11Status s;
        if (!printer_status(bz, &s, error)) return FALSE;
        if (status_has_error(&s)) {
            g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "E11 reported an error while starting print");
            return FALSE;
        }
        if (s.printing) return TRUE;
        g_usleep(100 * 1000);
    }
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "E11 did not enter printing state");
    return FALSE;
}

static gboolean printer_wait_buffer(E11Bluez *bz, GError **error)
{
    for (int i = 0; i < 200; i++) {
        g_usleep(20 * 1000);
        E11Status s;
        if (!printer_status(bz, &s, error)) return FALSE;
        if (status_has_error(&s)) {
            g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "E11 reported a print buffer error");
            return FALSE;
        }
        if (!s.buf_full) return TRUE;
    }
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "E11 print buffer remained full");
    return FALSE;
}

static gboolean send_frame(E11Bluez *bz, const guint8 *frame, gsize len,
                           gboolean need_response, GError **error)
{
    for (gsize off = 0; off < len; off += BLE_CHUNK) {
        const gsize n = MIN((gsize)BLE_CHUNK, len - off);
        if (!bluez_write(bz, frame + off, n, error)) return FALSE;
    }
    if (need_response) {
        GBytes *r = bluez_wait_packet(bz, -1, 1000);
        if (r) g_bytes_unref(r); 
    }
    return !cancelled(bz->cancel, error);
}

static void build_frame(const guint8 *chunk, gsize chunk_len, guint8 index,
                        guint8 total, guint8 frame[512])
{
    memset(frame, 0, 512);
    frame[0] = 0x7E; frame[1] = 0x5A;
    put_le16(frame + 2, 508);
    frame[4] = 0x10; frame[5] = 0x02;
    guint8 *pkt = frame + 6;
    pkt[0] = 0xAA; pkt[1] = 0xBB;
    pkt[4] = index;
    pkt[5] = total;
    if (chunk_len > PAYLOAD) chunk_len = PAYLOAD;
    memcpy(pkt + 6, chunk, chunk_len);
    guint32 sum = 0;
    for (int i = 4; i < 506; i++) sum += pkt[i];
    put_le16(pkt + 2, (guint16)(sum & 0xFFFFu));
}

static gboolean printer_print(E11Bluez *bz, const GByteArray *comp,
                              guint16 raw_len, guint16 speed, GError **error)
{
    GBytes *r = printer_cmd(bz, CMD_CHECK_DEVICE, 0, 0, TRUE, error);
    if (!r) return FALSE;
    gsize rn = 0;
    const guint8 *rp = g_bytes_get_data(r, &rn);
    gboolean check_ok = rn >= 8 && rp[7] == CMD_CHECK_DEVICE;
    g_bytes_unref(r);
    if (!check_ok) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "E11 device check failed");
        return FALSE;
    }

    if (!printer_wait_ready(bz, error)) return FALSE;
    r = printer_cmd(bz, CMD_START_PRINT, 0, 0, TRUE, error);
    if (!r) return FALSE;
    g_bytes_unref(r);
    if (!printer_wait_printing(bz, error)) return FALSE;
    if (!printer_wait_buffer(bz, error)) return FALSE;

    const gsize total_sz = (comp->len + PAYLOAD - 1) / PAYLOAD;
    if (total_sz == 0 || total_sz > 255) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid E11 frame count");
        return FALSE;
    }
    const guint8 total = (guint8)total_sz;
    r = printer_cmd(bz, CMD_NEXT_ZIPPED, 512, total, TRUE, error);
    if (!r) return FALSE;
    g_bytes_unref(r);

    for (guint i = 0; i < total; i++) {
        const gsize off = (gsize)i * PAYLOAD;
        const gsize n = MIN((gsize)PAYLOAD, comp->len - off);
        guint8 frame[512];
        build_frame(comp->data + off, n, (guint8)i, total, frame);
        if (!send_frame(bz, frame, sizeof(frame), i + 1u != total, error)) return FALSE;
    }

    g_usleep(20 * 1000);
    r = printer_cmd(bz, CMD_BUF_FULL, raw_len, speed, TRUE, error);
    if (!r) return FALSE;
    g_bytes_unref(r);
    return TRUE;
}

static void print_params_free(E11PrintParams *p)
{
    if (!p) return;
    g_clear_pointer(&p->address, g_free);
    g_clear_pointer(&p->text, g_free);
    if (p->cancel) g_object_unref(p->cancel);
    g_free(p);
}

static void result_free(E11Result *r)
{
    if (!r) return;
    g_free(r->message);
    g_free(r->device_address);
    g_free(r);
}

static gboolean e11_complete_on_main(gpointer user_data)
{
    E11Result *result = user_data;
    GThread *thread = NULL;
    GCancellable *cancel = NULL;
    guint status_source = 0;

    g_mutex_lock(&g_job_mutex);
    g_job.completion_source = 0;
    status_source = g_job.status_source;
    g_job.status_source = 0;
    thread = g_job.thread;
    g_job.thread = NULL;
    cancel = g_job.cancel;
    g_job.cancel = NULL;
    g_mutex_unlock(&g_job_mutex);

    if (status_source) g_source_remove(status_source);
    if (thread) g_thread_join(thread);
    if (cancel) g_object_unref(cancel);

    if (result->success) {
        char *msg = result->device_address ? g_strdup_printf(
            tr("e11_done_addr", "E11: printing completed · %s"),
            result->device_address) : g_strdup(tr("e11_done", "E11: printing completed"));
        if (host_api_v4() && g_host->set_status)
            g_host->set_status(msg, 10000);
        else
            show_message("Katasymbol E11", msg);
        g_free(msg);
    } else {
        char *msg = g_strdup_printf("E11: %s", result->message ? result->message : "Unknown E11 error");
        if (host_api_v4() && g_host->set_status)
            g_host->set_status(msg, 15000);
        else
            show_message(tr("e11_error_title", "E11 error"), msg);
        g_free(msg);
    }
    return G_SOURCE_REMOVE;
}

static gpointer e11_worker(gpointer user_data)
{
    E11PrintParams *p = user_data;
    E11Result *result = g_new0(E11Result, 1);
    GError *error = NULL;
    GByteArray *comp = NULL;
    guint16 raw_len = 0;
    E11Bluez bz = {0};

    post_status(tr("e11_preparing", "E11: preparing label…"), 0);
    if (!prepare_label(p, &comp, &raw_len, &error)) goto done;
    if (cancelled(p->cancel, &error)) goto done;

    gboolean connected = FALSE;
    if (p->address && p->address[0]) {
        char *st = g_strdup_printf("E11: %s %s", tr("e11_connecting_to", "connecting to"), p->address);
        post_status(st, 0);
        g_free(st);
        connected = bluez_connect(&bz, p->address, p->cancel, &error);
        if (!connected && p->auto_detect && !g_cancellable_is_cancelled(p->cancel)) {
            bluez_cleanup(&bz);
            g_clear_error(&error);
        }
    }

    if (!connected && p->auto_detect) {
        post_status(tr("e11_searching", "E11: searching for printer…"), 0);
        char *detected = bluez_auto_detect_e11(p->cancel, &error);
        if (!detected) goto done;
        g_free(p->address);
        p->address = detected;
        if (!bluez_connect(&bz, p->address, p->cancel, &error)) goto done;
        connected = TRUE;
        
        save_settings(p->address, p->font_size, p->width_mm, p->length_mm,
                      p->density, p->speed, p->auto_detect);
    }

    if (!connected) {
        if (!error)
            g_set_error_literal(&error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                                "E11 printer is not connected");
        goto done;
    }
    post_status(tr("e11_printing", "E11: printing…"), 0);
    if (!printer_print(&bz, comp, raw_len, (guint16)p->speed, &error)) goto done;
    result->success = TRUE;
    result->device_address = g_strdup(p->address);

done:
    bluez_cleanup(&bz);
    if (comp) g_byte_array_unref(comp);
    if (!result->success) {
        result->message = g_strdup(error ? error->message : "Unknown E11 error");
    }
    g_clear_error(&error);
    print_params_free(p);

    g_mutex_lock(&g_job_mutex);
    if (!g_job.shutting_down) {
        g_job.completion_source = g_idle_add_full(G_PRIORITY_DEFAULT,
            e11_complete_on_main, result, (GDestroyNotify)result_free);
        result = NULL;
    }
    g_mutex_unlock(&g_job_mutex);
    if (result) result_free(result);
    return NULL;
}

static gboolean start_print_job(const char *address, const char *text,
                                int font_size, int width_mm, int length_mm,
                                int density, int speed, gboolean auto_detect,
                                char **error_message)
{
    if (error_message) *error_message = NULL;
    g_mutex_lock(&g_job_mutex);
    if (g_job.thread) {
        g_mutex_unlock(&g_job_mutex);
        if (error_message) *error_message = g_strdup(tr("e11_print_running", "A print job is already running."));
        return FALSE;
    }
    if (g_job.shutting_down) {
        g_mutex_unlock(&g_job_mutex);
        if (error_message) *error_message = g_strdup(tr("e11_shutting_down", "Plugin is shutting down."));
        return FALSE;
    }

    E11PrintParams *p = g_new0(E11PrintParams, 1);
    p->address = g_strdup(address);
    p->text = g_strdup(text);
    p->font_size = font_size;
    p->width_mm = width_mm;
    p->length_mm = length_mm;
    p->density = density;
    p->speed = speed;
    p->auto_detect = auto_detect;
    g_job.cancel = g_cancellable_new();
    p->cancel = g_object_ref(g_job.cancel);
    g_job.thread = g_thread_new("diskpass-e11", e11_worker, p);
    if (!g_job.thread) {
        g_clear_object(&g_job.cancel);
        print_params_free(p);
        g_mutex_unlock(&g_job_mutex);
        if (error_message) *error_message = g_strdup(tr("e11_thread_fail", "Could not create the E11 print worker."));
        return FALSE;
    }
    g_mutex_unlock(&g_job_mutex);
    post_status(tr("e11_job_started", "E11: print job started…"), 0);
    return TRUE;
}

static GtkWidget *make_labeled_spin(GtkGrid *grid, int row, const char *label,
                                    double min, double max, double step, double value)
{
    GtkWidget *l = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_grid_attach(grid, l, 0, row, 1, 1);
    GtkWidget *s = gtk_spin_button_new_with_range(min, max, step);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(s), value);
    gtk_widget_set_hexpand(s, TRUE);
    gtk_grid_attach(grid, s, 1, row, 1, 1);
    return s;
}

static void on_use_selected_label_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    GtkTextView *view = GTK_TEXT_VIEW(user_data);
    char *label = dup_selected_disk_label();
    if (!label || !label[0]) {
        show_message("Katasymbol E11", tr("e11_select_disk", "Select a disk/entry in DiskPass first."));
        g_free(label);
        return;
    }
    GtkTextBuffer *buf = gtk_text_view_get_buffer(view);
    gtk_text_buffer_set_text(buf, label, -1);
    g_free(label);
}

static void e11_action(gpointer user_data)
{
    gboolean disk_label_mode = GPOINTER_TO_INT(user_data) != 0;
    g_mutex_lock(&g_job_mutex);
    gboolean busy = g_job.thread != NULL;
    g_mutex_unlock(&g_job_mutex);
    if (busy) {
        show_message("Katasymbol E11",
            tr("e11_print_running", "A print job is already running."));
        return;
    }

    char *initial_label = NULL;
    if (disk_label_mode) {
        initial_label = dup_selected_disk_label();
        if (!initial_label || !initial_label[0]) {
            show_message("Katasymbol E11", tr("e11_select_disk", "Select a disk/entry in DiskPass first."));
            g_free(initial_label);
            return;
        }
    }

    E11Dialog d = {0};
    d.dialog = gtk_dialog_new_with_buttons(
        tr("e11_title", "Print with Katasymbol E11"),
        find_parent_window(), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        tr("cancel", "Cancel"), GTK_RESPONSE_CANCEL,
        tr("e11_print", "Print"), GTK_RESPONSE_OK,
        NULL);
    gtk_window_set_default_size(GTK_WINDOW(d.dialog), 580, 500);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(d.dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 14);
    gtk_box_set_spacing(GTK_BOX(content), 10);

    GtkWidget *hint = gtk_label_new(tr("e11_hint", "Native C E11 driver using BlueZ. The MAC can be detected automatically and is saved after successful discovery."));
    gtk_label_set_xalign(GTK_LABEL(hint), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(hint), TRUE);
    gtk_box_pack_start(GTK_BOX(content), hint, FALSE, FALSE, 0);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_box_pack_start(GTK_BOX(content), grid, FALSE, FALSE, 0);

    GtkWidget *mac_l = gtk_label_new(tr("e11_mac", "MAC address"));
    gtk_label_set_xalign(GTK_LABEL(mac_l), 0.0f);
    gtk_grid_attach(GTK_GRID(grid), mac_l, 0, 0, 1, 1);
    d.address = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(d.address), "A4:93:40:43:41:2B");
    gtk_widget_set_hexpand(d.address, TRUE);
    gtk_grid_attach(GTK_GRID(grid), d.address, 1, 0, 1, 1);

    d.auto_detect = gtk_check_button_new_with_label(tr("e11_auto_detect", "Automatically find E11 if the MAC is empty or the saved device is unavailable"));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d.auto_detect), TRUE);
    gtk_grid_attach(GTK_GRID(grid), d.auto_detect, 1, 1, 1, 1);

    d.font_size = make_labeled_spin(GTK_GRID(grid), 2, tr("e11_font_size", "Font size"), 6, 160, 1, 40);
    d.width_mm = make_labeled_spin(GTK_GRID(grid), 3, tr("e11_tape_width", "Tape width, mm"), 6, 24, 1, 12);
    d.length_mm = make_labeled_spin(GTK_GRID(grid), 4, tr("e11_label_length", "Label length, mm"), 10, 300, 1, 40);
    d.density = make_labeled_spin(GTK_GRID(grid), 5, tr("e11_density", "Density"), 0, 15, 1, 4);
    d.speed = make_labeled_spin(GTK_GRID(grid), 6, tr("e11_speed", "Speed"), 1, 100, 1, 20);

    GtkWidget *text_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *text_l = gtk_label_new(tr("e11_text", "Text"));
    gtk_label_set_xalign(GTK_LABEL(text_l), 0.0f);
    gtk_box_pack_start(GTK_BOX(text_row), text_l, TRUE, TRUE, 0);
    GtkWidget *use_label_btn = gtk_button_new_with_label(tr("e11_use_selected", "Use selected disk label"));
    gtk_box_pack_end(GTK_BOX(text_row), use_label_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(content), text_row, FALSE, FALSE, 0);

    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(sw, TRUE);
    d.text_view = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(d.text_view), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(sw), d.text_view);
    gtk_box_pack_start(GTK_BOX(content), sw, TRUE, TRUE, 0);
    g_signal_connect(use_label_btn, "clicked", G_CALLBACK(on_use_selected_label_clicked), d.text_view);

    load_settings(&d);
    if (initial_label) {
        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(d.text_view));
        gtk_text_buffer_set_text(buf, initial_label, -1);
    }
    gtk_widget_show_all(d.dialog);

    while (gtk_dialog_run(GTK_DIALOG(d.dialog)) == GTK_RESPONSE_OK) {
        const char *addr_in = gtk_entry_get_text(GTK_ENTRY(d.address));
        char mac[18];
        char *text = text_view_dup_text(GTK_TEXT_VIEW(d.text_view));
        if (text) g_strstrip(text);

        gboolean auto_detect = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d.auto_detect));
        gboolean have_mac = normalize_mac(addr_in, mac);
        if (!have_mac && !auto_detect) {
            show_message("Katasymbol E11", tr("e11_invalid_mac", "Invalid MAC address. Enter a MAC or enable automatic detection."));
            g_free(text);
            continue;
        }
        if (!text || !*text) {
            show_message("Katasymbol E11", tr("e11_enter_text", "Enter text to print."));
            g_free(text);
            continue;
        }
        if (strlen(text) > E11_TEXT_MAX) {
            show_message("Katasymbol E11", tr("e11_text_too_long", "Text is too long."));
            g_free(text);
            continue;
        }

        int font_size = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.font_size));
        int width_mm = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.width_mm));
        int length_mm = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.length_mm));
        int density = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.density));
        int speed = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.speed));

        char *err = NULL;
        if (!start_print_job(have_mac ? mac : NULL, text, font_size, width_mm, length_mm,
                             density, speed, auto_detect, &err)) {
            show_message(tr("e11_error_title", "E11 error"), err ? err : "Unknown error");
            g_free(err);
            g_free(text);
            continue;
        }

        save_settings(have_mac ? mac : NULL, font_size, width_mm, length_mm, density, speed, auto_detect);
        g_free(text);
        break;
    }

    const char *final_addr = gtk_entry_get_text(GTK_ENTRY(d.address));
    char final_mac[18];
    gboolean final_have_mac = normalize_mac(final_addr, final_mac);
    save_settings(final_have_mac ? final_mac : NULL,
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.font_size)),
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.width_mm)),
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.length_mm)),
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.density)),
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d.speed)),
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d.auto_detect)));

    gtk_widget_destroy(d.dialog);
    g_free(initial_label);
}

G_MODULE_EXPORT gboolean diskpass_plugin_init(
    const DiskPassPluginHost *host, DiskPassPluginInfo *info, GError **error)
{
    if (!host || host->abi_version != DISKPASS_PLUGIN_ABI_VERSION || !host->register_action) {
        g_set_error_literal(error, G_MODULE_ERROR, G_MODULE_ERROR_FAILED, "Unsupported DiskPass plugin ABI");
        return FALSE;
    }
    g_host = host;
    g_mutex_lock(&g_job_mutex);
    g_job.shutting_down = FALSE;
    g_mutex_unlock(&g_job_mutex);

    info->abi_version = DISKPASS_PLUGIN_ABI_VERSION;
    info->id = E11_PLUGIN_ID;
    info->name = "Katasymbol E11 Native C Printer";
    info->version = E11_PLUGIN_VERSION;

    if (!host_api_v4() || !host->dup_selected_disk_label) {
        g_set_error_literal(error, G_MODULE_ERROR, G_MODULE_ERROR_FAILED,
            "DiskPass Plugin API v4 with selected disk label support is required");
        g_host = NULL;
        return FALSE;
    }

    const char *disk_label = tr("e11_action_disk_label", "Print selected disk label");
    if (!host->register_action("print-disk-label", disk_label, e11_action, GINT_TO_POINTER(1), NULL)) {
        g_set_error_literal(error, G_MODULE_ERROR, G_MODULE_ERROR_FAILED, "Cannot register disk-label print action");
        g_host = NULL;
        return FALSE;
    }
    return TRUE;
}

G_MODULE_EXPORT void diskpass_plugin_shutdown(void)
{
    GThread *thread = NULL;
    GCancellable *cancel = NULL;
    guint source = 0;
    guint status_source = 0;

    g_mutex_lock(&g_job_mutex);
    g_job.shutting_down = TRUE;
    source = g_job.completion_source;
    g_job.completion_source = 0;
    status_source = g_job.status_source;
    g_job.status_source = 0;
    thread = g_job.thread;
    g_job.thread = NULL;
    cancel = g_job.cancel;
    g_job.cancel = NULL;
    if (cancel) g_object_ref(cancel);
    g_mutex_unlock(&g_job_mutex);

    if (source) g_source_remove(source);
    if (status_source) g_source_remove(status_source);
    if (cancel) g_cancellable_cancel(cancel);
    if (thread) g_thread_join(thread);
    if (cancel) {
        g_object_unref(cancel); 
        g_object_unref(cancel); 
    }
    if (host_api_v4() && g_host->set_status) g_host->set_status(NULL, 0);
    g_host = NULL;
}
