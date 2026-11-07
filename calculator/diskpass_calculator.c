/* SPDX-License-Identifier: GPL-3.0-or-later
 * Полное окно в стиле GNOME Calculator: режимы Базовый, Расширенный,
 * Финансовый, Программирование, Клавиатурный и Конвертация (тёмная тема). */
#include "calculator-widget.h"
#include "calc-eval.h"
#include "calc-units.h"
#include "diskpass_calculator.h"
#include "diskpass_icon.h"
#include <sodium.h>
#include <math.h>
#include <string.h>

/* Calculator UI and math engine are copied from the user-provided GPLv3 source.
 * These additions handle DiskPass's local numeric access code only. */
static gboolean g_calc_unlocked;
static const char *g_calc_unlock_hash;
static const unsigned char *g_calc_salt;
static unsigned char *g_calc_out_key;
static guint g_calc_failed_attempts;
static gint64 g_calc_next_allowed_us;
static gint64 g_calc_retry_after;
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

typedef struct {
    GtkWidget *window, *header, *mode_btn, *empty_title, *undo, *redo, *more;
    GtkWidget *display_box, *scroller, *history_box, *expr, *bits_panel, *bits_lbl[2][8];
    GtkWidget *stack, *panels[M_COUNT], *conv_view;
    GtkWidget *mode_items[M_COUNT], *mode_label;
    GtkWidget *vars_pop, *funcs_pop, *base_pop, *bits_pop;
    GString *text;
    GPtrArray *states;           /* снимки текста для undo/redo */
    guint idx;
    double complex ans;
    CalcSettings cfg;
    Mode mode;
    /* конвертер */
    GtkWidget *cv_cat, *cv_u1, *cv_u2, *cv_val1, *cv_val2, *cv_cat_l, *cv_u1_l, *cv_u2_l;
    guint cat, from, to;
    GString *cin;
} App;

/* Keep the calculator session alive across ordinary GTK event iterations.
 * In particular, opening it from Settings must not enter a nested gtk_main(). */
typedef struct {
    App app;
    GtkSettings *settings;
    gboolean previous_dark;
    gchar *previous_decorations;
    GtkCssProvider *css;
    DiskpassCalculatorFinished on_finished;
    gpointer finished_data;
    gboolean asynchronous;
} CalcSession;

static gboolean g_calc_active;

static void calculator_session_destroy(GtkWidget *window, gpointer user_data);
static gboolean calculator_finish_async(gpointer user_data);

/* ---------- панели ---------- */
static GtkWidget *panel_of(App *a)
{
    return a->panels[a->mode == M_KBD ? M_BASIC : a->mode];
}

/* ---------- состояние / undo / биты ---------- */
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
    if (!a->idx) return;
    g_string_assign(a->text, g_ptr_array_index(a->states, --a->idx));
    sync_ui(a);
}
static void on_redo(GtkButton *b, App *a)
{
    (void)b;
    if (a->idx + 1 >= a->states->len) return;
    g_string_assign(a->text, g_ptr_array_index(a->states, ++a->idx));
    sync_ui(a);
}

/* ---------- история ---------- */
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

/* ---------- выбор из списка (поповеры) ---------- */
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
/* items — подписи; values — значения, передаваемые в on_choice */
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

/* ---------- вычисления ---------- */
static void insert_text(App *a, const char *t) {
    if (!a || !a->text || !t) return;
    gsize n = strlen(t);
    if (n > 65536 || a->text->len > 65536 - n) return;
    g_string_append(a->text, t);
    commit(a);
}

static void backspace(App *a)
{
    if (!a->text->len) return;
    if (g_str_has_suffix(a->text->str, " mod ")) g_string_truncate(a->text, a->text->len - 5);
    else g_string_truncate(a->text, g_utf8_prev_char(a->text->str + a->text->len) - a->text->str);
    commit(a);
}
static void solve(App *a)
{
    double complex v;
    if (!a->text->len) return;

    /* A long decimal number followed by '=' can be the access code.
     * Normal expressions are always evaluated by the original calculator.
     * Do not add a code-shaped number to the visible calculation history. */
    gboolean code_shaped = a->mode == M_BASIC && a->text->len >= 8 &&
        a->text->len <= 32 && g_calc_unlock_hash && *g_calc_unlock_hash;
    if (code_shaped) {
        for (gsize i = 0; i < a->text->len; ++i) {
            if (!g_ascii_isdigit(a->text->str[i])) { code_shaped = FALSE; break; }
        }
    }
    gint64 now_us = g_get_monotonic_time();
    if (code_shaped) {
        if (now_us < g_calc_retry_after || now_us < g_calc_next_allowed_us) {
            sodium_memzero(a->text->str, a->text->allocated_len);
            g_string_truncate(a->text, 0);
            commit(a);
            return;
        }
        if (crypto_pwhash_str_verify(g_calc_unlock_hash, a->text->str,
                                    (unsigned long long)a->text->len) == 0) {
            /* A separate key is derived for authenticated encryption of
             * preferences; the numeric code is never written to disk. */
            if (!g_calc_salt || !g_calc_out_key ||
                crypto_pwhash(g_calc_out_key,
                    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                    a->text->str, (unsigned long long)a->text->len,
                    g_calc_salt, crypto_pwhash_OPSLIMIT_MODERATE,
                    crypto_pwhash_MEMLIMIT_MODERATE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
                g_warning("DiskPass: could not derive protected configuration key");
                return;
            }
            g_calc_unlocked = TRUE;
            sodium_memzero(a->text->str, a->text->allocated_len);
            gtk_widget_destroy(a->window);
            return;
        }
        if (++g_calc_failed_attempts >= 5) {
            g_calc_failed_attempts = 0;
            g_calc_retry_after = now_us + 30 * G_USEC_PER_SEC;
            g_calc_next_allowed_us = g_calc_retry_after;
        } else {
            /* Slow each guess slightly, then apply a longer cooldown in
             * batches. This is a local throttle, not a defense against a
             * user who can restart or patch the process. */
            g_calc_next_allowed_us = now_us + G_USEC_PER_SEC;
        }
        /* Do not evaluate a failed access-code attempt as a calculator
         * expression: keep the code out of history/results and clear it. */
        sodium_memzero(a->text->str, a->text->allocated_len);
        g_string_truncate(a->text, 0);
        commit(a);
        return;
    }
    GString *e = g_string_new(a->text->str);
    gint open = 0;
    for (const char *p = e->str; *p; p++) open += (*p == '(') - (*p == ')');
    gchar *shown = g_strdup(e->str);
    while (open-- > 0) g_string_append_c(e, ')');
    if (calc_eval_full(&a->cfg, e->str, a->ans, &v)) {
        gchar *res = calc_format_full(&a->cfg, v);
        if (!code_shaped) add_history(a, shown, res);
        a->ans = v;
        g_string_assign(a->text, res);
        g_free(res);
    } else if (!code_shaped) add_history(a, shown, "Ошибка");
    commit(a);
    g_free(shown);
    g_string_free(e, TRUE);
}
static void set_base(App *a, gint base)
{
    double complex v;
    gboolean ok = a->text->len && calc_eval_full(&a->cfg, a->text->str, a->ans, &v);
    a->cfg.base = base;
    for (guint i = 0; i < G_N_ELEMENTS(BASES); i++)
        if (BASES[i].v == base) calculator_widget_set_button_label(CALCULATOR_WIDGET(a->panels[M_PROG]), "cal.show-base", BASES[i].label);
    calculator_widget_set_base(CALCULATOR_WIDGET(a->panels[M_PROG]), base);
    if (ok) { gchar *t = calc_format_full(&a->cfg, v); g_string_assign(a->text, t); g_free(t); }
    else g_string_truncate(a->text, 0);
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
    /* cal.set-inverse, cal.set-number-mode, cal.insert-character: состояние хранит сама панель */
}

/* ---------- конвертер ---------- */
static void set_menu_label(GtkWidget *label, const char *text) {
    if (GTK_IS_LABEL(label) && text) gtk_label_set_text(GTK_LABEL(label), text);
}
static void conv_refresh(App *a)
{
    char *end = NULL;
    double v = g_ascii_strtod(a->cin->len ? a->cin->str : "0", &end);
    if (!end || *end != '\0' || !isfinite(v)) v = NAN;
    double r = calc_units_convert(a->cat, a->from, a->to, v);
    gchar *out = isfinite(r) ? calc_format(r) : g_strdup("Ошибка");
    gchar *in = g_strdup(a->cin->len ? a->cin->str : "0");
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

/* ---------- режимы ---------- */
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
static void apply_mode(App *a, Mode m)
{
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
}

/* ---------- клавиатура ---------- */
static gboolean on_key(GtkWidget *w, GdkEventKey *e, App *a)
{
    (void)w;
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

/* ---------- меню x и f(x) ---------- */
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

/* ---------- шапка ---------- */
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
/* «⋯» рисуем сами: иконка view-more в разных темах то горизонтальная, то вертикальная */
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
    if (g_calc_active || !unlock_hash || !*unlock_hash || !salt || !out_key) return NULL;
    CalcSession *session = g_new0(CalcSession, 1);
    App *a = &session->app;
    session->asynchronous = asynchronous;
    session->on_finished = finished;
    session->finished_data = user_data;
    g_calc_active = TRUE;
    g_calc_unlock_hash = unlock_hash;
    g_calc_salt = salt;
    g_calc_out_key = out_key;
    g_calc_unlocked = FALSE;
    g_calc_failed_attempts = 0;
    g_calc_retry_after = 0;
    g_calc_next_allowed_us = 0;
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
    a->text = g_string_new("");
    a->cin = g_string_new("");
    a->cfg = (CalcSettings)CALC_SETTINGS_DEFAULT;
    a->states = g_ptr_array_new_with_free_func(g_free);
    g_ptr_array_add(a->states, g_strdup(""));

    /* Only the calculator window receives the calculator icon.
     * Never change GTK's process-wide default icon. */
    a->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_style_context_add_class(gtk_widget_get_style_context(a->window), "calc");
    gtk_window_set_title(GTK_WINDOW(a->window), "Калькулятор");
    gtk_window_set_icon_name(GTK_WINDOW(a->window), diskpass_calculator_icon_name());
    gtk_window_set_default_size(GTK_WINDOW(a->window), 360, 569);

    /* --- заголовок --- */
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

    /* --- содержимое --- */
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

    a->vars_pop = make_item_popover(a, vars_items, G_N_ELEMENTS(vars_items), 5);
    a->funcs_pop = make_item_popover(a, funcs_items, G_N_ELEMENTS(funcs_items), 4);
    {
        const char *bl[G_N_ELEMENTS(BASES)]; gint bv[G_N_ELEMENTS(BASES)];
        for (guint i = 0; i < G_N_ELEMENTS(BASES); i++) { bl[i] = BASES[i].label; bv[i] = BASES[i].v; }
        a->base_pop = choice_popover(a, CH_BASE, bl, bv, G_N_ELEMENTS(BASES), NULL);
        const char *wl[G_N_ELEMENTS(WORDS)]; gint wv[G_N_ELEMENTS(WORDS)];
        for (guint i = 0; i < G_N_ELEMENTS(WORDS); i++) { wl[i] = WORDS[i].label; wv[i] = WORDS[i].v; }
        a->bits_pop = choice_popover(a, CH_BITS, wl, wv, G_N_ELEMENTS(WORDS), NULL);
    }
    g_signal_connect(a->window, "key-press-event", G_CALLBACK(on_key), a);
    g_signal_connect(a->window, "destroy", G_CALLBACK(calculator_session_destroy), session);
    gtk_widget_show_all(a->window);
    apply_mode(a, M_BASIC);
#ifdef CALC_DEBUG_MODE
    apply_mode(a, CALC_DEBUG_MODE);
#endif
#ifdef CALC_SCRIPT
    { const char *s = CALC_SCRIPT; for (; *s; s++) { char t[2] = { *s, 0 }; if (*s == '=') do_action(a, "cal.solve", ""); else if (*s == '+') do_action(a, "cal.insert-general", "+"); else do_action(a, "cal.insert-digit", t); } }
#endif
    return session;
}

/* Called from the widget's destroy signal. Defer freeing session state until
 * the activation callback that destroyed the widget has fully unwound. */
static void calculator_session_destroy(GtkWidget *window, gpointer user_data)
{
    (void)window;
    CalcSession *session = user_data;
    if (session->asynchronous)
        g_idle_add(calculator_finish_async, session);
    else
        gtk_main_quit();
}

static void calculator_session_free(CalcSession *session)
{
    App *a = &session->app;
    /* Erase the entered code and any undo snapshots. */
    sodium_memzero(a->text->str, a->text->allocated_len);
    g_string_free(a->text, TRUE);
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
    g_calc_unlock_hash = NULL;
    g_calc_salt = NULL;
    g_calc_out_key = NULL;
    g_calc_active = FALSE;
    g_free(session);
}

static gboolean calculator_finish_async(gpointer user_data)
{
    CalcSession *session = user_data;
    gboolean unlocked = g_calc_unlocked;
    DiskpassCalculatorFinished finished = session->on_finished;
    gpointer data = session->finished_data;
    calculator_session_free(session);
    /* No calculator frame is active while the parent window is restored. */
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
    gboolean unlocked = g_calc_unlocked;
    calculator_session_free(session);
    return unlocked;
}
