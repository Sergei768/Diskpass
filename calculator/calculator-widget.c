/* SPDX-License-Identifier: GPL-3.0-or-later
 * Handwritten GTK3 adaptation of GNOME Calculator keypads
 * (basic, advanced, financial, programming, conversion).
 */
#include "calculator-widget.h"
#include "calculator-css.h"
#include <string.h>

struct _CalculatorWidget {
    GtkBox parent_instance;
    GtkWidget *sup, *sub, *inverse_button;
    gboolean updating, inverse;
    const gchar *mode;
    GList *buttons;
};
G_DEFINE_TYPE(CalculatorWidget, calculator_widget, GTK_TYPE_BOX)
static guint action_signal;

typedef enum { K_NORMAL, K_SUP, K_SUB, K_MENU, K_INVERSE, K_ICON } KeyKind;
typedef struct {
    const gchar *label, *action, *target, *style, *tip;
    gint col, row, w, h, parent;
    KeyKind kind;
    const gchar *alt_label, *alt_action, *alt_target;
} Key;

#define KEYN(l, a, t, s, tip, c, r, w, h, p, k, ...) { l, a, t, s, tip, c, r, w, h, p, k, __VA_ARGS__ }
#define PLAIN(l, a, t, s, tip, c, r) KEYN(l, a, t, s, tip, c, r, 1, 1, 0, K_NORMAL, NULL, NULL, NULL)
#define DIG(d, c, r, p) KEYN(d, "cal.insert-digit", d, "number-button", d, c, r, 1, 1, p, K_NORMAL, NULL, NULL, NULL)
#define FUNC(l, t, tip, c, r) KEYN(l, "cal.insert-function", t, "function-button", tip, c, r, 1, 1, 0, K_NORMAL, NULL, NULL, NULL)
#define FUNCI(l, t, tip, c, r, al, at) KEYN(l, "cal.insert-function", t, "function-button", tip, c, r, 1, 1, 0, K_NORMAL, al, NULL, at)
#define INV KEYN("⇧<sup>−1</sup>", "cal.set-inverse", "", "inverse-button", "Inverse functions", 0, 0, 1, 1, 0, K_INVERSE, NULL, NULL, NULL)

 
static const Key rb_top[] = {
    PLAIN("C", "cal.clear", "", "clear-button", "Clear", 0, 0),
    KEYN("↑n", "cal.set-number-mode", "superscript", "function-button", "Superscript mode", 1, 0, 1, 1, 0, K_SUP, NULL, NULL, NULL),
    KEYN("↓n", "cal.set-number-mode", "subscript", "function-button", "Subscript mode", 2, 0, 1, 1, 0, K_SUB, NULL, NULL, NULL),
    PLAIN("÷", "cal.insert-general", "÷", "operator-button", "Divide", 3, 0),
    PLAIN("mod", "cal.insert-alpha", "mod", "function-button", "Modulus divide", 4, 0),
};
static const Key rb_digits[] = {
    DIG("7", 0, 1, 0), DIG("8", 1, 1, 0), DIG("9", 2, 1, 0),
    DIG("4", 0, 2, 0), DIG("5", 1, 2, 0), DIG("6", 2, 2, 0),
    DIG("1", 0, 3, 0), DIG("2", 1, 3, 0), DIG("3", 2, 3, 0),
};
static const Key rb_ops[] = {
    PLAIN("×", "cal.insert-general", "×", "operator-button", "Multiply", 3, 1),
    PLAIN("%", "cal.insert-general", "%", "percent-button", "Percentage", 4, 1),
    PLAIN("−", "cal.subtract", "", "operator-button", "Subtract", 3, 2),
    PLAIN("\u200e( )", "cal.insert-brackets", "()", "parenthesis-button", "Group", 4, 2),
    PLAIN("+", "cal.insert-general", "+", "operator-button", "Add", 3, 3),
    KEYN("=", "cal.solve", "", "suggested-action", "Calculate result", 4, 3, 1, 2, 0, K_NORMAL, NULL, NULL, NULL),
};
static const Key rb_bottom[] = {
    DIG("0", 0, 4, 0),
    PLAIN(",", "cal.insert-numeric-point", "", "numeric-point-button", "Decimal point", 1, 4),
    KEYN("x", "cal.show-variables", "", "function-button", "Variables and constants", 2, 4, 1, 1, 0, K_MENU, NULL, NULL, NULL),
    KEYN("f(x)", "cal.show-functions", "", "function-button", "Additional functions", 3, 4, 1, 1, 0, K_MENU, NULL, NULL, NULL),
};
 
static const Key prog_digits[] = {
    DIG("B", 0, 0, 1), DIG("C", 1, 0, 1), DIG("D", 2, 0, 1), DIG("E", 3, 0, 1), DIG("F", 4, 0, 1),
    DIG("6", 0, 1, 1), DIG("7", 1, 1, 1), DIG("8", 2, 1, 1), DIG("9", 3, 1, 1), DIG("A", 4, 1, 1),
    DIG("1", 0, 2, 1), DIG("2", 1, 2, 1), DIG("3", 2, 2, 1), DIG("4", 3, 2, 1), DIG("5", 4, 2, 1),
};

 
#define X2 "<i>x</i><sup>2</sup>"
#define XY "<i>x</i><sup><i>y</i></sup>"
static const Key adv_left[] = {
    INV,
    FUNCI(X2, "²", "Square", 1, 0, "√<i>x</i>", "√"),
    FUNCI(XY, "^", "Power", 2, 0, "<sup><i>y</i></sup>√<i>x</i>", "root("),
    FUNC("conj", "conj(", "Complex conjugate", 3, 0),
    FUNC("<i>x</i><sup>−1</sup>", "⁻¹", "Reciprocal", 4, 0),
    FUNCI("sin", "sin(", "Sine", 0, 1, "sin<sup>−1</sup>", "asin("),
    FUNCI("sinh", "sinh(", "Hyperbolic sine", 1, 1, "sinh<sup>−1</sup>", "asinh("),
    FUNC("log<sub><i>y</i></sub>", "logb(", "Logarithm to base y", 2, 1),
    FUNC("Arg", "arg(", "Argument", 3, 1),
    FUNC("[<i>x</i>]", "round(", "Round", 4, 1),
    FUNCI("cos", "cos(", "Cosine", 0, 2, "cos<sup>−1</sup>", "acos("),
    FUNCI("cosh", "cosh(", "Hyperbolic cosine", 1, 2, "cosh<sup>−1</sup>", "acosh("),
    FUNCI("log", "log(", "Logarithm", 2, 2, "10<sup><i>x</i></sup>", "10^"),
    FUNC("Re", "re(", "Real part", 3, 2),
    FUNC("|<i>x</i>|", "abs(", "Absolute value", 4, 2),
    FUNCI("tan", "tan(", "Tangent", 0, 3, "tan<sup>−1</sup>", "atan("),
    FUNCI("tanh", "tanh(", "Hyperbolic tangent", 1, 3, "tanh<sup>−1</sup>", "atanh("),
    FUNCI("ln", "ln(", "Natural logarithm", 2, 3, "e<sup><i>x</i></sup>", "exp("),
    FUNC("Im", "im(", "Imaginary part", 3, 3),
    FUNC("<i>x</i>!", "!", "Factorial", 4, 3),
    PLAIN("Deg", "cal.cycle-angle", "", "function-button", "Angle unit", 0, 4),
    FUNC("π", "π", "Pi", 1, 4), FUNC("e", "e", "Euler's number", 2, 4), FUNC("i", "i", "Imaginary unit", 3, 4),
    FUNC("<i>a</i>×<i>b</i>", "×", "Multiplication", 4, 4),
};
static const Key fin_top[] = {
    INV,
    FUNCI(X2, "²", "Square", 1, 0, "√<i>x</i>", "√"),
    FUNCI(XY, "^", "Power", 2, 0, "<sup><i>y</i></sup>√<i>x</i>", "root("),
    FUNCI("log", "log(", "Logarithm", 3, 0, "10<sup><i>x</i></sup>", "10^"),
    FUNCI("ln", "ln(", "Natural logarithm", 4, 0, "e<sup><i>x</i></sup>", "exp("),
};
 
#define FIN(l, t, tip, c, r) KEYN(l, "cal.insert-function", t, "function-button", tip, c, r, 1, 1, 1, K_NORMAL, NULL, NULL, NULL)
static const Key fin_funcs[] = {
    FIN("Ctrm", "ctrm(", "Compounding term", 0, 0), FIN("Ddb", "ddb(", "Double declining depreciation", 1, 0), FIN("Fv", "fv(", "Future value", 2, 0),
    FIN("Gpm", "gpm(", "Gross profit margin", 0, 1), FIN("Pmt", "pmt(", "Periodic payment", 1, 1), FIN("Pv", "pv(", "Present value", 2, 1),
    FIN("Rate", "rate(", "Rate per period", 0, 2), FIN("Sln", "sln(", "Straight-line depreciation", 1, 2), FIN("Syd", "syd(", "Sum-of-years depreciation", 2, 2),
    FIN("Term", "term(", "Payment period", 0, 3),
    KEYN("Конвертация валют", "cal.convert-currency", "", "function-button", "Currency conversion", 1, 3, 2, 1, 1, K_NORMAL, NULL, NULL, NULL),
};
static const Key prog_left[] = {
    INV,
    FUNCI(X2, "²", "Square", 1, 0, "√<i>x</i>", "√"),
    FUNCI(XY, "^", "Power", 2, 0, "<sup><i>y</i></sup>√<i>x</i>", "root("),
    FUNC("twos", "twos(", "Two's complement", 3, 0),
    FUNC("⌈<i>x</i>⌉", "ceil(", "Ceiling", 4, 0),
    FUNC("∧", "∧", "Bitwise AND", 0, 1), FUNC("∨", "∨", "Bitwise OR", 1, 1),
    FUNC("log<sub><i>y</i></sub>", "logb(", "Logarithm to base y", 2, 1),
    FUNC("swap", "swap(", "Swap bytes", 3, 1),
    FUNC("⌊<i>x</i>⌋", "floor(", "Floor", 4, 1),
    FUNC("¬", "¬", "Bitwise NOT", 0, 2), FUNC("⊻", "⊻", "Bitwise XOR", 1, 2),
    FUNCI("log", "log(", "Logarithm", 2, 2, "10<sup><i>x</i></sup>", "10^"),
    FUNC("int", "int(", "Integer part", 3, 2),
    FUNC("|<i>x</i>|", "abs(", "Absolute value", 4, 2),
    FUNC("«", "«", "Shift left", 0, 3), FUNC("»", "»", "Shift right", 1, 3),
    FUNC("log<sub>2</sub>", "log2(", "Logarithm to base 2", 2, 3),
    FUNC("frac", "frac(", "Fractional part", 3, 3),
    FUNC("<i>x</i>!", "!", "Factorial", 4, 3),
    KEYN("Десятичный", "cal.show-base", "", "function-button", "Number base", 0, 4, 2, 1, 0, K_MENU, NULL, NULL, NULL),
    KEYN("64-бита", "cal.show-bits", "", "function-button", "Word size", 2, 4, 2, 1, 0, K_MENU, NULL, NULL, NULL),
    PLAIN("á", "cal.insert-character", "", "function-button", "Insert character", 4, 4),
};
 
static const Key conv_keys[] = {
    PLAIN("C", "cal.clear", "", "clear-button", "Clear", 0, 0),
    PLAIN("⇅", "cal.swap-units", "", "function-button", "Swap units", 1, 0),
    KEYN("edit-clear-symbolic", "cal.backspace", "", "function-button", "Backspace", 2, 0, 1, 1, 0, K_ICON, NULL, NULL, NULL),
    DIG("7", 0, 1, 0), DIG("8", 1, 1, 0), DIG("9", 2, 1, 0),
    DIG("4", 0, 2, 0), DIG("5", 1, 2, 0), DIG("6", 2, 2, 0),
    DIG("1", 0, 3, 0), DIG("2", 1, 3, 0), DIG("3", 2, 3, 0),
    DIG("0", 0, 4, 0),
    PLAIN(",", "cal.insert-numeric-point", "", "numeric-point-button", "Decimal point", 1, 4),
    PLAIN("°′″", "cal.insert-degrees", "", "function-button", "Degrees, minutes, seconds", 2, 4),
};

 
static void set_label_text(GtkWidget *label, const gchar *text)
{
    if (!text) text = "";
    if (strchr(text, '<')) gtk_label_set_markup(GTK_LABEL(label), text);
    else gtk_label_set_text(GTK_LABEL(label), text);
}

static void update_inverse_labels(CalculatorWidget *self)
{
    for (GList *l = self->buttons; l; l = l->next) {
        const Key *k = g_object_get_data(G_OBJECT(l->data), "calculator-key");
        GtkWidget *label = g_object_get_data(G_OBJECT(l->data), "key-label");
        if (k->alt_label && label) set_label_text(label, self->inverse ? k->alt_label : k->label);
    }
}

static void clicked(GtkButton *button, CalculatorWidget *self)
{
    const Key *key = g_object_get_data(G_OBJECT(button), "calculator-key");
    const gchar *action = key->action, *target = key->target;
    if (self->updating) return;
    if (key->kind == K_SUP || key->kind == K_SUB) {
        gboolean active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button));
        self->updating = TRUE;
        if (active) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(key->kind == K_SUP ? self->sub : self->sup), FALSE);
        self->mode = active ? key->target : "normal";
        target = self->mode;
        self->updating = FALSE;
    } else if (key->kind == K_INVERSE) {
        self->inverse = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button));
        update_inverse_labels(self);
        target = self->inverse ? "true" : "false";
    } else if (self->inverse && key->alt_label) {
        if (key->alt_action) action = key->alt_action;
        target = key->alt_target;
    }
    g_signal_emit(self, action_signal, 0, action, target);
}

static void calculator_widget_finalize(GObject *object)
{
    CalculatorWidget *self = CALCULATOR_WIDGET(object);
    g_clear_pointer(&self->buttons, g_list_free);
    G_OBJECT_CLASS(calculator_widget_parent_class)->finalize(object);
}

static void calculator_widget_class_init(CalculatorWidgetClass *klass)
{
    G_OBJECT_CLASS(klass)->finalize = calculator_widget_finalize;
    action_signal = g_signal_new("action", G_TYPE_FROM_CLASS(klass), G_SIGNAL_RUN_LAST,
        0, NULL, NULL, NULL, G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
}

static void add_keys(CalculatorWidget *self, GtkWidget **grids, GtkCssProvider *css, const Key *keys, guint n, gint col_off)
{
    for (guint i = 0; i < n; i++) {
        const Key *key = &keys[i];
        GtkWidget *b, *label = NULL;
        gboolean toggle = key->kind == K_SUP || key->kind == K_SUB || key->kind == K_INVERSE;
        gboolean markup = key->label && strchr(key->label, '<');
        if (key->kind == K_ICON) {
            b = gtk_button_new_from_icon_name(key->label, GTK_ICON_SIZE_BUTTON);
        } else if (key->kind == K_MENU) {
            GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
            GtkWidget *arrow = gtk_image_new_from_icon_name("pan-down-symbolic", GTK_ICON_SIZE_BUTTON);
            b = gtk_button_new();
            label = gtk_label_new(NULL);
            set_label_text(label, key->label);
            gtk_box_pack_start(GTK_BOX(box), label, TRUE, TRUE, 0);
            gtk_box_pack_end(GTK_BOX(box), arrow, FALSE, FALSE, 0);
            gtk_container_add(GTK_CONTAINER(b), box);
        } else if (markup) {
            b = toggle ? gtk_toggle_button_new() : gtk_button_new();
            label = gtk_label_new(NULL);
            set_label_text(label, key->label);
            gtk_container_add(GTK_CONTAINER(b), label);
        } else {
            b = toggle ? gtk_toggle_button_new_with_label(key->label) : gtk_button_new_with_label(key->label);
            label = gtk_bin_get_child(GTK_BIN(b));
        }
        if (key->kind == K_SUP) self->sup = b;
        if (key->kind == K_SUB) self->sub = b;
        if (key->kind == K_INVERSE) self->inverse_button = b;
        gtk_widget_set_focus_on_click(b, FALSE);
        gtk_widget_set_tooltip_text(b, key->tip);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), key->style);
         
        gtk_style_context_add_provider(gtk_widget_get_style_context(b), GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
        g_object_set_data(G_OBJECT(b), "calculator-key", (gpointer)key);
        if (label) g_object_set_data(G_OBJECT(b), "key-label", label);
        g_signal_connect_object(b, toggle ? "toggled" : "clicked", G_CALLBACK(clicked), self, 0);
        gtk_grid_attach(GTK_GRID(grids[key->parent]), b, key->col + (key->parent ? 0 : col_off), key->row, key->w, key->h);
        self->buttons = g_list_prepend(self->buttons, b);
    }
}

static GtkWidget *new_grid(gint w, gint h)
{
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 4);
    gtk_widget_set_hexpand(grid, TRUE);
    gtk_widget_set_vexpand(grid, FALSE);
    if (w > 0) gtk_widget_set_size_request(grid, w, h);
    return grid;
}

static void calculator_widget_init(CalculatorWidget *self)
{
    self->mode = "normal";
    gtk_orientable_set_orientation(GTK_ORIENTABLE(self), GTK_ORIENTATION_VERTICAL);
    gtk_style_context_add_class(gtk_widget_get_style_context(GTK_WIDGET(self)), "embedded-calculator");
    gtk_container_set_border_width(GTK_CONTAINER(self), 12);
}

#define ADD(keys, off) add_keys(self, grids, css, keys, G_N_ELEMENTS(keys), off)

static void build(CalculatorWidget *self, const gchar *mode)
{
    GtkCssProvider *css = gtk_css_provider_new();
    GtkWidget *grids[2] = { NULL, NULL };
    gtk_css_provider_load_from_data(css, calculator_css, -1, NULL);
    gtk_style_context_add_provider(gtk_widget_get_style_context(GTK_WIDGET(self)), GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    if (!g_strcmp0(mode, "conversion")) {
        grids[0] = new_grid(336, 236);
        ADD(conv_keys, 0);
    } else if (!g_strcmp0(mode, "advanced")) {
        grids[0] = new_grid(676, 236);
        ADD(adv_left, 0); ADD(rb_top, 5); ADD(rb_digits, 5); ADD(rb_ops, 5); ADD(rb_bottom, 5);
    } else if (!g_strcmp0(mode, "financial")) {
        grids[0] = new_grid(676, 236);
        grids[1] = new_grid(-1, -1);
        gtk_grid_attach(GTK_GRID(grids[0]), grids[1], 0, 1, 5, 4);
        ADD(fin_top, 0); ADD(fin_funcs, 0);
        ADD(rb_top, 5); ADD(rb_digits, 5); ADD(rb_ops, 5); ADD(rb_bottom, 5);
    } else if (!g_strcmp0(mode, "programming")) {
        grids[0] = new_grid(676, 236);
        grids[1] = new_grid(-1, -1);
        gtk_grid_attach(GTK_GRID(grids[0]), grids[1], 5, 1, 3, 3);
        ADD(prog_left, 0); ADD(prog_digits, 0);
        ADD(rb_top, 5); ADD(rb_ops, 5); ADD(rb_bottom, 5);
    } else {
        grids[0] = new_grid(336, 236);
        ADD(rb_top, 0); ADD(rb_digits, 0); ADD(rb_ops, 0); ADD(rb_bottom, 0);
    }
    g_object_unref(css);
    gtk_box_pack_start(GTK_BOX(self), grids[0], TRUE, TRUE, 0);
    gtk_widget_show_all(grids[0]);
    calculator_widget_set_base(self, 10);
}

GtkWidget *calculator_widget_new_for_mode(const gchar *mode)
{
    CalculatorWidget *self = g_object_new(CALCULATOR_TYPE_WIDGET, NULL);
    build(self, mode);
    return GTK_WIDGET(self);
}
GtkWidget *calculator_widget_new(void) { return calculator_widget_new_for_mode("basic"); }

const gchar *calculator_widget_get_number_mode(CalculatorWidget *self)
{
    g_return_val_if_fail(CALCULATOR_IS_WIDGET(self), NULL);
    return self->mode;
}
gboolean calculator_widget_get_inverse(CalculatorWidget *self)
{
    g_return_val_if_fail(CALCULATOR_IS_WIDGET(self), FALSE);
    return self->inverse;
}
GtkWidget *calculator_widget_get_button(CalculatorWidget *self, const gchar *action, const gchar *target)
{
    g_return_val_if_fail(CALCULATOR_IS_WIDGET(self), NULL);
    for (GList *l = self->buttons; l; l = l->next) {
        const Key *k = g_object_get_data(G_OBJECT(l->data), "calculator-key");
        if (!g_strcmp0(k->action, action) && (!target || !g_strcmp0(k->target, target))) return l->data;
    }
    return NULL;
}
void calculator_widget_set_button_label(CalculatorWidget *self, const gchar *action, const gchar *label)
{
    GtkWidget *b = calculator_widget_get_button(self, action, NULL);
    GtkWidget *l = b ? g_object_get_data(G_OBJECT(b), "key-label") : NULL;
    if (l) set_label_text(l, label);
}
void calculator_widget_set_base(CalculatorWidget *self, gint base)
{
    g_return_if_fail(CALCULATOR_IS_WIDGET(self));
    for (GList *l = self->buttons; l; l = l->next) {
        const Key *k = g_object_get_data(G_OBJECT(l->data), "calculator-key");
        if (g_strcmp0(k->action, "cal.insert-digit")) continue;
        gchar c = k->target[0];
        gint v = c >= '0' && c <= '9' ? c - '0' : c - 'A' + 10;
        gtk_widget_set_sensitive(GTK_WIDGET(l->data), v < base);
    }
}
