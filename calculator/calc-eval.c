/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "calc-eval.h"
#include <math.h>
#include <stdint.h>
#include <string.h>

typedef double complex cd;
typedef struct { const char *p; gboolean ok; cd ans; const CalcSettings *c; guint recursion_depth; } P;

static cd or_(P *s);
static cd unary(P *s);
static cd primary(P *s);

static void skip(P *s) { while (*s->p == ' ') s->p++; }
static gboolean eat(P *s, const char *t)
{
    size_t n = strlen(t);
    skip(s);
    if (!strncmp(s->p, t, n)) { s->p += n; return TRUE; }
    return FALSE;
}
static cd clean(cd v)
{
    double r = creal(v), i = cimag(v), m = fmax(1.0, fmax(fabs(r), fabs(i)));
    if (fabs(r) < 1e-12 * m) r = 0;
    if (fabs(i) < 1e-12 * m) i = 0;
    if (r == 0) r = 0.0;   /* убрать «-0» */
    if (i == 0) i = 0.0;
    return CMPLX(r, i);
}
static gboolean is_real(cd v) { return cimag(v) == 0; }

/* ---- углы ---- */
static double to_rad(const CalcSettings *c, double x) { return c->angle == 1 ? x : c->angle == 2 ? x * G_PI / 200 : x * G_PI / 180; }
static double from_rad(const CalcSettings *c, double x) { return c->angle == 1 ? x : c->angle == 2 ? x * 200 / G_PI : x * 180 / G_PI; }

/* ---- целые операции ---- */
static guint64 bit_mask(const CalcSettings *c) { return c->bits >= 64 ? ~(guint64)0 : (((guint64)1 << c->bits) - 1); }
static gboolean to_i64(cd v, int64_t *out)
{
    double r = creal(v);
    if (!is_real(v) || !isfinite(r) || fabs(r) >= 9.2e18) return FALSE;
    *out = (int64_t)r;
    return TRUE;
}
guint64 calc_to_bits(const CalcSettings *cfg, cd v)
{
    int64_t x = 0;
    if (!to_i64(v, &x)) return 0;
    return (guint64)x & bit_mask(cfg);
}

/* ---- функции ---- */
typedef enum {
    F_SIN, F_COS, F_TAN, F_ASIN, F_ACOS, F_ATAN, F_SINH, F_COSH, F_TANH, F_ASINH, F_ACOSH, F_ATANH,
    F_LN, F_LOG, F_LOG2, F_EXP, F_SQRT, F_ABS, F_FLOOR, F_CEIL, F_ROUND, F_INT, F_FRAC,
    F_CONJ, F_ARG, F_RE, F_IM, F_TWOS, F_SWAP,
    F_LOGB, F_ROOT, F_GPM, F_SLN,
    F_CTRM, F_FV, F_PMT, F_PV, F_RATE, F_TERM, F_DDB, F_SYD
} FnId;
typedef struct { const char *name; FnId id; int nargs; } Fn;
static const Fn fns[] = {
    {"asinh", F_ASINH, 1}, {"acosh", F_ACOSH, 1}, {"atanh", F_ATANH, 1},
    {"asin", F_ASIN, 1}, {"acos", F_ACOS, 1}, {"atan", F_ATAN, 1},
    {"sinh", F_SINH, 1}, {"cosh", F_COSH, 1}, {"tanh", F_TANH, 1},
    {"sin", F_SIN, 1}, {"cos", F_COS, 1}, {"tan", F_TAN, 1},
    {"log2", F_LOG2, 1}, {"logb", F_LOGB, 2}, {"log", F_LOG, 1}, {"ln", F_LN, 1}, {"exp", F_EXP, 1},
    {"sqrt", F_SQRT, 1}, {"root", F_ROOT, 2}, {"abs", F_ABS, 1},
    {"floor", F_FLOOR, 1}, {"ceil", F_CEIL, 1}, {"round", F_ROUND, 1}, {"int", F_INT, 1}, {"frac", F_FRAC, 1},
    {"conj", F_CONJ, 1}, {"arg", F_ARG, 1}, {"re", F_RE, 1}, {"im", F_IM, 1},
    {"twos", F_TWOS, 1}, {"swap", F_SWAP, 1},
    {"ctrm", F_CTRM, 3}, {"ddb", F_DDB, 4}, {"fv", F_FV, 3}, {"gpm", F_GPM, 2}, {"pmt", F_PMT, 3},
    {"pv", F_PV, 3}, {"rate", F_RATE, 3}, {"sln", F_SLN, 3}, {"syd", F_SYD, 4}, {"term", F_TERM, 3},
};

static cd trig(const CalcSettings *c, FnId id, cd x)
{
    gboolean real = is_real(x);
    cd a = real ? to_rad(c, creal(x)) : x;
    switch (id) {
    case F_SIN: return csin(a);
    case F_COS: return ccos(a);
    case F_TAN: return ctan(a);
    default: return 0;
    }
}
static cd inv_trig(const CalcSettings *c, FnId id, cd x)
{
    cd r = id == F_ASIN ? casin(x) : id == F_ACOS ? cacos(x) : catan(x);
    return is_real(clean(r)) ? from_rad(c, creal(r)) : r;
}

static cd apply1(P *s, FnId id, cd x)
{
    const CalcSettings *c = s->c;
    double r = creal(x);
    switch (id) {
    case F_SIN: case F_COS: case F_TAN: return trig(c, id, x);
    case F_ASIN: case F_ACOS: case F_ATAN: return inv_trig(c, id, x);
    case F_SINH: return csinh(x);
    case F_COSH: return ccosh(x);
    case F_TANH: return ctanh(x);
    case F_ASINH: return casinh(x);
    case F_ACOSH: return cacosh(x);
    case F_ATANH: return catanh(x);
    case F_LN: if (x == 0) { s->ok = FALSE; return 0; } return clog(x);
    case F_LOG: if (x == 0) { s->ok = FALSE; return 0; } return clog(x) / log(10.0);
    case F_LOG2: if (x == 0) { s->ok = FALSE; return 0; } return clog(x) / log(2.0);
    case F_EXP: return cexp(x);
    case F_SQRT: return csqrt(x);
    case F_ABS: return cabs(x);
    case F_FLOOR: return floor(r);
    case F_CEIL: return ceil(r);
    case F_ROUND: return round(r);
    case F_INT: return trunc(r);
    case F_FRAC: return r - trunc(r);
    case F_CONJ: return conj(x);
    case F_ARG: return from_rad(c, carg(x));
    case F_RE: return creal(x);
    case F_IM: return cimag(x);
    case F_TWOS: { int64_t v; if (!to_i64(x, &v)) { s->ok = FALSE; return 0; } return (double)((guint64)v & bit_mask(c)); }
    case F_SWAP: {
        int64_t v; if (!to_i64(x, &v)) { s->ok = FALSE; return 0; }
        guint64 u = (guint64)v & bit_mask(c), o = 0;
        for (int i = 0; i < c->bits / 8; i++) o |= ((u >> (8 * i)) & 0xff) << (c->bits - 8 - 8 * i);
        return (double)o;
    }
    default: s->ok = FALSE; return 0;
    }
}

static cd applyn(P *s, FnId id, const cd *a)
{
    double x = creal(a[0]), y = creal(a[1]), z = creal(a[2]), w = creal(a[3]);
    switch (id) {
    case F_LOGB: if (a[0] == 0 || a[1] == 0 || clog(a[1]) == 0) { s->ok = FALSE; return 0; } return clog(a[0]) / clog(a[1]);
    case F_ROOT: if (a[1] == 0) { s->ok = FALSE; return 0; } return cpow(a[0], 1.0 / a[1]);
    case F_SLN: if (z == 0) { s->ok = FALSE; return 0; } return (x - y) / z;
    case F_GPM: if (y >= 100) { s->ok = FALSE; return 0; } return x / (1 - y / 100);
    /* pint — процентная ставка за период в долях (0,05 = 5 %) */
    case F_CTRM: if (x <= -1 || y <= 0 || z <= 0) { s->ok = FALSE; return 0; } return log(y / z) / log(1 + x);
    case F_FV: if (y == 0) return x * z; return x * (pow(1 + y, z) - 1) / y;
    case F_PMT: if (y == 0) { if (z == 0) { s->ok = FALSE; return 0; } return x / z; } return x * y / (1 - pow(1 + y, -z));
    case F_PV: if (y == 0) return x * z; return x * (1 - pow(1 + y, -z)) / y;
    case F_RATE: if (y == 0 || z == 0) { s->ok = FALSE; return 0; } return pow(x / y, 1 / z) - 1;
    case F_TERM: if (x == 0 || z <= -1) { s->ok = FALSE; return 0; } return log(1 + y * z / x) / log(1 + z);
    case F_DDB: { /* cost; salvage; life; period */
        if (!isfinite(z) || !isfinite(w) || z <= 0 || w < 1 || w > z ||
            w > 1000000 || w != floor(w)) { s->ok = FALSE; return 0; }
        double value = x, dep = 0;
        for (int i = 1; i <= (int)w; i++) { dep = fmin(value * 2 / z, fmax(0, value - y)); value -= dep; }
        return dep;
    }
    case F_SYD: if (z <= 0 || w < 1 || w > z) { s->ok = FALSE; return 0; } return (x - y) * (z - w + 1) * 2 / (z * (z + 1));
    default: s->ok = FALSE; return 0;
    }
}

/* ---- числа ---- */
static int digit_val(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

static cd number(P *s)
{
    int base = s->c->base;
    if (base == 10) {
        char buf[64]; size_t i = 0;
        while (i < 63 && (g_ascii_isdigit(*s->p) || *s->p == ',')) { buf[i++] = *s->p == ',' ? '.' : *s->p; s->p++; }
        buf[i] = 0;
        return g_ascii_strtod(buf, NULL);
    }
    double v = 0;
    while (digit_val(*s->p) >= 0 && digit_val(*s->p) < base) { v = v * base + digit_val(*s->p); s->p++; }
    return v;
}

static cd primary(P *s)
{
    if (s->recursion_depth >= 256) { s->ok = FALSE; return 0; }
    s->recursion_depth++;
    skip(s);
    if (eat(s, "(")) { cd v = or_(s); eat(s, ")"); return v; }
    if (eat(s, "√")) { cd v = clean(primary(s)); return csqrt(v); }
    if (eat(s, "Ans")) return s->ans;
    int d = digit_val(*s->p);
    if ((d >= 0 && d < s->c->base) || (s->c->base == 10 && *s->p == ',')) return number(s);
    for (guint i = 0; i < G_N_ELEMENTS(fns); i++) {
        size_t n = strlen(fns[i].name);
        if (!strncmp(s->p, fns[i].name, n) && s->p[n] == '(') {
            s->p += n + 1;
            cd args[4] = { 0, 0, 0, 0 };
            int cnt = 0;
            args[cnt++] = or_(s);
            while (s->ok && eat(s, ";")) {
                if (cnt >= (int)G_N_ELEMENTS(args)) { s->ok = FALSE; return 0; }
                args[cnt++] = or_(s);
            }
            if (!eat(s, ")")) { s->ok = FALSE; return 0; }
            if (!s->ok) return 0;
            if (cnt != fns[i].nargs) { s->ok = FALSE; return 0; }
            cd r = fns[i].nargs == 1 ? apply1(s, fns[i].id, args[0]) : applyn(s, fns[i].id, args);
            if (!isfinite(creal(r)) || !isfinite(cimag(r))) s->ok = FALSE;
            return clean(r);
        }
    }
    if (eat(s, "π")) return G_PI;
    if (eat(s, "φ")) return (1 + sqrt(5.0)) / 2;
    if (eat(s, "e")) return G_E;
    if (eat(s, "i")) return I;
    s->ok = FALSE;
    return 0;
}

static cd postfix(P *s)
{
    cd v = primary(s);
    for (;;) {
        if (!s->ok) return v;
        if (eat(s, "!")) {
            double r = creal(v);
            if (!is_real(v) || r < 0 || r > 170 || r != floor(r)) { s->ok = FALSE; return 0; }
            v = tgamma(r + 1);
        } else if (eat(s, "%")) v /= 100;
        else if (eat(s, "²")) v *= v;
        else if (eat(s, "⁻¹")) { if (v == 0) { s->ok = FALSE; return 0; } v = 1.0 / v; }
        else return v;
    }
}
static cd power(P *s)
{
    cd b = postfix(s);
    if (s->ok && eat(s, "^")) {
        cd e = unary(s);
        if (b == 0 && creal(e) <= 0 && is_real(e)) { s->ok = FALSE; return 0; }
        return is_real(b) && is_real(e) && creal(b) >= 0 ? pow(creal(b), creal(e)) : cpow(b, e);
    }
    return b;
}
static cd unary(P *s)
{
    if (eat(s, "−")) return clean(-unary(s));
    if (eat(s, "¬")) {
        cd v = unary(s); int64_t x;
        if (!to_i64(v, &x)) { s->ok = FALSE; return 0; }
        return (double)(~x);
    }
    return power(s);
}
static gboolean starts_atom(P *s)
{
    skip(s);
    if (g_str_has_prefix(s->p, "mod")) return FALSE;
    return *s->p == '(' || g_ascii_isalpha(*s->p) || g_str_has_prefix(s->p, "π")
        || g_str_has_prefix(s->p, "φ") || g_str_has_prefix(s->p, "√");
}
static cd term(P *s)
{
    cd v = unary(s);
    for (;;) {
        if (!s->ok) return v;
        if (eat(s, "×")) v *= unary(s);
        else if (eat(s, "÷")) { cd d = unary(s); if (d == 0) s->ok = FALSE; else v /= d; }
        else if (eat(s, "mod")) {
            cd d = unary(s);
            if (d == 0 || !is_real(d) || !is_real(v)) s->ok = FALSE; else v = fmod(creal(v), creal(d));
        }
        else if (starts_atom(s)) v *= unary(s);
        else return v;
    }
}
static cd add_(P *s)
{
    cd v = term(s);
    for (;;) {
        if (!s->ok) return v;
        if (eat(s, "+")) v += term(s);
        else if (eat(s, "−")) v -= term(s);
        else return v;
    }
}
static cd shift_(P *s)
{
    cd v = add_(s);
    for (;;) {
        if (!s->ok) return v;
        gboolean left = eat(s, "«");
        if (!left && !eat(s, "»")) return v;
        cd n = add_(s); int64_t x, k;
        if (!to_i64(v, &x) || !to_i64(n, &k) || k < 0 || k > 63) { s->ok = FALSE; return 0; }
        v = (double)(left ? (int64_t)((guint64)x << k) : (x >> k));
    }
}
static cd bitbin(P *s, cd a, cd b, int op)
{
    int64_t x, y;
    if (!to_i64(a, &x) || !to_i64(b, &y)) { s->ok = FALSE; return 0; }
    return (double)(op == 0 ? (x & y) : op == 1 ? (x | y) : (x ^ y));
}
static cd and_(P *s)
{
    cd v = shift_(s);
    while (s->ok && eat(s, "∧")) v = bitbin(s, v, shift_(s), 0);
    return v;
}
static cd xor_(P *s)
{
    cd v = and_(s);
    while (s->ok && eat(s, "⊻")) v = bitbin(s, v, and_(s), 2);
    return v;
}
static cd or_(P *s)
{
    cd v = xor_(s);
    while (s->ok && eat(s, "∨")) v = bitbin(s, v, xor_(s), 1);
    return v;
}

gboolean calc_eval_full(const CalcSettings *cfg, const char *text, cd ans, cd *out)
{
    if (!cfg || !text || !out || strlen(text) > 65536 ||
        (cfg->base != 2 && cfg->base != 8 && cfg->base != 10 && cfg->base != 16) ||
        (cfg->bits != 8 && cfg->bits != 16 && cfg->bits != 32 && cfg->bits != 64) ||
        cfg->angle < 0 || cfg->angle > 2 || !isfinite(creal(ans)) || !isfinite(cimag(ans)))
        return FALSE;
    P s = { text, TRUE, ans, cfg, 0 };
    cd v = or_(&s);
    skip(&s);
    if (*s.p) s.ok = FALSE;
    if (!s.ok || !isfinite(creal(v)) || !isfinite(cimag(v))) return FALSE;
    *out = clean(v);
    return TRUE;
}

static char *fmt_real(double v)
{
    char *t = g_strdup_printf("%.12g", v);
    GString *o = g_string_new("");
    for (const char *c = t; *c; c++) {
        if (*c == '.') g_string_append_c(o, ',');
        else if (*c == '-') g_string_append(o, "−");   /* U+2212, как на кнопке */
        else g_string_append_c(o, *c);
    }
    g_free(t);
    return g_string_free(o, FALSE);
}
char *calc_format_full(const CalcSettings *cfg, cd v)
{
    if (!is_real(v)) {
        double r = creal(v), im = cimag(v);
        char *ri = fmt_real(fabs(im));
        char *res;
        if (r == 0) res = g_strdup_printf("%s%si", im < 0 ? "−" : "", fabs(im) == 1 ? "" : ri);
        else {
            char *rr = fmt_real(r);
            res = g_strdup_printf("%s%s%si", rr, im < 0 ? "−" : "+", fabs(im) == 1 ? "" : ri);
            g_free(rr);
        }
        g_free(ri);
        return res;
    }
    double r = creal(v);
    if (cfg->base != 10 && r == floor(r) && fabs(r) < 9.2e18) {
        guint64 u = (guint64)(int64_t)r & bit_mask(cfg);
        if (cfg->base == 16) return g_strdup_printf("%" G_GINT64_MODIFIER "X", u);
        if (cfg->base == 8) return g_strdup_printf("%" G_GINT64_MODIFIER "o", u);
        GString *b = g_string_new("");
        int top = 63;
        while (top > 0 && !((u >> top) & 1)) top--;
        for (int i = top; i >= 0; i--) g_string_append_c(b, ((u >> i) & 1) ? '1' : '0');
        return g_string_free(b, FALSE);
    }
    return fmt_real(r);
}

gboolean calc_eval(const char *expr, double ans, double *out)
{
    CalcSettings c = CALC_SETTINGS_DEFAULT;
    cd v;
    if (!calc_eval_full(&c, expr, ans, &v) || !is_real(v)) return FALSE;
    *out = creal(v);
    return TRUE;
}
char *calc_format(double v) { CalcSettings c = CALC_SETTINGS_DEFAULT; return calc_format_full(&c, v); }
