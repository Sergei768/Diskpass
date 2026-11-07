/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef CALC_EVAL_H
#define CALC_EVAL_H
#include <glib.h>
#include <complex.h>
G_BEGIN_DECLS

/* Настройки вычисления: система счисления (2/8/10/16), разрядность слова
 * (8/16/32/64) и единицы углов (0 градусы, 1 радианы, 2 грады). */
typedef struct { gint base; gint bits; gint angle; } CalcSettings;
#define CALC_SETTINGS_DEFAULT { 10, 64, 0 }

/* Поддерживается: + − × ÷ mod % ^ ! ² ⁻¹ √, скобки, комплексные числа (i),
 * побитовые ∧ ∨ ⊻ ¬ « », функции (аргументы через «;») sin cos tan asin acos
 * atan sinh cosh tanh asinh acosh atanh ln log log2 logb exp sqrt root abs
 * floor ceil round int frac conj arg re im twos swap и финансовые ctrm ddb fv
 * gpm pmt pv rate sln syd term; константы π e φ i Ans. Недостающие ")"
 * добавляются автоматически. */
gboolean calc_eval_full(const CalcSettings *cfg, const char *expr, double complex ans, double complex *out);
/* Число -> текст (десятичная запятая; в системах 2/8/16 — целое слово). g_free(). */
char *calc_format_full(const CalcSettings *cfg, double complex v);
/* Значение как беззнаковое слово заданной разрядности (для панели битов). */
guint64 calc_to_bits(const CalcSettings *cfg, double complex v);

/* Упрощённые обёртки: десятичная система, градусы, только вещественные. */
gboolean calc_eval(const char *expr, double ans, double *out);
char *calc_format(double v);
G_END_DECLS
#endif
