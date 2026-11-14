/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef CALC_EVAL_H
#define CALC_EVAL_H
#include <glib.h>
#include <complex.h>
G_BEGIN_DECLS

 

typedef struct { gint base; gint bits; gint angle; } CalcSettings;
#define CALC_SETTINGS_DEFAULT { 10, 64, 0 }

 





gboolean calc_eval_full(const CalcSettings *cfg, const char *expr, double complex ans, double complex *out);
 
char *calc_format_full(const CalcSettings *cfg, double complex v);
 
guint64 calc_to_bits(const CalcSettings *cfg, double complex v);

 
gboolean calc_eval(const char *expr, double ans, double *out);
char *calc_format(double v);
G_END_DECLS
#endif
